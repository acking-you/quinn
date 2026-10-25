use std::{
    io::{self, IoSliceMut},
    mem,
    net::{IpAddr, Ipv4Addr},
    os::windows::io::AsRawSocket,
    ptr,
    sync::Mutex,
    time::Instant,
};

use libc::{c_int, c_uint};
use once_cell::sync::Lazy;
use windows_sys::Win32::NetworkManagement::IpHelper;
use windows_sys::Win32::Networking::WinSock;

use crate::{
    EcnCodepoint, IO_ERROR_LOG_INTERVAL, RecvMeta, Transmit, UdpSockRef,
    cmsg::{self, CMsgHdr},
    log::debug,
    log_sendmsg_error,
};

/// QUIC-friendly UDP socket for Windows
///
/// Unlike a standard Windows UDP socket, this allows ECN bits to be read and written.
#[derive(Debug)]
pub struct UdpSocketState {
    last_send_error: Mutex<Instant>,
}

impl UdpSocketState {
    pub fn new(socket: UdpSockRef<'_>) -> io::Result<Self> {
        assert!(
            CMSG_LEN
                >= WinSock::CMSGHDR::cmsg_space(mem::size_of::<WinSock::IN6_PKTINFO>())
                    + WinSock::CMSGHDR::cmsg_space(mem::size_of::<c_int>())
                    + WinSock::CMSGHDR::cmsg_space(mem::size_of::<u32>())
        );
        assert!(
            mem::align_of::<WinSock::CMSGHDR>() <= mem::align_of::<cmsg::Aligned<[u8; 0]>>(),
            "control message buffers will be misaligned"
        );

        socket.0.set_nonblocking(true)?;
        let addr = socket.0.local_addr()?;
        let is_ipv6 = addr.as_socket_ipv6().is_some();
        let v6only = unsafe {
            let mut result: u32 = 0;
            let mut len = mem::size_of_val(&result) as i32;
            let rc = WinSock::getsockopt(
                socket.0.as_raw_socket() as _,
                WinSock::IPPROTO_IPV6,
                WinSock::IPV6_V6ONLY as _,
                &mut result as *mut _ as _,
                &mut len,
            );
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
            result != 0
        };
        let is_ipv4 = addr.as_socket_ipv4().is_some() || !v6only;

        // We don't support old versions of Windows that do not enable access to `WSARecvMsg()`
        if WSARECVMSG_PTR.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "network stack does not support WSARecvMsg function",
            ));
        }

        if is_ipv4 {
            set_socket_option(
                &*socket.0,
                WinSock::IPPROTO_IP,
                WinSock::IP_DONTFRAGMENT,
                OPTION_ON,
            )?;

            set_socket_option(
                &*socket.0,
                WinSock::IPPROTO_IP,
                WinSock::IP_PKTINFO,
                OPTION_ON,
            )?;
            set_socket_option(
                &*socket.0,
                WinSock::IPPROTO_IP,
                WinSock::IP_RECVECN,
                OPTION_ON,
            )?;
        }

        if is_ipv6 {
            set_socket_option(
                &*socket.0,
                WinSock::IPPROTO_IPV6,
                WinSock::IPV6_DONTFRAG,
                OPTION_ON,
            )?;

            set_socket_option(
                &*socket.0,
                WinSock::IPPROTO_IPV6,
                WinSock::IPV6_PKTINFO,
                OPTION_ON,
            )?;

            set_socket_option(
                &*socket.0,
                WinSock::IPPROTO_IPV6,
                WinSock::IPV6_RECVECN,
                OPTION_ON,
            )?;
        }

        let now = Instant::now();
        Ok(Self {
            last_send_error: Mutex::new(now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now)),
        })
    }

    /// Enable or disable receive offloading.
    ///
    /// Also referred to as UDP Receive Segment Coalescing Offload (URO) on Windows.
    ///
    /// <https://learn.microsoft.com/en-us/windows-hardware/drivers/network/udp-rsc-offload>
    ///
    /// Disabled by default on Windows due to <https://github.com/quinn-rs/quinn/issues/2041>.
    pub fn set_gro(&self, socket: UdpSockRef<'_>, enable: bool) -> io::Result<()> {
        set_socket_option(
            &*socket.0,
            WinSock::IPPROTO_UDP,
            WinSock::UDP_RECV_MAX_COALESCED_SIZE,
            match enable {
                // u32 per
                // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options.
                // Choice of 2^16 - 1 inspired by msquic.
                true => u16::MAX as u32,
                false => 0,
            },
        )
    }

    /// Sends a [`Transmit`] on the given socket.
    ///
    /// This function will only ever return errors of kind [`io::ErrorKind::WouldBlock`].
    /// All other errors will be logged and converted to `Ok`.
    ///
    /// UDP transmission errors are considered non-fatal because higher-level protocols must
    /// employ retransmits and timeouts anyway in order to deal with UDP's unreliable nature.
    /// Thus, logging is most likely the only thing you can do with these errors.
    ///
    /// If you would like to handle these errors yourself, use [`UdpSocketState::try_send`]
    /// instead.
    pub fn send(&self, socket: UdpSockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
        match send(socket, transmit) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(e) => {
                log_sendmsg_error(&self.last_send_error, e, transmit);

                Ok(())
            }
        }
    }

    /// Sends a [`Transmit`] on the given socket without any additional error handling.
    pub fn try_send(&self, socket: UdpSockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
        send(socket, transmit)
    }

    pub fn recv(
        &self,
        socket: UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let wsa_recvmsg_ptr = WSARECVMSG_PTR.expect("valid function pointer for WSARecvMsg");

        // we cannot use [`socket2::MsgHdrMut`] as we do not have access to inner field which holds the WSAMSG
        let mut ctrl_buf = cmsg::Aligned([0; CMSG_LEN]);
        let mut source: WinSock::SOCKADDR_INET = unsafe { mem::zeroed() };
        let mut data = WinSock::WSABUF {
            buf: bufs[0].as_mut_ptr(),
            len: bufs[0].len() as _,
        };

        let ctrl = WinSock::WSABUF {
            buf: ctrl_buf.0.as_mut_ptr(),
            len: ctrl_buf.0.len() as _,
        };

        let mut wsa_msg = WinSock::WSAMSG {
            name: &mut source as *mut _ as *mut _,
            namelen: mem::size_of_val(&source) as _,
            lpBuffers: &mut data,
            Control: ctrl,
            dwBufferCount: 1,
            dwFlags: 0,
        };

        let mut len = 0;
        unsafe {
            let rc = (wsa_recvmsg_ptr)(
                socket.0.as_raw_socket() as usize,
                &mut wsa_msg,
                &mut len,
                ptr::null_mut(),
                None,
            );
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
        }

        let addr = unsafe {
            let (_, addr) = socket2::SockAddr::try_init(|addr_storage, len| {
                *len = mem::size_of_val(&source) as _;
                ptr::copy_nonoverlapping(&source, addr_storage as _, 1);
                Ok(())
            })?;
            addr.as_socket()
        };

        // Decode control messages (PKTINFO and ECN)
        let mut ecn_bits = 0;
        let mut dst_ip = None;
        let mut stride = len;

        let cmsg_iter = unsafe { cmsg::Iter::new(&wsa_msg) };
        for cmsg in cmsg_iter {
            const UDP_COALESCED_INFO: i32 = WinSock::UDP_COALESCED_INFO as i32;
            // [header (len)][data][padding(len + sizeof(data))] -> [header][data][padding]
            match (cmsg.cmsg_level, cmsg.cmsg_type) {
                (WinSock::IPPROTO_IP, WinSock::IP_PKTINFO) => {
                    let pktinfo =
                        unsafe { cmsg::decode::<WinSock::IN_PKTINFO, WinSock::CMSGHDR>(cmsg) };
                    // Addr is stored in big endian format
                    let ip4 = Ipv4Addr::from(u32::from_be(unsafe { pktinfo.ipi_addr.S_un.S_addr }));
                    dst_ip = Some(ip4.into());
                }
                (WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO) => {
                    let pktinfo =
                        unsafe { cmsg::decode::<WinSock::IN6_PKTINFO, WinSock::CMSGHDR>(cmsg) };
                    // Addr is stored in big endian format
                    dst_ip = Some(IpAddr::from(unsafe { pktinfo.ipi6_addr.u.Byte }));
                }
                (WinSock::IPPROTO_IP, WinSock::IP_ECN) => {
                    // ECN is a C integer https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ecn
                    ecn_bits = unsafe { cmsg::decode::<c_int, WinSock::CMSGHDR>(cmsg) };
                }
                (WinSock::IPPROTO_IPV6, WinSock::IPV6_ECN) => {
                    // ECN is a C integer https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ecn
                    ecn_bits = unsafe { cmsg::decode::<c_int, WinSock::CMSGHDR>(cmsg) };
                }
                (WinSock::IPPROTO_UDP, UDP_COALESCED_INFO) => {
                    // Has type u32 (aka DWORD) per
                    // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options
                    stride = unsafe { cmsg::decode::<u32, WinSock::CMSGHDR>(cmsg) };
                }
                _ => {}
            }
        }

        meta[0] = RecvMeta {
            len: len as usize,
            stride: stride as usize,
            addr: addr.unwrap(),
            ecn: EcnCodepoint::from_bits(ecn_bits as u8),
            dst_ip,
        };
        Ok(1)
    }

    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    ///
    /// This is 1 if the platform doesn't support GSO. Subject to change if errors are detected
    /// while using GSO.
    #[inline]
    pub fn max_gso_segments(&self) -> usize {
        *MAX_GSO_SEGMENTS
    }

    /// The number of segments to read when GRO is enabled. Used as a factor to
    /// compute the receive buffer size.
    ///
    /// Returns 1 if the platform doesn't support GRO.
    #[inline]
    pub fn gro_segments(&self) -> usize {
        // Arbitrary reasonable value inspired by Linux and msquic
        64
    }

    /// Resize the send buffer of `socket` to `bytes`
    #[inline]
    pub fn set_send_buffer_size(&self, socket: UdpSockRef<'_>, bytes: usize) -> io::Result<()> {
        socket.0.set_send_buffer_size(bytes)
    }

    /// Resize the receive buffer of `socket` to `bytes`
    #[inline]
    pub fn set_recv_buffer_size(&self, socket: UdpSockRef<'_>, bytes: usize) -> io::Result<()> {
        socket.0.set_recv_buffer_size(bytes)
    }

    /// Get the size of the `socket` send buffer
    #[inline]
    pub fn send_buffer_size(&self, socket: UdpSockRef<'_>) -> io::Result<usize> {
        socket.0.send_buffer_size()
    }

    /// Get the size of the `socket` receive buffer
    #[inline]
    pub fn recv_buffer_size(&self, socket: UdpSockRef<'_>) -> io::Result<usize> {
        socket.0.recv_buffer_size()
    }

    #[inline]
    pub fn may_fragment(&self) -> bool {
        false
    }
}

fn send(socket: UdpSockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
    send_with_source_fallback(
        transmit,
        |packet| send_msg(&socket, packet),
        || default_source_matches(&socket, transmit),
    )
}

fn send_with_source_fallback(
    transmit: &Transmit<'_>,
    mut send: impl FnMut(&Transmit<'_>) -> io::Result<()>,
    default_source_matches: impl FnOnce() -> bool,
) -> io::Result<()> {
    match send(transmit) {
        Err(error)
            if error.raw_os_error() == Some(WinSock::WSAEINVAL)
                && matches!(transmit.src_ip, Some(IpAddr::V4(_)))
                && transmit.destination.is_ipv4()
                && default_source_matches() =>
        {
            // Some Windows network stacks reject IP_PKTINFO on wildcard-bound
            // sockets even when its source is the route's own local address.
            // Omit only that redundant control message, never change the source
            // requested by the caller or discard ECN/segmentation metadata.
            let mut packet = transmit.clone();
            packet.src_ip = None;
            send(&packet)
        }
        result => result,
    }
}

fn default_source_matches(socket: &UdpSockRef<'_>, transmit: &Transmit<'_>) -> bool {
    let Some(IpAddr::V4(requested)) = transmit.src_ip else {
        return false;
    };
    let Ok(local) = socket.0.local_addr() else {
        return false;
    };
    let Some(local) = local.as_socket_ipv4() else {
        return false;
    };
    if !local.ip().is_unspecified() {
        return *local.ip() == requested;
    }
    let destination = socket2::SockAddr::from(transmit.destination);
    // SAFETY: the destination is IPv4; all output pointers refer to writable,
    // correctly sized storage. A socket's explicit interface selection must
    // constrain the route lookup, just as it constrains the retry's send.
    unsafe {
        let mut interface = 0_u32;
        let mut len = mem::size_of_val(&interface) as i32;
        if WinSock::getsockopt(
            socket.0.as_raw_socket() as _,
            WinSock::IPPROTO_IP,
            WinSock::IP_UNICAST_IF,
            &mut interface as *mut _ as _,
            &mut len,
        ) != 0
        {
            return false;
        }
        let mut route = mem::zeroed();
        let mut source: WinSock::SOCKADDR_INET = mem::zeroed();
        // Unlike setsockopt, getsockopt returns IP_UNICAST_IF in host order.
        if IpHelper::GetBestRoute2(
            ptr::null(),
            interface,
            ptr::null(),
            destination.as_ptr().cast(),
            0,
            &mut route,
            &mut source,
        ) != 0
        {
            return false;
        }
        source.si_family == WinSock::AF_INET
            && Ipv4Addr::from(u32::from_be(source.Ipv4.sin_addr.S_un.S_addr)) == requested
    }
}

fn send_msg(socket: &UdpSockRef<'_>, transmit: &Transmit<'_>) -> io::Result<()> {
    // we cannot use [`socket2::sendmsg()`] and [`socket2::MsgHdr`] as we do not have access
    // to the inner field which holds the WSAMSG
    let mut ctrl_buf = cmsg::Aligned([0; CMSG_LEN]);
    let daddr = socket2::SockAddr::from(transmit.destination);

    let mut data = WinSock::WSABUF {
        buf: transmit.contents.as_ptr() as *mut _,
        len: transmit.contents.len() as _,
    };

    let ctrl = WinSock::WSABUF {
        buf: ctrl_buf.0.as_mut_ptr(),
        len: ctrl_buf.0.len() as _,
    };

    let mut wsa_msg = WinSock::WSAMSG {
        name: daddr.as_ptr() as *mut _,
        namelen: daddr.len(),
        lpBuffers: &mut data,
        Control: ctrl,
        dwBufferCount: 1,
        dwFlags: 0,
    };

    // Add control messages (ECN and PKTINFO)
    let mut encoder = unsafe { cmsg::Encoder::new(&mut wsa_msg) };

    if let Some(ip) = transmit.src_ip {
        let ip = std::net::SocketAddr::new(ip, 0);
        let ip = socket2::SockAddr::from(ip);
        match ip.family() {
            WinSock::AF_INET => {
                let src_ip = unsafe { ptr::read(ip.as_ptr() as *const WinSock::SOCKADDR_IN) };
                let pktinfo = WinSock::IN_PKTINFO {
                    ipi_addr: src_ip.sin_addr,
                    ipi_ifindex: 0,
                };
                encoder.push(WinSock::IPPROTO_IP, WinSock::IP_PKTINFO, pktinfo);
            }
            WinSock::AF_INET6 => {
                let src_ip = unsafe { ptr::read(ip.as_ptr() as *const WinSock::SOCKADDR_IN6) };
                let pktinfo = WinSock::IN6_PKTINFO {
                    ipi6_addr: src_ip.sin6_addr,
                    ipi6_ifindex: unsafe { src_ip.Anonymous.sin6_scope_id },
                };
                encoder.push(WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO, pktinfo);
            }
            _ => {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
        }
    }

    // ECN is a C integer https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ecn
    let ecn = transmit.ecn.map_or(0, |x| x as c_int);
    // True for IPv4 or IPv4-Mapped IPv6
    let is_ipv4 = transmit.destination.is_ipv4()
        || matches!(transmit.destination.ip(), IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some());
    if is_ipv4 {
        encoder.push(WinSock::IPPROTO_IP, WinSock::IP_ECN, ecn);
    } else {
        encoder.push(WinSock::IPPROTO_IPV6, WinSock::IPV6_ECN, ecn);
    }

    // Segment size is a u32 https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-wsasetudpsendmessagesize
    if let Some(segment_size) = transmit.segment_size {
        encoder.push(
            WinSock::IPPROTO_UDP,
            WinSock::UDP_SEND_MSG_SIZE,
            segment_size as u32,
        );
    }

    encoder.finish();

    let mut len = 0;
    let rc = unsafe {
        WinSock::WSASendMsg(
            socket.0.as_raw_socket() as usize,
            &wsa_msg,
            0,
            &mut len,
            ptr::null_mut(),
            None,
        )
    };

    match rc {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

fn set_socket_option(
    socket: &impl AsRawSocket,
    level: i32,
    name: i32,
    value: u32,
) -> io::Result<()> {
    let rc = unsafe {
        WinSock::setsockopt(
            socket.as_raw_socket() as usize,
            level,
            name,
            &value as *const _ as _,
            mem::size_of_val(&value) as _,
        )
    };

    match rc == 0 {
        true => Ok(()),
        false => Err(io::Error::last_os_error()),
    }
}

pub(crate) const BATCH_SIZE: usize = 1;
// Enough to store max(IP_PKTINFO + IP_ECN, IPV6_PKTINFO + IPV6_ECN) + max(UDP_SEND_MSG_SIZE, UDP_COALESCED_INFO) bytes (header + data) and some extra margin
const CMSG_LEN: usize = 128;
const OPTION_ON: u32 = 1;

// FIXME this could use [`std::sync::OnceLock`] once the MSRV is bumped to 1.70 and upper
static WSARECVMSG_PTR: Lazy<WinSock::LPFN_WSARECVMSG> = Lazy::new(|| {
    let s = unsafe { WinSock::socket(WinSock::AF_INET as _, WinSock::SOCK_DGRAM as _, 0) };
    if s == WinSock::INVALID_SOCKET {
        debug!(
            "ignoring WSARecvMsg function pointer due to socket creation error: {}",
            io::Error::last_os_error()
        );
        return None;
    }

    // Detect if OS expose WSARecvMsg API based on
    // https://github.com/Azure/mio-uds-windows/blob/a3c97df82018086add96d8821edb4aa85ec1b42b/src/stdnet/ext.rs#L601
    let guid = WinSock::WSAID_WSARECVMSG;
    let mut wsa_recvmsg_ptr = None;
    let mut len = 0;

    // Safety: Option handles the NULL pointer with a None value
    let rc = unsafe {
        WinSock::WSAIoctl(
            s as _,
            WinSock::SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guid as *const _ as *const _,
            mem::size_of_val(&guid) as u32,
            &mut wsa_recvmsg_ptr as *mut _ as *mut _,
            mem::size_of_val(&wsa_recvmsg_ptr) as u32,
            &mut len,
            ptr::null_mut(),
            None,
        )
    };

    if rc == -1 {
        debug!(
            "ignoring WSARecvMsg function pointer due to ioctl error: {}",
            io::Error::last_os_error()
        );
    } else if len as usize != mem::size_of::<WinSock::LPFN_WSARECVMSG>() {
        debug!("ignoring WSARecvMsg function pointer due to pointer size mismatch");
        wsa_recvmsg_ptr = None;
    }

    unsafe {
        WinSock::closesocket(s);
    }

    wsa_recvmsg_ptr
});

static MAX_GSO_SEGMENTS: Lazy<usize> = Lazy::new(|| {
    let socket = match std::net::UdpSocket::bind("[::]:0")
        .or_else(|_| std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)))
    {
        Ok(socket) => socket,
        Err(_) => return 1,
    };
    const GSO_SIZE: c_uint = 1500;
    match set_socket_option(
        &socket,
        WinSock::IPPROTO_UDP,
        WinSock::UDP_SEND_MSG_SIZE,
        GSO_SIZE,
    ) {
        // Empirically found on Windows 11 x64
        Ok(()) => 512,
        Err(_) => 1,
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_source_retries_once_without_changing_the_datagram() {
        let packet = Transmit {
            destination: "192.0.2.2:4433".parse().unwrap(),
            src_ip: Some("192.0.2.1".parse().unwrap()),
            ecn: Some(EcnCodepoint::Ect0),
            segment_size: Some(1200),
            contents: &[7; 2400],
        };
        let mut calls = 0;
        let error = send_with_source_fallback(
            &packet,
            |sent| {
                calls += 1;
                assert_eq!(sent.destination, packet.destination);
                assert_eq!(sent.contents.as_ptr(), packet.contents.as_ptr());
                assert_eq!(sent.contents.len(), packet.contents.len());
                assert_eq!(sent.ecn, packet.ecn);
                assert_eq!(sent.segment_size, packet.segment_size);
                assert_eq!(sent.src_ip, if calls == 1 { packet.src_ip } else { None });
                Err(io::Error::from_raw_os_error(WinSock::WSAEINVAL))
            },
            || true,
        )
        .unwrap_err();
        assert_eq!(calls, 2, "a failed retry must not loop or report success");
        assert_eq!(error.raw_os_error(), Some(WinSock::WSAEINVAL));
    }

    #[test]
    fn fallback_requires_a_redundant_source_and_the_specific_error() {
        let packet = Transmit {
            destination: "127.0.0.1:4433".parse().unwrap(),
            src_ip: Some(Ipv4Addr::LOCALHOST.into()),
            ecn: None,
            segment_size: None,
            contents: b"hello",
        };
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        assert!(default_source_matches(&(&socket).into(), &packet));
        let destination = socket2::SockAddr::from(packet.destination);
        let mut interface = 0_u32;
        // SAFETY: destination is a valid IPv4 socket address and the output
        // points to a writable interface index.
        assert_eq!(
            unsafe { IpHelper::GetBestInterfaceEx(destination.as_ptr().cast(), &mut interface) },
            0
        );
        assert_ne!(interface, 0);
        set_socket_option(
            &socket,
            WinSock::IPPROTO_IP,
            WinSock::IP_UNICAST_IF,
            interface.to_be(),
        )
        .unwrap();
        assert!(default_source_matches(&(&socket).into(), &packet));
        let mut different_source = packet.clone();
        different_source.src_ip = Some("192.0.2.1".parse().unwrap());
        assert!(!default_source_matches(
            &(&socket).into(),
            &different_source
        ));

        for (code, same_source) in [
            (WinSock::WSAEINVAL, false),
            (WinSock::WSAEWOULDBLOCK, true),
            (WinSock::WSAENETUNREACH, true),
        ] {
            let mut calls = 0;
            let error = send_with_source_fallback(
                &packet,
                |_| {
                    calls += 1;
                    Err(io::Error::from_raw_os_error(code))
                },
                || same_source,
            )
            .unwrap_err();
            assert_eq!(calls, 1, "must preserve source selection and other errors");
            assert_eq!(error.raw_os_error(), Some(code));
        }
        send_with_source_fallback(&packet, |_| Ok(()), || panic!("no lookup on success")).unwrap();
    }
}
