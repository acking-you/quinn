use std::{
    io::{self, IoSliceMut},
    mem::{self, MaybeUninit},
    net::IpAddr,
    os::fd::AsRawFd,
};

use socket2::SockRef;

use crate::{
    RecvMeta, Transmit, UdpSocketState,
    cmsg::{self, MsgHdr},
    imp::{BATCH_SIZE, IpTosTy, decode_recv, recv_single, retry_if_interrupted, send_single},
};

/// Automatic opt-in is limited to the Darwin ABI validated by this fork.
#[cfg(target_os = "macos")]
pub(crate) fn is_supported() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let mut release = [0u8; 64];
        let mut len = release.len();
        // SAFETY: sysctl receives a valid name and a writable buffer of the supplied size.
        let result = unsafe {
            libc::sysctlbyname(
                c"kern.osrelease".as_ptr(),
                release.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        // Darwin 27 is validated on this fork. New kernel families require separate validation.
        result == 0
            && release.starts_with(b"27.")
            && sendmsg_x_fn().is_some()
            && recvmsg_x_fn().is_some()
    })
}

fn unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS | libc::ENOTSUP | libc::EINVAL)
    )
}

pub(crate) fn send(
    state: &UdpSocketState,
    io: SockRef<'_>,
    transmit: &Transmit<'_>,
) -> io::Result<()> {
    match transmit.effective_segment_size() {
        None => send_single(state, io, transmit),
        Some(0) => Err(io::ErrorKind::InvalidInput.into()),
        Some(_) if state.is_apple_fast_path_enabled() => send_via_sendmsg_x(state, io, transmit),
        // A transmit prepared before batching was disabled must not be merged into one datagram.
        Some(_) => Err(io::Error::from_raw_os_error(libc::EMSGSIZE)),
    }
}

/// Send using the fast `sendmsg_x` API
fn send_via_sendmsg_x(
    state: &UdpSocketState,
    io: SockRef<'_>,
    transmit: &Transmit<'_>,
) -> io::Result<()> {
    let mut hdrs = unsafe { mem::zeroed::<[msghdr_x; BATCH_SIZE]>() };
    let mut iovs = unsafe { mem::zeroed::<[libc::iovec; BATCH_SIZE]>() };
    let mut ctrls = [cmsg::Aligned([0u8; cmsg::LEN]); BATCH_SIZE];
    let addr = socket2::SockAddr::from(transmit.destination);
    let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
    let mut cnt = 0;
    if transmit.contents.len().div_ceil(segment_size) > BATCH_SIZE {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    for (i, chunk) in transmit
        .contents
        .chunks(segment_size)
        .enumerate()
        .take(BATCH_SIZE)
    {
        prepare_msg_x(
            &Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: chunk,
                segment_size: Some(chunk.len()),
                src_ip: transmit.src_ip,
            },
            &addr,
            &mut hdrs[i],
            &mut iovs[i],
            &mut ctrls[i],
            true,
            state.sendmsg_einval(),
        );
        hdrs[i].msg_datalen = chunk.len();
        state.check_send_buffer_limit(chunk.len(), &hdrs[i])?;
        cnt += 1;
    }
    let Some(sendmsg_x) = state.resolve_apple_fast_fn(sendmsg_x_fn) else {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    };
    if let Err(error) =
        retry_if_interrupted(|| unsafe { sendmsg_x(io.as_raw_fd(), hdrs.as_ptr(), cnt as u32, 0) })
    {
        if unsupported(&error) {
            state.disable_apple_fast_path();
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        return Err(error);
    }
    Ok(())
}

/// Prepares an `msghdr_x` for use with `sendmsg_x`
fn prepare_msg_x(
    transmit: &Transmit<'_>,
    dst_addr: &socket2::SockAddr,
    hdr: &mut msghdr_x,
    iov: &mut libc::iovec,
    ctrl: &mut cmsg::Aligned<[u8; cmsg::LEN]>,
    #[allow(unused_variables)] encode_src_ip: bool,
    sendmsg_einval: bool,
) {
    iov.iov_base = transmit.contents.as_ptr() as *const _ as *mut _;
    iov.iov_len = transmit.contents.len();

    let name = dst_addr.as_ptr() as *mut libc::c_void;
    let namelen = dst_addr.len();
    hdr.msg_name = name as *mut _;
    hdr.msg_namelen = namelen;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = cmsg::LEN as _;
    let mut encoder = unsafe { cmsg::Encoder::new(hdr) };
    let ecn = transmit.ecn.map_or(0, |x| x as libc::c_int);
    let is_ipv4 = transmit.destination.is_ipv4()
        || matches!(transmit.destination.ip(), IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some());
    if is_ipv4 {
        if !sendmsg_einval {
            encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
        }
    } else {
        encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
    }

    if let Some(ip) = &transmit.src_ip {
        match ip {
            IpAddr::V4(v4) => {
                if encode_src_ip {
                    let addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    };
                    encoder.push(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, addr);
                }
            }
            IpAddr::V6(v6) => {
                let pktinfo = libc::in6_pktinfo {
                    ipi6_ifindex: 0,
                    ipi6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                };
                encoder.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, pktinfo);
            }
        }
    }

    encoder.finish();
}

/// Returns the `sendmsg_x` function pointer, resolving it via `dlsym` on first call
///
/// Returns `None` if the symbol is not available on the current OS version.
fn sendmsg_x_fn() -> Option<SendmsgXFn> {
    static ADDR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    // SAFETY: `resolve_symbol` only returns non-zero addresses obtained from `dlsym`, which
    // guarantees a callable symbol whose type matches the declaration above.
    resolve_symbol(&ADDR, c"sendmsg_x")
        .map(|addr| unsafe { mem::transmute::<usize, SendmsgXFn>(addr) })
}

type SendmsgXFn =
    unsafe extern "C" fn(libc::c_int, *const msghdr_x, libc::c_uint, libc::c_int) -> isize;

/// Receive using the fast `recvmsg_x` API
// Keep the full message arrays off the ordinary receive path's stack, even after inlining
// the statically selected policy and backend. Only busy receives need this frame.
#[inline(never)]
pub(crate) fn recv_via_recvmsg_x(
    state: &UdpSocketState,
    io: SockRef<'_>,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> io::Result<usize> {
    let mut names = [MaybeUninit::<libc::sockaddr_storage>::uninit(); BATCH_SIZE];
    // MacOS 10.15 `recvmsg_x` does not override the `msghdr_x`
    // `msg_controllen`. Thus, after the call to `recvmsg_x`, one does not know
    // which control messages have been written to. To prevent reading
    // uninitialized memory, do not use `MaybeUninit` for `ctrls`, instead
    // initialize `ctrls` with `0`s. A control message of all `0`s is
    // automatically skipped by `libc::CMSG_NXTHDR`.
    let mut ctrls = [cmsg::Aligned([0u8; cmsg::LEN]); BATCH_SIZE];
    let mut hdrs = unsafe { mem::zeroed::<[msghdr_x; BATCH_SIZE]>() };
    let max_msg_count = bufs.len().min(BATCH_SIZE);
    for i in 0..max_msg_count {
        prepare_recv_x(&mut bufs[i], &mut names[i], &mut ctrls[i], &mut hdrs[i]);
    }
    let Some(recvmsg_x) = state.resolve_apple_fast_fn(recvmsg_x_fn) else {
        return recv_single(io, bufs, meta);
    };
    let msg_count = match retry_if_interrupted(|| unsafe {
        recvmsg_x(io.as_raw_fd(), hdrs.as_mut_ptr(), max_msg_count as _, 0)
    }) {
        Ok(count) => count,
        Err(error) if unsupported(&error) => {
            state.disable_apple_fast_path();
            return recv_single(io, bufs, meta);
        }
        Err(error) => return Err(error),
    };
    for i in 0..(msg_count as usize) {
        meta[i] = decode_recv(&names[i], &hdrs[i], hdrs[i].msg_datalen as usize)?;
    }
    Ok(msg_count as usize)
}

/// Prepares an `msghdr_x` for receiving with `recvmsg_x`
fn prepare_recv_x(
    buf: &mut IoSliceMut<'_>,
    name: &mut MaybeUninit<libc::sockaddr_storage>,
    ctrl: &mut cmsg::Aligned<[u8; cmsg::LEN]>,
    hdr: &mut msghdr_x,
) {
    hdr.msg_name = name.as_mut_ptr() as _;
    hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
    hdr.msg_iov = buf as *mut IoSliceMut<'_> as *mut libc::iovec;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = cmsg::LEN as _;
    hdr.msg_flags = 0;
    hdr.msg_datalen = buf.len();
}

/// Returns the `recvmsg_x` function pointer, resolving it via `dlsym` on first call
///
/// Returns `None` if the symbol is not available on the current OS version.
fn recvmsg_x_fn() -> Option<RecvmsgXFn> {
    static ADDR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    // SAFETY: `resolve_symbol` only returns non-zero addresses obtained from `dlsym`, which
    // guarantees a callable symbol whose type matches the declaration above.
    resolve_symbol(&ADDR, c"recvmsg_x")
        .map(|addr| unsafe { mem::transmute::<usize, RecvmsgXFn>(addr) })
}

type RecvmsgXFn =
    unsafe extern "C" fn(libc::c_int, *mut msghdr_x, libc::c_uint, libc::c_int) -> isize;

/// Resolves a symbol via `dlsym` on first call, caching the result
///
/// Returns `None` if the symbol is not available on the current OS version.
fn resolve_symbol(lock: &std::sync::OnceLock<usize>, name: &std::ffi::CStr) -> Option<usize> {
    let addr =
        *lock.get_or_init(|| unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) as usize });
    (addr != 0).then_some(addr)
}

// Adapted from https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/socket_private.h
#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct msghdr_x {
    pub msg_name: *mut libc::c_void,
    pub msg_namelen: libc::socklen_t,
    pub msg_iov: *mut libc::iovec,
    pub msg_iovlen: libc::c_int,
    pub msg_control: *mut libc::c_void,
    pub msg_controllen: libc::socklen_t,
    pub msg_flags: libc::c_int,
    pub msg_datalen: usize,
}

impl MsgHdr for msghdr_x {
    type ControlMessage = libc::cmsghdr;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage {
        let selfp = self as *const _ as *mut libc::msghdr;
        unsafe { libc::CMSG_FIRSTHDR(selfp) }
    }

    unsafe fn cmsg_nxt_hdr(&self, cmsg: *const Self::ControlMessage) -> *mut Self::ControlMessage {
        let selfp = self as *const _ as *mut libc::msghdr;
        unsafe { libc::CMSG_NXTHDR(selfp, cmsg) }
    }

    fn set_control_len(&mut self, len: usize) {
        self.msg_controllen = len as _;
    }

    fn control_len(&self) -> usize {
        self.msg_controllen as _
    }
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, time::Duration};

    use super::*;

    #[test]
    fn disabled_batching_preserves_datagram_boundaries() {
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let state = UdpSocketState::new((&sender).into()).unwrap();
        state.disable_apple_fast_path();
        let mut transmit = Transmit {
            destination: receiver.local_addr().unwrap(),
            ecn: None,
            contents: b"abcd",
            segment_size: Some(2),
            src_ip: None,
        };
        assert_eq!(
            state
                .try_send((&sender).into(), &transmit)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EMSGSIZE),
        );
        transmit.contents = b"";
        transmit.segment_size = None;
        state.try_send((&sender).into(), &transmit).unwrap();
        let mut bytes = [0; 32];
        assert_eq!(receiver.recv_from(&mut bytes).unwrap().0, 0);
        transmit.contents = b"single";
        state.try_send((&sender).into(), &transmit).unwrap();
        let (len, _) = receiver.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"single");
    }
}
