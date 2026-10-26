//! Statically selected datagram mechanisms and receive policies.
//!
//! A backend owns the platform syscalls and their capability checks. Its associated receive
//! policy owns only scheduling hints. Single and batched policies are zero-sized; only the
//! adaptive policy stores state. No trait objects, packet storage, or extra readiness probes.

use std::io::{self, IoSliceMut};
#[cfg(apple_fast)]
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};

/// Platform mechanism, selected by `cfg` before monomorphization.
pub(crate) trait DatagramIo: Sized {
    type Receive: ReceivePolicy<Self>;

    /// Number of receive buffers, independent of segments coalesced into each buffer by GRO.
    const BATCH_SIZE: usize;

    fn send(
        state: &UdpSocketState,
        socket: UdpSockRef<'_>,
        transmit: &Transmit<'_>,
    ) -> io::Result<()>;

    /// `BATCH` is a compile-time choice, not a branch on each packet.
    fn recv<const BATCH: bool>(
        state: &UdpSocketState,
        socket: UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize>;
}

/// Additional capability required only by an adaptive receive policy.
#[cfg(apple_fast)]
pub(crate) trait AdaptiveIo: DatagramIo {
    /// A load hint must never re-enable a mechanism disabled by a capability failure.
    fn batch_enabled(state: &UdpSocketState) -> bool;
}

pub(crate) trait ReceivePolicy<B: DatagramIo>: Default + std::fmt::Debug {
    fn recv(
        &self,
        state: &UdpSocketState,
        socket: UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize>;
}

/// One native receive. A platform may still coalesce several segments into that buffer.
#[cfg(not(any(recv_mmsg, apple_fast)))]
#[derive(Debug, Default)]
pub(crate) struct Single;

#[cfg(not(any(recv_mmsg, apple_fast)))]
impl<B: DatagramIo> ReceivePolicy<B> for Single {
    #[inline(always)]
    fn recv(
        &self,
        state: &UdpSocketState,
        socket: UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        B::recv::<false>(state, socket, bufs, meta)
    }
}

/// Native `recvmmsg`, preserving the kernel's GSO/GRO path without load tracking.
#[cfg(recv_mmsg)]
#[derive(Debug, Default)]
pub(crate) struct Batch;

#[cfg(recv_mmsg)]
impl<B: DatagramIo> ReceivePolicy<B> for Batch {
    #[inline(always)]
    fn recv(
        &self,
        state: &UdpSocketState,
        socket: UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        B::recv::<true>(state, socket, bufs, meta)
    }
}

/// Avoid building full Apple message arrays for isolated packets.
#[cfg(apple_fast)]
#[derive(Debug, Default)]
pub(crate) struct Adaptive {
    /// 0..=2 count consecutive ordinary reads; 3..=6 select full batches.
    hint: AtomicUsize,
}

#[cfg(apple_fast)]
impl<B: AdaptiveIo> ReceivePolicy<B> for Adaptive {
    #[inline(always)]
    fn recv(
        &self,
        state: &UdpSocketState,
        socket: UdpSockRef<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        if !B::batch_enabled(state) {
            return B::recv::<false>(state, socket, bufs, meta);
        }
        let hint = self.hint.load(Ordering::Relaxed);
        let result = if hint <= 2 || bufs.len() == 1 {
            B::recv::<false>(state, socket, bufs, meta)
        } else {
            B::recv::<true>(state, socket, bufs, meta)
        };
        // Three ordinary successes establish a backlog. Four sparse batches return to
        // ordinary receive. An empty busy socket retains batching for its next burst.
        let next = match &result {
            Ok(_) if hint < 2 => hint + 1,
            Ok(count) if hint == 2 || *count > 1 => 6,
            Ok(_) => hint - 1,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && hint <= 2 => 0,
            Err(_) => hint,
        };
        if next != hint {
            // Only a performance hint: simultaneous readers may overwrite observations.
            self.hint.store(next, Ordering::Relaxed);
        }
        result
    }
}
