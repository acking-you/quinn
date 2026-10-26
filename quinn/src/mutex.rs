use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

#[cfg(feature = "lock_tracking")]
use std::collections::VecDeque;
#[cfg(feature = "lock_tracking")]
use tracing::warn;

#[cfg(feature = "lock_tracking")]
use crate::{Duration, Instant};

/// A compact mutex with panic poisoning and optional lock timing diagnostics.
#[derive(Debug)]
pub(crate) struct Mutex<T> {
    inner: parking_lot::Mutex<Inner<T>>,
}

#[derive(Debug)]
struct Inner<T> {
    value: T,
    poisoned: bool,
    #[cfg(feature = "lock_tracking")]
    last_lock_owner: VecDeque<(&'static str, Duration)>,
}

impl<T> Mutex<T> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            inner: parking_lot::Mutex::new(Inner {
                value,
                poisoned: false,
                #[cfg(feature = "lock_tracking")]
                last_lock_owner: VecDeque::new(),
            }),
        }
    }

    /// Acquires the lock, failing if an earlier panic may have left state inconsistent.
    pub(crate) fn lock(&self, _purpose: &'static str) -> MutexGuard<'_, T> {
        #[cfg(feature = "lock_tracking")]
        let now = Instant::now();
        let guard = self.inner.lock();
        assert!(
            !guard.poisoned,
            "connection state poisoned by an earlier panic"
        );
        #[cfg(feature = "lock_tracking")]
        let lock_time = Instant::now();
        #[cfg(feature = "lock_tracking")]
        if lock_time.duration_since(now) > Duration::from_millis(1) {
            warn!(
                "Locking the connection for {} took {:?}. Last owners: {:?}",
                _purpose,
                lock_time.duration_since(now),
                guard.last_lock_owner
            );
        }
        MutexGuard {
            guard,
            panicking: std::thread::panicking(),
            #[cfg(feature = "lock_tracking")]
            start_time: lock_time,
            #[cfg(feature = "lock_tracking")]
            purpose: _purpose,
        }
    }
}

pub(crate) struct MutexGuard<'a, T> {
    guard: parking_lot::MutexGuard<'a, Inner<T>>,
    panicking: bool,
    #[cfg(feature = "lock_tracking")]
    start_time: Instant,
    #[cfg(feature = "lock_tracking")]
    purpose: &'static str,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard.value
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard.value
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.guard.poisoned |= !self.panicking && std::thread::panicking();
        #[cfg(feature = "lock_tracking")]
        {
            if self.guard.last_lock_owner.len() == 20 {
                self.guard.last_lock_owner.pop_back();
            }
            let duration = self.start_time.elapsed();
            if duration > Duration::from_millis(1) {
                warn!(
                    "Utilizing the connection for {} took {:?}",
                    self.purpose, duration
                );
            }
            self.guard
                .last_lock_owner
                .push_front((self.purpose, duration));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::Mutex;

    #[test]
    fn panic_poisoning_prevents_reusing_partial_state() {
        let state = Mutex::new(0);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let mut guard = state.lock("modify");
                *guard = 1;
                panic!("interrupted state update");
            }))
            .is_err()
        );
        assert!(catch_unwind(AssertUnwindSafe(|| state.lock("reuse"))).is_err());
    }
}
