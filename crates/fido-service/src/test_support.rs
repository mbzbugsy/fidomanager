//! Deterministic doubles shared by the service unit tests.

use std::cell::Cell;
use std::rc::Rc;

use crate::{MonotonicClock, MonotonicMillis};

/// Manually advanced clock, cloneable so a test, the supervisor, the coordinator and a fake
/// endpoint can all observe the same time.
#[derive(Debug, Clone, Default)]
pub(crate) struct FakeClock(Rc<Cell<u64>>);

impl FakeClock {
    pub(crate) fn advance(&self, millis: u64) {
        self.0.set(self.0.get() + millis);
    }
}

impl MonotonicClock for FakeClock {
    fn now(&self) -> MonotonicMillis {
        MonotonicMillis::from_millis(self.0.get())
    }
}
