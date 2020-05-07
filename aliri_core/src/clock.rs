//! Utilities for messing with time

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Unix time
///
/// Unix time as represented by the number of seconds elapsed since the
/// beginning of the Unix epoch on 1970/01/01 at 00:00:00 UTC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[repr(transparent)]
pub struct UnixTime(pub u64);

impl From<SystemTime> for UnixTime {
    fn from(t: SystemTime) -> Self {
        let time = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        UnixTime(time)
    }
}

/// Represents a clock, which can tell the current time
pub trait Clock {
    /// Gets the current time according to this clock
    fn now(&self) -> UnixTime;
}

/// The system clock as provided by `std::time::SystemTime`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct System;

impl Clock for System {
    fn now(&self) -> UnixTime {
        UnixTime::from(SystemTime::now())
    }
}

/// A test clock which maintains the current time as internal state
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestClock(UnixTime);

impl Clock for TestClock {
    fn now(&self) -> UnixTime {
        self.0
    }
}

impl TestClock {
    /// Updates the clock's current time to `val`
    pub fn set(&mut self, val: UnixTime) {
        self.0 = val;
    }

    /// Increments the clock's current time by `inc` seconds
    pub fn inc(&mut self, inc: u64) {
        (self.0).0 += inc;
    }
}
