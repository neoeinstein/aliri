//! Utilities for messing with time

use std::time::SystemTime;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Unix time
///
/// Unix time as represented by the number of seconds elapsed since the
/// beginning of the Unix epoch on 1970/01/01 at 00:00:00 UTC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct UnixTime(pub u64);

impl From<SystemTime> for UnixTime {
    fn from(t: SystemTime) -> Self {
        let time = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        UnixTime(time)
    }
}

impl Serialize for UnixTime {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UnixTime {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = u64::deserialize(deserializer)?;
        Ok(Self(s))
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
    #[inline]
    fn now(&self) -> UnixTime {
        UnixTime::from(SystemTime::now())
    }
}

/// A test clock which maintains the current time as internal state
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestClock(UnixTime);

impl Clock for TestClock {
    #[inline]
    fn now(&self) -> UnixTime {
        self.0
    }
}

impl TestClock {
    /// Creates a new test clock with the specified time
    #[inline]
    pub const fn new(time: UnixTime) -> Self {
        Self(time)
    }

    /// Updates the clock's current time to `val`
    pub fn set(&mut self, val: UnixTime) {
        self.0 = val;
    }

    /// Increments the clock's current time by `inc` seconds
    pub fn inc(&mut self, inc: u64) {
        (self.0).0 += inc;
    }
}
