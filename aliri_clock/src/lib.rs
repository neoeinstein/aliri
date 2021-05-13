//! Utilities for messing with time
//!
//! Types included allow messing with and mocking out clocks and other
//! side-effect-laden time operations.

#![warn(
    missing_docs,
    unused_import_braces,
    unused_imports,
    unused_qualifications
)]
#![deny(
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_must_use
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::time::SystemTime;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Unix time
///
/// Unix time as represented by the number of seconds elapsed since the
/// beginning of the Unix epoch on 1970/01/01 at 00:00:00 UTC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct UnixTime(pub u64);

impl From<SystemTime> for UnixTime {
    #[inline]
    fn from(t: SystemTime) -> Self {
        let time = t
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("times before Unix epoch are not expected")
            .as_secs();

        UnixTime(time)
    }
}

#[cfg(any(feature = "serde", doc))]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for UnixTime {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

#[cfg(any(feature = "serde", doc))]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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
