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

use std::{
    fmt, ops,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

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

impl From<UnixTime> for SystemTime {
    #[inline]
    fn from(t: UnixTime) -> Self {
        SystemTime::UNIX_EPOCH + Duration::from_secs(t.0)
    }
}

impl fmt::Display for UnixTime {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl ops::Add<DurationSecs> for UnixTime {
    type Output = Self;

    #[inline]
    fn add(self, other: DurationSecs) -> Self::Output {
        Self(self.0 + other.0)
    }
}

impl ops::AddAssign<DurationSecs> for UnixTime {
    #[inline]
    fn add_assign(&mut self, other: DurationSecs) {
        self.0 += other.0
    }
}

impl ops::Sub<DurationSecs> for UnixTime {
    type Output = Self;

    #[inline]
    fn sub(self, other: DurationSecs) -> Self::Output {
        Self(self.0 - other.0)
    }
}

impl ops::SubAssign<DurationSecs> for UnixTime {
    #[inline]
    fn sub_assign(&mut self, other: DurationSecs) {
        self.0 -= other.0
    }
}

impl ops::Sub for UnixTime {
    type Output = DurationSecs;

    #[inline]
    fn sub(self, other: Self) -> Self::Output {
        DurationSecs(self.0 - other.0)
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

/// Duration denominated in whole seconds
///
/// An unsigned duration in whole seconds. This type is just a bit more svelte than
/// the standard duration type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct DurationSecs(pub u64);

impl From<Duration> for DurationSecs {
    #[inline]
    fn from(d: Duration) -> Self {
        Self(d.as_secs())
    }
}

impl From<DurationSecs> for Duration {
    #[inline]
    fn from(d: DurationSecs) -> Self {
        Duration::from_secs(d.0)
    }
}

impl fmt::Display for DurationSecs {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl ops::Add for DurationSecs {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self::Output {
        Self(self.0 + other.0)
    }
}

impl ops::AddAssign for DurationSecs {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0
    }
}

impl ops::Sub for DurationSecs {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self::Output {
        Self(self.0 - other.0)
    }
}

impl ops::SubAssign for DurationSecs {
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        self.0 -= other.0
    }
}

impl ops::Mul<u64> for DurationSecs {
    type Output = Self;

    #[inline]
    fn mul(self, other: u64) -> Self {
        Self(self.0 * other)
    }
}

impl ops::MulAssign<u64> for DurationSecs {
    #[inline]
    fn mul_assign(&mut self, other: u64) {
        self.0 *= other
    }
}

impl ops::Mul<f64> for DurationSecs {
    type Output = Self;

    #[inline]
    fn mul(self, other: f64) -> Self {
        Self((self.0 as f64 * other) as u64)
    }
}

impl ops::MulAssign<f64> for DurationSecs {
    #[inline]
    fn mul_assign(&mut self, other: f64) {
        *self = *self * other
    }
}

impl ops::Div<u64> for DurationSecs {
    type Output = Self;

    #[inline]
    fn div(self, other: u64) -> Self {
        Self(self.0 / other)
    }
}

impl ops::DivAssign<u64> for DurationSecs {
    #[inline]
    fn div_assign(&mut self, other: u64) {
        self.0 /= other
    }
}

#[cfg(any(feature = "serde", doc))]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for DurationSecs {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

#[cfg(any(feature = "serde", doc))]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de> Deserialize<'de> for DurationSecs {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = u64::deserialize(deserializer)?;
        Ok(Self(s))
    }
}

/// Represents a clock, which can tell the current time
pub trait Clock: fmt::Debug {
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
#[derive(Clone, Debug, Default)]
pub struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    #[inline]
    fn now(&self) -> UnixTime {
        UnixTime(self.0.load(Ordering::Acquire))
    }
}

impl TestClock {
    /// Creates a new test clock with the specified time
    #[inline]
    pub fn new(time: UnixTime) -> Self {
        Self(Arc::new(AtomicU64::new(time.0)))
    }

    /// Updates the clock's current time to `val`
    pub fn set(&self, val: UnixTime) {
        self.0.store(val.0, Ordering::Release);
    }

    /// Increments the clock's current time by `inc` seconds
    pub fn advance(&self, inc: DurationSecs) {
        self.0.fetch_add(inc.0, Ordering::AcqRel);
    }
}
