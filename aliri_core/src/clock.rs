use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[repr(transparent)]
pub struct UnixTime(pub u64);

impl From<SystemTime> for UnixTime {
    fn from(t: SystemTime) -> Self {
        let time = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        UnixTime(time)
    }
}

pub trait Clock {
    fn now(&self) -> UnixTime;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct System;

impl Clock for System {
    fn now(&self) -> UnixTime {
        UnixTime::from(SystemTime::now())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestClock(UnixTime);

impl Clock for TestClock {
    fn now(&self) -> UnixTime {
        self.0
    }
}

impl TestClock {
    pub fn set(&mut self, val: UnixTime) {
        self.0 = val;
    }

    pub fn inc(&mut self, inc: u64) {
        (self.0).0 += inc;
    }
}
