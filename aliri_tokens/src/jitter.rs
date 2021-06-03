//! Utilities for adding a bit of jitter to reduce stampeding

use aliri_clock::UnixTime;

/// A type that provides some jittering of time
pub trait JitterSource {
    /// Jitters a given input time
    fn jitter(&mut self, time: UnixTime) -> UnixTime;
}

/// A jitter source that does not do any jittering of time
#[derive(Debug)]
pub struct NullJitter;

impl JitterSource for NullJitter {
    #[inline]
    fn jitter(&mut self, time: UnixTime) -> UnixTime {
        time
    }
}

#[cfg(feature = "rand")]
mod random {
    use aliri_clock::{DurationSecs, UnixTime};
    use rand::{Rng, SeedableRng};

    /// Jitters a value earlier by a random amount
    ///
    /// Times jittered by this type will have a value with a uniform distribution
    /// in the interval `(time - max_jitter, time]`.
    #[derive(Debug)]
    pub struct RandomEarlyJitter<R> {
        max_jitter: DurationSecs,
        rand_source: R,
    }

    impl RandomEarlyJitter<rand::rngs::StdRng> {
        /// Constructs a new instance that will jitter times early up to `max_jitter`.
        pub fn new(max_jitter: DurationSecs) -> Self {
            Self {
                max_jitter,
                rand_source: rand::rngs::StdRng::from_rng(rand::thread_rng()).unwrap(),
            }
        }
    }

    impl<R: Rng> super::JitterSource for RandomEarlyJitter<R> {
        fn jitter(&mut self, time: UnixTime) -> UnixTime {
            let jitter = self.rand_source.gen_range(0..(self.max_jitter.0));
            time - DurationSecs(jitter)
        }
    }
}

#[cfg(feature = "rand")]
pub use random::RandomEarlyJitter;
