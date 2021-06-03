//! Error backoff handling

use std::time::Duration;

/// Configuration for how to manage backoff when an error is encountered
#[derive(Debug)]
pub struct ErrorBackoffConfig {
    initial_error_delay: Duration,
    max_error_delay: Duration,
    multiplier: u64,
}

impl Default for ErrorBackoffConfig {
    /// Default backoff configuration
    ///
    /// Uses an initial error delay of 100 ms with a multiplier of 2. Maximum delay is
    /// capped at 15 seconds.
    fn default() -> Self {
        Self {
            initial_error_delay: Duration::from_millis(100),
            max_error_delay: Duration::from_secs(15),
            multiplier: 2,
        }
    }
}

impl ErrorBackoffConfig {
    /// Constructs a new backoff configuration
    ///
    /// When encountering an error for the first time, the backoff will be `initial_error_delay`.
    /// On subsequent errors, the backoff should be multiplied by `multiplier`, with a cap of
    /// `max_error_delay`.
    pub fn new(initial_error_delay: Duration, max_error_delay: Duration, multiplier: u64) -> Self {
        Self {
            initial_error_delay,
            max_error_delay,
            multiplier,
        }
    }
}

/// Utility trait for extending types with a backoff handler
pub trait WithBackoff {
    /// The output of providing backoff
    type Output;

    /// Applies backoff to the current value
    fn with_backoff(self, handler: &mut ErrorBackoffHandler) -> Self::Output;
}

impl<T, E> WithBackoff for Result<T, E> {
    type Output = Result<T, (E, Duration)>;
    fn with_backoff(self, handler: &mut ErrorBackoffHandler) -> Self::Output {
        match self {
            Ok(ok) => {
                handler.success();
                Ok(ok)
            }
            Err(err) => Err((err, handler.error())),
        }
    }
}

/// A stateful handler that manages error backoff state
#[derive(Debug)]
pub struct ErrorBackoffHandler {
    config: ErrorBackoffConfig,
    last_delay: Option<Duration>,
}

impl ErrorBackoffHandler {
    /// Constructs a new handler from an [`ErrorBackoffConfig`].
    pub fn new(config: ErrorBackoffConfig) -> Self {
        Self {
            config,
            last_delay: None,
        }
    }

    /// Reports a success
    ///
    /// This resets the internal delay state.
    pub fn success(&mut self) {
        self.last_delay = None;
    }

    /// Reports a failure and returns the expected backoff delay
    ///
    /// This will apply the values in the backoff configuration, increasing the backoff delay
    /// if required, and then report the expected next delay.
    pub fn error(&mut self) -> Duration {
        let new_delay = self
            .last_delay
            .map(|s: Duration| {
                (Duration::from_millis(s.as_millis() as u64 * self.config.multiplier))
                    .min(self.config.max_error_delay)
            })
            .unwrap_or(self.config.initial_error_delay);
        self.last_delay = Some(new_delay);
        new_delay
    }
}

impl From<ErrorBackoffConfig> for ErrorBackoffHandler {
    fn from(config: ErrorBackoffConfig) -> Self {
        Self::new(config)
    }
}
