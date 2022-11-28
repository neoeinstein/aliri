use aliri_clock::{Clock, DurationSecs, System, UnixTime};
use serde::{Deserialize, Serialize};

use super::{AccessTokenRef, IdTokenRef};

/// A token as returned by the authority with some additional lifetime information
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenWithLifetime {
    access_token: Box<AccessTokenRef>,
    id_token: Option<Box<IdTokenRef>>,
    lifetime: DurationSecs,
    issued: UnixTime,
    stale: UnixTime,
    expiry: UnixTime,
}

impl TokenWithLifetime {
    pub(crate) fn clone_it(&self) -> Self {
        Self {
            access_token: self.access_token.to_owned().into_boxed_ref(),
            id_token: self
                .id_token
                .as_deref()
                .map(|x| (*x).to_owned().into_boxed_ref()),
            lifetime: self.lifetime,
            issued: self.issued,
            stale: self.stale,
            expiry: self.expiry,
        }
    }
}

/// A token's lifecycle status
#[derive(Debug)]
pub enum TokenStatus {
    /// The token is fresh and valid
    Fresh,
    /// The token is valid, but should be refreshed
    Stale,
    /// The token is no longer valid
    Expired,
}

impl TokenWithLifetime {
    /// Gets the current access token
    #[inline]
    pub fn access_token(&self) -> &AccessTokenRef {
        &self.access_token
    }

    /// Gets the current ID token, if available
    #[inline]
    pub fn id_token(&self) -> Option<&IdTokenRef> {
        self.id_token.as_deref()
    }

    /// Gets the token's lifetime
    #[inline]
    pub fn lifetime(&self) -> DurationSecs {
        self.lifetime
    }

    /// Gets the time that the token was issued
    #[inline]
    pub fn issued(&self) -> UnixTime {
        self.issued
    }

    /// Gets the time that the token will become stale
    #[inline]
    pub fn stale(&self) -> UnixTime {
        self.stale
    }

    /// Gets the time that the token will expire
    #[inline]
    pub fn expiry(&self) -> UnixTime {
        self.expiry
    }

    /// Gets the interval during which the token should be considered fresh
    #[inline]
    pub fn fresh_interval(&self) -> std::ops::Range<UnixTime> {
        self.issued..self.stale
    }

    /// Gets the interval during which the token is valid
    #[inline]
    pub fn valid_interval(&self) -> std::ops::Range<UnixTime> {
        self.issued..self.expiry
    }

    /// Gets the token's current lifetime status
    #[inline]
    pub fn token_status(&self) -> TokenStatus {
        self.token_status_with_clock(&System)
    }

    /// Gets the token's lifetime status based on the current time
    /// as reported by the provided clock
    #[inline]
    pub fn token_status_with_clock<C: Clock>(&self, clock: &C) -> TokenStatus {
        self.token_status_at(clock.now())
    }

    /// Gets the token's lifetime status as of the provided time
    #[inline]
    pub fn token_status_at(&self, time: UnixTime) -> TokenStatus {
        if time < self.stale {
            TokenStatus::Fresh
        } else if time < self.expiry {
            TokenStatus::Stale
        } else {
            TokenStatus::Expired
        }
    }

    /// Gets a duration for how much longer the token will be fresh
    #[inline]
    pub fn until_stale(&self) -> DurationSecs {
        self.until_stale_with_clock(&System)
    }

    /// Gets a duration for how much longer the token will be fresh based on the current time
    /// as reported by the provided clock
    #[inline]
    pub fn until_stale_with_clock<C: Clock>(&self, clock: &C) -> DurationSecs {
        self.until_stale_at(clock.now())
    }

    /// Gets a duration for how much longer the token would be fresh as of the
    /// provided time
    #[inline]
    pub fn until_stale_at(&self, time: UnixTime) -> DurationSecs {
        if time < self.stale {
            self.stale - time
        } else {
            DurationSecs(0)
        }
    }

    /// Gets a duration for how much longer the token will be valid
    #[inline]
    pub fn until_expired(&self) -> DurationSecs {
        self.until_expired_with_clock(&System)
    }

    /// Gets a duration for how much longer the token will be valid based on the current time
    /// as reported by the provided clock
    #[inline]
    pub fn until_expired_with_clock<C: Clock>(&self, clock: &C) -> DurationSecs {
        self.until_expired_at(clock.now())
    }

    /// Gets a duration for how much longer the token would be valid as of the
    /// provided time
    #[inline]
    pub fn until_expired_at(&self, time: UnixTime) -> DurationSecs {
        if time < self.expiry {
            self.expiry - time
        } else {
            DurationSecs(0)
        }
    }
}

/// Configuration for determining how long a token should be considered fresh
#[derive(Clone, Debug)]
pub struct TokenLifetimeConfig<C = System> {
    freshness_period: f64,
    min_staleness_period: DurationSecs,
    clock: C,
}

impl Default for TokenLifetimeConfig {
    /// Default lifetime configuration
    ///
    /// Uses a freshness period of 75%, with a minimum stale period of 30 seconds, and using
    /// the system clock.
    fn default() -> Self {
        Self {
            freshness_period: 0.75,
            min_staleness_period: DurationSecs(30),
            clock: System,
        }
    }
}

impl TokenLifetimeConfig {
    /// Constructs a new lifetime configuration
    ///
    /// A token using this configuration will be considered stale when the `freshness_period`
    /// (represented as a ratio of the token's lifetime) has passed. The token will be always
    /// be considered stale with at least `min_staleness_period` remaining.
    pub fn new(freshness_period: f64, min_staleness_period: DurationSecs) -> Self {
        Self {
            freshness_period,
            min_staleness_period,
            clock: System,
        }
    }
}

impl<C> TokenLifetimeConfig<C> {
    fn time_to_stale(&self, issued: UnixTime, valid_duration: DurationSecs) -> UnixTime {
        let delay = (valid_duration * self.freshness_period).max(self.min_staleness_period);
        issued + delay
    }
}

impl<C: Clock> TokenLifetimeConfig<C> {
    /// Given an access token, id token, and token lifetime, constructs a token with a lifetime
    pub fn create_token<A, I>(
        &self,
        access_token: A,
        id_token: Option<I>,
        valid_duration: DurationSecs,
    ) -> TokenWithLifetime
    where
        A: AsRef<AccessTokenRef>,
        I: AsRef<IdTokenRef>,
    {
        let issued = self.clock.now();
        TokenWithLifetime {
            access_token: access_token.as_ref().to_owned().into_boxed_ref(),
            id_token: id_token.map(|i| i.as_ref().to_owned().into_boxed_ref()),
            lifetime: valid_duration,
            issued,
            stale: self.time_to_stale(issued, valid_duration),
            expiry: issued + valid_duration,
        }
    }
}
