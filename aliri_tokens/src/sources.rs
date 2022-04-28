//! Token sources

use crate::{
    AccessToken, AccessTokenRef, IdToken, IdTokenRef, TokenLifetimeConfig, TokenWithLifetime,
};
use aliri_clock::{DurationSecs, System};
use async_trait::async_trait;
use std::error;

pub mod cache;
#[cfg(feature = "file")]
#[cfg_attr(docsrs, doc(cfg(feature = "file")))]
pub mod file;
pub mod in_memory;
#[cfg(feature = "oauth2")]
#[cfg_attr(docsrs, doc(cfg(feature = "oauth2")))]
pub mod oauth2;

/// An asynchronous source for tokens
#[async_trait]
pub trait AsyncTokenSource: Send + Sync {
    /// The error type returned in the event that retrieving a token fails
    type Error: error::Error + Send + Sync + 'static;

    /// Requests a token from an asynchronous source
    async fn request_token(&mut self) -> Result<TokenWithLifetime, Self::Error>;
}

/// An asynchronous cache for tokens
///
/// This can be used to provide intermediate layers for caching and reusing tokens
#[async_trait]
pub trait AsyncTokenCache: Send + Sync {
    /// Requests a token from the cache
    async fn request_token(
        &mut self,
    ) -> Result<TokenWithLifetime, Box<dyn error::Error + Send + Sync + 'static>>;

    /// Persists a token into the cache
    async fn persist_token(
        &mut self,
        token: &TokenWithLifetime,
    ) -> Result<(), Box<dyn error::Error + Send + Sync + 'static>>;
}

/// A constant source that always returns the same access and id tokens
///
/// The lifetime parameters and reported validity can be configured as
/// desired to generate desired effects on token caching layers.
#[derive(Debug)]
pub struct ConstTokenSource<Clock> {
    access_token: Box<AccessTokenRef>,
    id_token: Option<Box<IdTokenRef>>,
    lifetime_config: TokenLifetimeConfig<Clock>,
    valid_duration: DurationSecs,
}

impl ConstTokenSource<System> {
    /// Constructs a new constant token source from the given access token
    ///
    /// By default, the token will use the default staleness parameters
    /// and indicate that every token is freshly valid for 60 seconds from
    /// when requested
    pub fn new<T>(access_token: T) -> Self
    where
        T: Into<AccessToken>,
    {
        Self {
            access_token: access_token.into().into_boxed_ref(),
            id_token: None,
            lifetime_config: TokenLifetimeConfig::default(),
            valid_duration: DurationSecs(60),
        }
    }
}

impl<Clock> ConstTokenSource<Clock> {
    /// Sets the static ID token
    pub fn with_id_token<T>(self, id_token: T) -> Self
    where
        T: Into<IdToken>,
    {
        Self {
            access_token: self.access_token,
            id_token: Some(id_token.into().into_boxed_ref()),
            lifetime_config: self.lifetime_config,
            valid_duration: self.valid_duration,
        }
    }

    /// Sets the lifetime config that will be used to influence
    /// token staleness
    pub fn with_lifetime_config<NewClock>(
        self,
        config: TokenLifetimeConfig<NewClock>,
    ) -> ConstTokenSource<NewClock> {
        ConstTokenSource {
            access_token: self.access_token,
            id_token: self.id_token,
            lifetime_config: config,
            valid_duration: self.valid_duration,
        }
    }

    /// Sets the token validity period for every time a token is returned
    pub fn with_token_valid_for(self, duration: DurationSecs) -> Self {
        Self {
            access_token: self.access_token,
            id_token: self.id_token,
            lifetime_config: self.lifetime_config,
            valid_duration: duration,
        }
    }
}

#[async_trait]
impl<Clock> AsyncTokenSource for ConstTokenSource<Clock>
where
    Clock: aliri_clock::Clock + Send + Sync,
{
    type Error = core::convert::Infallible;

    async fn request_token(&mut self) -> Result<TokenWithLifetime, Self::Error> {
        Ok(self.lifetime_config.create_token(
            &self.access_token,
            self.id_token.as_ref(),
            self.valid_duration,
        ))
    }
}
