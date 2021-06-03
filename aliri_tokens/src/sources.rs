//! Token sources

use crate::TokenWithLifetime;
use async_trait::async_trait;
use std::error;

pub mod cache;
#[cfg(feature = "file")]
pub mod file;
#[cfg(feature = "oauth2")]
pub mod oauth2;

pub use file::FileTokenSource;

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
