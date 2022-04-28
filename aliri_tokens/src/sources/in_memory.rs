//! An in-memory token caching layer

use crate::sources::AsyncTokenCache;
use crate::TokenWithLifetime;
use async_trait::async_trait;
use std::error;

/// An in-memory token cache
#[derive(Default, Debug)]
pub struct InMemoryTokenCache {
    token: Option<TokenWithLifetime>,
}

impl InMemoryTokenCache {
    /// Constructs a new in-memory token cache
    pub const fn new() -> Self {
        Self { token: None }
    }
}

#[async_trait]
impl AsyncTokenCache for InMemoryTokenCache {
    async fn request_token(
        &mut self,
    ) -> Result<TokenWithLifetime, Box<dyn error::Error + Send + Sync + 'static>> {
        self.token
            .as_ref()
            .map(|t| t.clone_it())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no token available"))
            .map_err(From::from)
    }

    async fn persist_token(
        &mut self,
        token: &TokenWithLifetime,
    ) -> Result<(), Box<dyn error::Error + Send + Sync + 'static>> {
        self.token = Some(token.clone_it());
        Ok(())
    }
}
