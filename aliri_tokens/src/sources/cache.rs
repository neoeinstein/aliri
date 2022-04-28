//! Utilities for caching of tokens

use super::{AsyncTokenCache, AsyncTokenSource};
use crate::TokenWithLifetime;
use aliri_clock::{Clock, DurationSecs, System, UnixTime};
use async_trait::async_trait;
use std::{error, fmt};

/// A token source with zero or more intermediate caches and an ultimate fallback
pub struct CachedTokenSource<B, C = System> {
    caches: Vec<(String, Box<dyn AsyncTokenCache>)>,
    fallback: B,
    minimum_validity: DurationSecs,
    best_token_expiry: UnixTime,
    clock: C,
}

impl<B> CachedTokenSource<B, System> {
    /// Constructs a new cached token source
    ///
    /// `fallback` will be used as the last-resort token source if none of the caches
    /// successfully returns a token that is better than the token most recently obtained.
    pub fn new(fallback: B) -> Self {
        Self {
            caches: Vec::new(),
            fallback,
            minimum_validity: DurationSecs(60),
            best_token_expiry: UnixTime::default(),
            clock: System,
        }
    }
}

impl<B, C> CachedTokenSource<B, C> {
    /// Adds a caching layer to the token source
    pub fn with_cache(
        mut self,
        name: impl Into<String>,
        cache: impl AsyncTokenCache + 'static,
    ) -> Self {
        self.caches.push((name.into(), Box::new(cache)));
        self
    }

    /// Sets the minimum validity for any cached token returned by this source
    ///
    /// If a cache returns a token that will be valid for less than `minimum_validity`, then
    /// the next cache or fallback is queried instead of returning the token.
    pub fn with_minimum_validity(mut self, minimum_validity: DurationSecs) -> Self {
        self.minimum_validity = minimum_validity;
        self
    }

    /// Sets a custom clock to be used
    ///
    /// Useful for testing purposes
    pub fn with_clock<D>(self, clock: D) -> CachedTokenSource<B, D> {
        CachedTokenSource {
            caches: self.caches,
            fallback: self.fallback,
            minimum_validity: self.minimum_validity,
            best_token_expiry: self.best_token_expiry,
            clock,
        }
    }

    async fn cascade_token_updates(&mut self, token: &TokenWithLifetime, idx: Option<usize>) {
        let idx = idx.unwrap_or(self.caches.len() + 1);
        if idx > 0 {
            for (name, cache) in self.caches.iter_mut().take(idx - 1).rev() {
                match cache.persist_token(token).await {
                    Ok(()) => {
                        tracing::trace!(cache = %name, "pushed new token to cache");
                    }
                    Err(error) => {
                        tracing::warn!(cache = %name, error = (&*error as &dyn error::Error), "unable to push new token to cache");
                    }
                }
            }
        }

        self.best_token_expiry = token.expiry();
    }
}

impl<B, C> fmt::Debug for CachedTokenSource<B, C>
where
    B: fmt::Debug,
    C: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CachedTokenSource")
            .field(
                "caches",
                &self
                    .caches
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("fallback", &self.fallback)
            .field("minimum_validity", &self.minimum_validity)
            .field("best_token_expiry", &self.best_token_expiry)
            .field("clock", &self.clock)
            .finish()
    }
}

#[async_trait]
impl<B: AsyncTokenSource> AsyncTokenSource for CachedTokenSource<B> {
    type Error = B::Error;

    async fn request_token(&mut self) -> Result<TokenWithLifetime, Self::Error> {
        let mut found_token = None;
        for (idx, (name, cache)) in self.caches.iter_mut().enumerate() {
            match cache.request_token().await {
                Ok(token) => {
                    let must_be_valid_until = self.clock.now() + self.minimum_validity;

                    if token.expiry() < must_be_valid_until {
                        tracing::debug!(cache = %name, must_be_valid_until = must_be_valid_until.0, token_expiry = token.expiry().0, "found token in cache but does not meet minimum validity requirement, trying next source");
                    } else if token.expiry() <= self.best_token_expiry {
                        tracing::trace!(cache = %name, prior_expiry = self.best_token_expiry.0, token_expiry = token.expiry().0, "token in cache is not better, trying next source")
                    } else {
                        tracing::debug!(cache = %name, prior_expiry = self.best_token_expiry.0, token_expiry = token.expiry().0, "found token in cache with better expiry");
                        found_token = Some((idx, token));
                        break;
                    }
                }
                Err(error) => {
                    tracing::warn!(cache = %name, error = (&*error as &dyn error::Error), "token cache returned error, trying next source")
                }
            }
        }

        if let Some((idx, token)) = found_token {
            self.cascade_token_updates(&token, Some(idx)).await;
            Ok(token)
        } else {
            tracing::debug!("no cached token has better expiry, using fallback");

            match self.fallback.request_token().await {
                Ok(token) => {
                    self.cascade_token_updates(&token, None).await;
                    Ok(token)
                }
                Err(error) => Err(error),
            }
        }
    }
}
