use std::ops;

use aliri_clock::{Clock, System};
use thiserror::Error;
use tokio::sync::watch;

use crate::{
    backoff::ErrorBackoffConfig, jitter::JitterSource, sources::AsyncTokenSource, TokenRefresher,
    TokenWithLifetime,
};

/// A token watcher that can be uses to obtain up-to-date tokens
#[derive(Clone, Debug)]
pub struct TokenWatcher {
    watcher: watch::Receiver<TokenWithLifetime>,
}

/// An outstanding borrow of a token
///
/// This borrow should be held for as brief a time as possible, as outstanding
/// token borrows will block updates of a new token.
#[derive(Debug)]
pub struct BorrowedToken<'a> {
    inner: watch::Ref<'a, TokenWithLifetime>,
}

impl ops::Deref for BorrowedToken<'_> {
    type Target = TokenWithLifetime;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// An error generated when the token publisher ceases to publish new tokens
#[derive(Debug, Error)]
#[error("token publisher has quit publishing new tokens")]
pub struct TokenPublisherQuit(#[from] watch::error::RecvError);

impl TokenWatcher {
    pub(crate) fn new(watcher: watch::Receiver<TokenWithLifetime>) -> Self {
        Self { watcher }
    }

    /// Spawns a new token watcher which will automatically and periodically refresh
    /// the token from a token source
    ///
    /// The token will be refreshed when it becomes stale. The token's stale time will be
    /// jittered by `jitter_source` so that multiple instances don't stampede at the same time.
    ///
    /// This jittering also has the benefit of potentially allowing an update from one instance
    /// to be shared within a caching layer, thus preventing multiple requests to the ultimate
    /// token authority.
    ///
    /// To also be able to refresh the token on demand, e.g. when the token authority revoked
    /// the current token, use a [`TokenRefresher`] instead.
    pub async fn spawn_from_token_source<S, J>(
        token_source: S,
        jitter_source: J,
        backoff_config: ErrorBackoffConfig,
    ) -> Result<Self, S::Error>
    where
        S: AsyncTokenSource + 'static,
        J: JitterSource + Send + 'static,
    {
        Self::spawn_from_token_source_with_clock(
            token_source,
            jitter_source,
            backoff_config,
            System,
        )
        .await
    }

    /// Spawns a new token watcher using the given clock
    pub async fn spawn_from_token_source_with_clock<S, J, C>(
        token_source: S,
        jitter_source: J,
        backoff_config: ErrorBackoffConfig,
        clock: C,
    ) -> Result<Self, S::Error>
    where
        S: AsyncTokenSource + 'static,
        J: JitterSource + Send + 'static,
        C: Clock + Send + 'static,
    {
        let refresher = TokenRefresher::spawn_from_token_source_with_clock(
            token_source,
            jitter_source,
            backoff_config,
            clock,
        )
        .await?;

        Ok(refresher.watcher())
    }

    /// A future that returns as ready whenever a new token is published
    ///
    /// If the publisher is ever dropped, then this function will return an error
    /// indicating that no new tokens will be published.
    pub async fn changed(&mut self) -> Result<(), TokenPublisherQuit> {
        Ok(self.watcher.changed().await?)
    }

    /// Borrows the current valid token
    ///
    /// This borrow should be short-lived as outstanding borrows will block the publisher
    /// being able to report new tokens.
    pub fn token(&self) -> BorrowedToken<'_> {
        BorrowedToken {
            inner: self.watcher.borrow(),
        }
    }

    /// Runs a given asynchronous function whenever a new token update is provided
    ///
    /// Loops forever so long as the publisher is still alive.
    pub async fn watch<
        X: Fn(TokenWithLifetime) -> F,
        F: std::future::Future<Output = ()> + 'static,
    >(
        mut self,
        sink: X,
    ) {
        loop {
            if self.changed().await.is_err() {
                break;
            }

            let t = (*self.token()).clone_it();
            sink(t).await
        }
    }
}
