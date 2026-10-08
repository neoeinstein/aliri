use std::ops;

use thiserror::Error;
use tokio::sync::watch;

use crate::TokenWithLifetime;

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
    /// Create new TokenWatcher.
    pub fn new(reciever: watch::Receiver<TokenWithLifetime>) -> Self {
        Self { watcher: reciever }
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
    pub fn token(&'_ self) -> BorrowedToken<'_> {
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
