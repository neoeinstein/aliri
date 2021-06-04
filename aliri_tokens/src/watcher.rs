use crate::jitter::JitterSource;
use crate::sources::AsyncTokenSource;
use crate::{
    backoff::{ErrorBackoffConfig, ErrorBackoffHandler, WithBackoff},
    TokenWithLifetime,
};
use aliri_clock::{Clock, DurationSecs, System, UnixTime};
use std::{error, ops, sync::Arc, time::Duration};
use tokio::sync::watch;

/// A token watcher that can be uses to obtain up-to-date tokens
#[derive(Clone, Debug)]
pub struct TokenWatcher {
    watcher: watch::Receiver<Arc<TokenWithLifetime>>,
}

/// An outstanding borrow of a token
///
/// This borrow should be held for as brief a time as possible, as outstanding
/// token borrows will block updates of a new token.
#[derive(Debug)]
pub struct BorrowedToken<'a> {
    inner: watch::Ref<'a, Arc<TokenWithLifetime>>,
}

impl<'a> ops::Deref for BorrowedToken<'a> {
    type Target = TokenWithLifetime;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl TokenWatcher {
    /// Spawns a new token watcher which will automatically and periodically refresh
    /// the token from a token source
    ///
    /// The token will be refreshed when it becomes stale. The token's stale time will be
    /// jittered by `jitter_source` so that multiple instances don't stampede at the same time.
    ///
    /// This jittering also has the benefit of potentially allowing an update from one instance
    /// to be shared within a caching layer, thus preventing multiple requests to the ultimate
    /// token authority.
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
        mut token_source: S,
        jitter_source: J,
        backoff_config: ErrorBackoffConfig,
        clock: C,
    ) -> Result<Self, S::Error>
    where
        S: AsyncTokenSource + 'static,
        J: JitterSource + Send + 'static,
        C: Clock + Send + 'static,
    {
        let initial_token = token_source.request_token().await?;

        let first_stale = initial_token.stale();

        let (tx, rx) = watch::channel(initial_token.into());

        let join = tokio::spawn(forever_refresh(
            token_source,
            jitter_source,
            tx,
            first_stale,
            backoff_config,
            clock,
        ));

        tokio::spawn(async move {
            if let Err(err) = join.await {
                if err.is_panic() {
                    tracing::error!("forever refresh panicked!")
                } else if err.is_cancelled() {
                    tracing::info!("forever refresh was cancelled")
                }
            } else {
                tracing::info!("all token listeners dropped")
            }
        });

        // TODO: Return a join handle to the user to allow cancellation?

        Ok(TokenWatcher { watcher: rx })
    }

    // /// A future that returns as ready whenever a new token is published
    // ///
    // /// If the publisher is ever dropped, then this function will return an error
    // /// indicating that no new tokens will be published.
    // pub async fn changed(&mut self) -> Result<(), TokenPublisherQuit> {
    //     Ok(self.watcher.changed().await?)
    // }

    /// Borrows the current valid token
    ///
    /// This borrow should be short-lived as outstanding borrows will block the publisher
    /// being able to report new tokens.
    pub fn token(&self) -> BorrowedToken {
        BorrowedToken {
            inner: self.watcher.borrow(),
        }
    }

    // /// Runs a given asynchronous function whenever a new token update is provided
    // ///
    // /// Loops forever so long as the publisher is still alive.
    // pub async fn watch<
    //     X: Fn(TokenWithLifetime) -> F,
    //     F: std::future::Future<Output = ()> + 'static,
    // >(
    //     mut self,
    //     sink: X,
    // ) {
    //     loop {
    //         if self.changed().await.is_err() {
    //             break;
    //         }
    //
    //         let t = (*self.token()).clone_it();
    //         sink(t).await
    //     }
    // }
}

enum Delay {
    UntilTime(UnixTime),
    ForDuration(Duration),
}

async fn forever_refresh<S, J, C>(
    mut token_source: S,
    mut jitter_source: J,
    tx: watch::Sender<Arc<TokenWithLifetime>>,
    first_stale: UnixTime,
    backoff_config: ErrorBackoffConfig,
    clock: C,
) where
    S: AsyncTokenSource,
    J: JitterSource,
    C: Clock,
{
    let mut backoff_handler = ErrorBackoffHandler::new(backoff_config);
    let mut stale_epoch = Delay::UntilTime(jitter_source.jitter(first_stale));

    loop {
        match stale_epoch {
            Delay::ForDuration(d) => {
                tokio::time::delay_for(d).await;
            }
            Delay::UntilTime(t) => {
                // We do this dance because the timer does not "advance" while a system is suspended.
                // This is unlikely to occur if the instance is long-lived in the cloud, but on
                // local machines, such as laptops, this is more possible.
                //
                // To handle this case, we use a heartbeat of about 30 seconds. Thus, if we wake
                // up after the token is not just expired, but stale, there will be, on average,
                // a 15 second lag time until we attempt to get a current token.
                const HEARTBEAT: DurationSecs = DurationSecs(30);
                loop {
                    let now = clock.now();
                    if now >= t {
                        tracing::trace!("token now stale");
                        break;
                    } else {
                        let until_stale = t - now;
                        let delay = until_stale.min(HEARTBEAT);
                        tracing::trace!(
                            delay = delay.0,
                            until_stale = until_stale.0,
                            "token not yet stale, sleeping…"
                        );
                        tokio::time::delay_for(delay.into()).await;
                    }
                }
            }
        }

        tracing::debug!("requesting new token");
        stale_epoch = match token_source
            .request_token()
            .await
            .with_backoff(&mut backoff_handler)
        {
            Ok(token) => {
                let token_stale = token.stale();

                if tx.broadcast(token.into()).is_err() {
                    tracing::info!(
                        "no one is listening for token refreshes anymore, halting refreshes"
                    );
                    return;
                }

                tracing::debug!(
                    stale = token_stale.0,
                    delay = (token_stale - clock.now()).0,
                    "waiting for token to become stale"
                );
                Delay::UntilTime(jitter_source.jitter(token_stale))
            }
            Err((error, delay)) => {
                tracing::warn!(
                    error = (&error as &dyn error::Error),
                    delay_ms = delay.as_millis() as u64,
                    "error requesting token, will retry"
                );
                Delay::ForDuration(delay)
            }
        };
    }
}
