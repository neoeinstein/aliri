use std::{error, sync::Arc, time::Duration};

use aliri_clock::{Clock, DurationSecs, System, UnixTime};
use thiserror::Error;
use tokio::sync::{watch, Mutex};

use crate::{
    backoff::{ErrorBackoffConfig, ErrorBackoffHandler, WithBackoff},
    jitter::JitterSource,
    sources::AsyncTokenSource,
    TokenWatcher, TokenWithLifetime,
};

enum Delay {
    UntilTime(UnixTime),
    ForDuration(Duration),
}

/// An error generated when refreshing the token failed
#[derive(Debug, Error)]
pub enum TokenRefreshFailed {
    /// An error generated when sending the token failed
    #[error("sending token failed")]
    SendError(#[from] watch::error::SendError<TokenWithLifetime>),
    /// An error generated when requesting the token failed
    #[error("requesting token failed")]
    RequestTokenError(#[from] Box<dyn error::Error + Send + Sync>),
}

/// A token watcher that can be uses to obtain up-to-date tokens
#[derive(Debug)]
pub struct TokenRefresher<S: AsyncTokenSource> {
    watcher: watch::Receiver<TokenWithLifetime>,
    sender: Arc<Mutex<watch::Sender<TokenWithLifetime>>>,
    token_source: Arc<Mutex<S>>,
    fr_join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl<S: AsyncTokenSource + 'static> TokenRefresher<S> {
    /// Gets a watcher for watching the token change
    pub fn get_watcher(&self) -> TokenWatcher {
        TokenWatcher::new(self.watcher.clone())
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
    pub async fn spawn_from_token_source<J>(
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
    pub async fn spawn_from_token_source_with_clock<J, C>(
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

        let (tx, rx) = watch::channel(initial_token);

        let mut token_refresher = TokenRefresher {
            watcher: rx,
            sender: Arc::new(Mutex::new(tx)),
            token_source: Arc::new(Mutex::new(token_source)),
            fr_join_handle: None,
        };

        let join = tokio::spawn(TokenRefresher::<S>::forever_refresh(
            token_refresher.token_source.clone(),
            jitter_source,
            token_refresher.sender.clone(),
            first_stale,
            backoff_config,
            clock,
        ));

        token_refresher.fr_join_handle = Some(join);

        /*tokio::spawn(async move {
            if let Err(err) = join.await {
                if err.is_panic() {
                    tracing::error!("forever refresh panicked!")
                } else if err.is_cancelled() {
                    tracing::info!("forever refresh was cancelled")
                }
            } else {
                tracing::info!("all token listeners dropped")
            }
        });*/

        Ok(token_refresher)
    }

    async fn forever_refresh<J, C>(
        token_source: Arc<Mutex<S>>,
        mut jitter_source: J,
        tx: Arc<Mutex<watch::Sender<TokenWithLifetime>>>,
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
                    tokio::time::sleep(d).await;
                }
                Delay::UntilTime(t) => {
                    // We do this dance because the timer does not "advance" while a system is
                    // suspended. This is unlikely to occur if the instance is
                    // long-lived in the cloud, but on local machines, such as laptops,
                    // this is more possible.
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
                            tokio::time::sleep(delay.into()).await;
                        }
                    }
                }
            }

            tracing::debug!("requesting new token");
            let mut token_source = token_source.lock().await;

            stale_epoch = match token_source
                .request_token()
                .await
                .with_backoff(&mut backoff_handler)
            {
                Ok(token) => {
                    let token_stale = token.stale();

                    if tx.lock().await.send(token).is_err() {
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

    /// Manually refreshes the token
    ///
    /// Be aware that if you are using caching, the cache will still be used
    pub async fn refresh(&mut self) -> Result<(), TokenRefreshFailed> {
        let mut token_source = self.token_source.lock().await;

        let token = token_source
            .request_token()
            .await
            .map_err(|error| TokenRefreshFailed::RequestTokenError(Box::new(error)))?;

        self.refresh_using_token(token)
            .await
            .map_err(TokenRefreshFailed::SendError)
    }

    /// Manually refreshes the token using the specified token
    pub async fn refresh_using_token(
        &self,
        token: TokenWithLifetime,
    ) -> Result<(), watch::error::SendError<TokenWithLifetime>> {
        self.sender.lock().await.send(token)
    }
}

impl<S: AsyncTokenSource> Drop for TokenRefresher<S> {
    fn drop(&mut self) {
        if let Some(join) = self.fr_join_handle.as_ref() {
            join.abort()
        };
    }
}
