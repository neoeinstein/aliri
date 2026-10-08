use std::{error, sync::Arc};

use aliri_clock::{Clock, DurationSecs, System, UnixTime};
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::Instant,
};

use crate::{
    backoff::{ErrorBackoffConfig, ErrorBackoffHandler, WithBackoff},
    jitter::JitterSource,
    sources::AsyncTokenSource,
    TokenWatcher, TokenWithLifetime,
};

/// An error generated when a requested token refresh failed
#[derive(Clone, Debug, Error)]
pub enum TokenRefreshFailed {
    /// The token source failed to provide a new token
    #[error("requesting token failed")]
    RequestToken(#[source] Arc<dyn error::Error + Send + Sync>),
    /// The background refresh task is no longer running
    #[error("token refresher is no longer running")]
    RefresherStopped,
}

type RefreshReply = oneshot::Sender<Result<(), TokenRefreshFailed>>;

/// A handle to a background task which keeps a token up to date
///
/// The task refreshes the token whenever it becomes stale, just like
/// [`TokenWatcher::spawn_from_token_source()`], and additionally whenever
/// [`refresh()`](Self::refresh) is called, e.g. because an authority rejected the
/// current token.
#[derive(Clone, Debug)]
pub struct TokenRefresher {
    watcher: watch::Receiver<TokenWithLifetime>,
    requests: mpsc::UnboundedSender<RefreshReply>,
}

impl TokenRefresher {
    /// Spawns a new token refresher which will automatically and periodically refresh
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

    /// Spawns a new token refresher using the given clock
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

        let (tx, rx) = watch::channel(initial_token);
        let (requests, request_rx) = mpsc::unbounded_channel();

        let task = RefreshTask {
            token_source,
            jitter_source,
            backoff_handler: ErrorBackoffHandler::new(backoff_config),
            clock,
            tx,
            requests: request_rx,
            accepting_requests: true,
        };

        let join = tokio::spawn(task.run(first_stale));

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

        Ok(Self {
            watcher: rx,
            requests,
        })
    }

    /// Gets a watcher for the token
    pub fn watcher(&self) -> TokenWatcher {
        TokenWatcher::new(self.watcher.clone())
    }

    /// Refreshes the token immediately and waits until the new token has been published
    ///
    /// Concurrent calls are coalesced, such that all calls waiting at the same time are
    /// answered by a single request to the token source. Afterwards, the next automatic
    /// refresh is scheduled based on the new token.
    ///
    /// Be aware that a token source with a caching layer will hand out a cached token
    /// again as long as that token appears to be valid.
    pub async fn refresh(&self) -> Result<(), TokenRefreshFailed> {
        let (reply, response) = oneshot::channel();
        self.requests
            .send(reply)
            .map_err(|_| TokenRefreshFailed::RefresherStopped)?;
        response
            .await
            .map_err(|_| TokenRefreshFailed::RefresherStopped)?
    }
}

/// When the next refresh is due
#[derive(Clone, Copy)]
enum NextRefresh {
    /// When the current token becomes stale
    Stale(UnixTime),
    /// When the backoff after a failed refresh has elapsed
    Backoff(Instant),
}

enum Event {
    Timer,
    Request(Option<RefreshReply>),
    Closed,
}

/// The background task, which exclusively owns the token source
struct RefreshTask<S, J, C> {
    token_source: S,
    jitter_source: J,
    backoff_handler: ErrorBackoffHandler,
    clock: C,
    tx: watch::Sender<TokenWithLifetime>,
    requests: mpsc::UnboundedReceiver<RefreshReply>,
    accepting_requests: bool,
}

impl<S, J, C> RefreshTask<S, J, C>
where
    S: AsyncTokenSource,
    J: JitterSource,
    C: Clock,
{
    async fn run(mut self, first_stale: UnixTime) {
        let mut next = NextRefresh::Stale(self.jitter_source.jitter(first_stale));
        let mut waiting = Vec::new();

        loop {
            if !self.wait_for_refresh(next, &mut waiting).await {
                tracing::info!(
                    "no one is listening for token refreshes anymore, halting refreshes"
                );
                return;
            }

            tracing::debug!(requested = waiting.len(), "requesting new token");
            let result = self
                .token_source
                .request_token()
                .await
                .with_backoff(&mut self.backoff_handler);

            // Whoever asked for a refresh while the token was being requested is served
            // by this refresh as well
            while let Ok(reply) = self.requests.try_recv() {
                waiting.push(reply);
            }

            let outcome = match result {
                Ok(token) => {
                    let token_stale = token.stale();

                    if self.tx.send(token).is_err() {
                        tracing::info!(
                            "no one is listening for token refreshes anymore, halting refreshes"
                        );
                        return;
                    }

                    tracing::debug!(
                        stale = token_stale.0,
                        delay = (token_stale - self.clock.now()).0,
                        "waiting for token to become stale"
                    );
                    next = NextRefresh::Stale(self.jitter_source.jitter(token_stale));
                    Ok(())
                }
                Err((error, delay)) => {
                    tracing::warn!(
                        error = (&error as &dyn error::Error),
                        delay_ms = delay.as_millis() as u64,
                        "error requesting token, will retry"
                    );
                    next = NextRefresh::Backoff(Instant::now() + delay);
                    Err(TokenRefreshFailed::RequestToken(Arc::new(error)))
                }
            };

            for reply in waiting.drain(..) {
                let _ = reply.send(outcome.clone());
            }
        }
    }

    /// Waits until either the next refresh is due or a refresh has been requested
    ///
    /// Returns `false` once no one is interested in new tokens anymore.
    async fn wait_for_refresh(
        &mut self,
        next: NextRefresh,
        waiting: &mut Vec<RefreshReply>,
    ) -> bool {
        loop {
            let (wake_at, due_on_wake) = match next {
                NextRefresh::Backoff(deadline) => (deadline, true),
                NextRefresh::Stale(t) => {
                    // We do this dance because the timer does not "advance" while a system is
                    // suspended. This is unlikely to occur if the instance is
                    // long-lived in the cloud, but on local machines, such as laptops,
                    // this is more possible.
                    //
                    // To handle this case, we use a heartbeat of about 30 seconds. Thus, if we wake
                    // up after the token is not just expired, but stale, there will be, on average,
                    // a 15 second lag time until we attempt to get a current token.
                    const HEARTBEAT: DurationSecs = DurationSecs(30);
                    let now = self.clock.now();
                    if now >= t {
                        tracing::trace!("token now stale");
                        return true;
                    }

                    let until_stale = t - now;
                    let delay = until_stale.min(HEARTBEAT);
                    tracing::trace!(
                        delay = delay.0,
                        until_stale = until_stale.0,
                        "token not yet stale, sleeping…"
                    );
                    (Instant::now() + delay.into(), false)
                }
            };

            let event = tokio::select! {
                () = tokio::time::sleep_until(wake_at) => Event::Timer,
                reply = self.requests.recv(), if self.accepting_requests => Event::Request(reply),
                () = self.tx.closed() => Event::Closed,
            };

            match event {
                Event::Timer if due_on_wake => return true,
                Event::Timer => {}
                Event::Request(Some(reply)) => {
                    waiting.push(reply);
                    return true;
                }
                // Every refresher handle is gone, but watchers still want fresh tokens
                Event::Request(None) => self.accepting_requests = false,
                Event::Closed => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use async_trait::async_trait;
    use tokio::time;

    use super::*;
    use crate::{jitter::NullJitter, AccessToken, IdToken, TokenLifetimeConfig};

    /// A clock that follows tokio's (pausable) time
    #[derive(Debug)]
    struct TokioClock(Instant);

    impl Clock for TokioClock {
        fn now(&self) -> UnixTime {
            UnixTime(1_000_000 + self.0.elapsed().as_secs())
        }
    }

    #[derive(Debug, Error)]
    #[error("token source failed")]
    struct SourceFailed;

    /// Issues tokens valid for 100 seconds, which become stale after 75 seconds
    struct CountingSource {
        calls: Arc<AtomicUsize>,
        fail_from_call: Option<usize>,
        latency: Duration,
        start: Instant,
    }

    #[async_trait]
    impl AsyncTokenSource for CountingSource {
        type Error = SourceFailed;

        async fn request_token(&mut self) -> Result<TokenWithLifetime, Self::Error> {
            time::sleep(self.latency).await;
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_from_call.is_some_and(|n| call >= n) {
                return Err(SourceFailed);
            }

            Ok(TokenLifetimeConfig::default()
                .with_clock(TokioClock(self.start))
                .create_token(
                    AccessToken::new(format!("token-{call}")),
                    None::<IdToken>,
                    DurationSecs(100),
                ))
        }
    }

    fn source() -> (CountingSource, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = CountingSource {
            calls: calls.clone(),
            fail_from_call: None,
            latency: Duration::ZERO,
            start: Instant::now(),
        };
        (source, calls)
    }

    async fn spawn(source: CountingSource) -> TokenRefresher {
        let clock = TokioClock(source.start);
        TokenRefresher::spawn_from_token_source_with_clock(
            source,
            NullJitter,
            ErrorBackoffConfig::default(),
            clock,
        )
        .await
        .unwrap()
    }

    fn current_token(watcher: &TokenWatcher) -> String {
        watcher.token().access_token().as_str().to_owned()
    }

    #[tokio::test(start_paused = true)]
    async fn refreshes_when_token_becomes_stale() {
        let (source, calls) = source();
        let refresher = spawn(source).await;

        time::sleep(Duration::from_secs(70)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        time::sleep(Duration::from_secs(10)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(current_token(&refresher.watcher()), "token-2");
    }

    #[tokio::test(start_paused = true)]
    async fn manual_refresh_publishes_token_and_reschedules() {
        let (source, calls) = source();
        let refresher = spawn(source).await;

        time::sleep(Duration::from_secs(50)).await;
        refresher.refresh().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(current_token(&refresher.watcher()), "token-2");

        // The first token would have become stale at 75s, the new one becomes stale at 125s
        time::sleep(Duration::from_secs(30)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        time::sleep(Duration::from_secs(50)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_refreshes_are_coalesced() {
        let (mut source, calls) = source();
        source.latency = Duration::from_secs(1);
        let refresher = spawn(source).await;

        let (a, b, c) = tokio::join!(refresher.refresh(), refresher.refresh(), async {
            // Arrives while the first refresh is in flight
            time::sleep(Duration::from_millis(500)).await;
            refresher.refresh().await
        });

        a.unwrap();
        b.unwrap();
        c.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_refresh_is_reported_to_the_caller() {
        let (mut source, _) = source();
        source.fail_from_call = Some(2);
        let refresher = spawn(source).await;

        let err = refresher.refresh().await.unwrap_err();

        assert!(matches!(err, TokenRefreshFailed::RequestToken(_)));
        assert_eq!(current_token(&refresher.watcher()), "token-1");
    }

    #[tokio::test(start_paused = true)]
    async fn watchers_keep_receiving_tokens_after_refresher_is_dropped() {
        let (source, calls) = source();
        let watcher = spawn(source).await.watcher();

        time::sleep(Duration::from_secs(80)).await;

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(current_token(&watcher), "token-2");
    }
}
