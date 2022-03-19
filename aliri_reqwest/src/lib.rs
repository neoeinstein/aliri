//! Middleware to automatically attach authorization to outgoing requests
//!
//! When using [`ClientWithMiddleware`](reqwest_middleware::ClientWithMiddleware),
//! include the [`AccessTokenMiddleware`] in the middleware stack to use
//! the current access token provided by a [`TokenWatcher`] for each outbound
//! request.
//!
//! If a request already has specified an `Authorization` header value by
//! the time that the middleware executes, the existing value will be left
//! in place, allowing overrides to be specified as required.
//!
//! ```no_run
//! use aliri_reqwest::AccessTokenMiddleware;
//! use aliri_tokens::TokenWatcher;
//! use reqwest::Client;
//! use reqwest_middleware::ClientBuilder;
//! # use aliri_tokens::backoff::ErrorBackoffConfig;
//! # use aliri_tokens::jitter::NullJitter;
//! # use aliri_tokens::sources::ConstTokenSource;
//! #
//! # #[tokio::main(flavor = "current_thread")] async fn main() {
//! # let (token_source, jitter, backoff)  = (ConstTokenSource::new("token"), NullJitter, ErrorBackoffConfig::default());
//!
//! let token_watcher = TokenWatcher::spawn_from_token_source(
//!     token_source,
//!     jitter,
//!     backoff,
//! )
//! .await
//! .unwrap();
//!
//! let client = ClientBuilder::new(Client::default())
//!     .with(AccessTokenMiddleware::new(token_watcher))
//!     .build();
//!
//! let req = client
//!     .get("https://example.com");
//! # async move { req
//!     .send()
//!     .await
//!     .unwrap();
//! # };
//! # }
//! ```
//!
//! The middleware can also be configured to add an authorization token
//! only conditionally. This can be useful in the event that you want to
//! use a single common middleware stack with multiple potential backends
//! and want to ensure that specific tokens are used for specific backends.
//!
//! These predicates can be composed together to evaluate more complex
//! requirements prior to attaching a token to a request.
//!
//! ```no_run
//! use aliri_reqwest::{
//!     AccessTokenMiddleware, AccessTokenPredicate, ExactHostMatch, HttpsOnly
//! };
//! # let watcher = todo!();
//!
//! AccessTokenMiddleware::new(watcher)
//!     .with_predicate(HttpsOnly.and(ExactHostMatch::new("example.com")));
//! ```

#![warn(
    missing_docs,
    unused_import_braces,
    unused_imports,
    unused_qualifications
)]
#![deny(
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_must_use
)]

use aliri_clock::Clock;
use aliri_tokens::TokenWatcher;
use bytes::{BufMut, BytesMut};
use reqwest::{header, Request, Response};
use reqwest_middleware::{Middleware, Next, Result};
use task_local_extensions::Extensions;

/// A middleware that injects an access token into outgoing requests
#[derive(Clone, Debug)]
pub struct AccessTokenMiddleware<P> {
    token_watcher: TokenWatcher,
    predicate: P,
}

impl AccessTokenMiddleware<HttpsOnly> {
    /// Construct a new middleware from a token watcher
    ///
    /// By default, this middleware will only send its token if the request
    /// is being sent via HTTPS. To change this behavior, provide a
    /// custom predicate with [`with_predicate()`][Self::with_predicate()].
    pub fn new(token_watcher: TokenWatcher) -> Self {
        Self {
            token_watcher,
            predicate: HttpsOnly,
        }
    }

    /// Replaces the default predicate with a custom predicate
    pub fn with_predicate<P>(self, predicate: P) -> AccessTokenMiddleware<P> {
        AccessTokenMiddleware {
            token_watcher: self.token_watcher,
            predicate,
        }
    }
}

impl<P> AccessTokenMiddleware<P> {
    fn get_token_from_source(&self) -> header::HeaderValue {
        let token = self.token_watcher.token();

        if tracing::enabled!(tracing::Level::TRACE) {
            let now = aliri_clock::System.now();

            tracing::trace!(
                token.status = ?token.token_status_at(now),
                token.lifetime = token.lifetime().0,
                token.issued = token.issued().0,
                token.stale = token.stale().0,
                token.until_stale = token.until_stale_at(now).0,
                token.expiry = token.expiry().0,
                token.until_expired = token.until_expired_at(now).0,
                "obtained access token"
            );
        }

        let mut header_value = BytesMut::with_capacity(token.access_token().as_str().len() + 7);
        header_value.put_slice(b"bearer ");
        header_value.put_slice(token.access_token().as_str().as_bytes());
        let mut value =
            header::HeaderValue::from_maybe_shared(header_value).expect("only valid header bytes");
        value.set_sensitive(true);
        value
    }
}

#[async_trait::async_trait]
impl<P> Middleware for AccessTokenMiddleware<P>
where
    P: AccessTokenPredicate + Send + Sync + 'static,
{
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        if self.predicate.evaluate(&req) == PredicateResult::Attach {
            req.headers_mut()
                .entry(header::AUTHORIZATION)
                .or_insert_with(|| self.get_token_from_source());
        }

        next.run(req, extensions).await
    }
}

/// The result of evaluating a predicate
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum PredicateResult {
    /// Ignore the request
    Ignore,

    /// Attach an access token to the request
    Attach,
}

/// A predicate that decides whether or not an access token should be
/// attached to a request.
pub trait AccessTokenPredicate {
    /// Evaluate the predicate
    fn evaluate(&self, request: &Request) -> PredicateResult;

    /// Compose two predicates together using a logical and
    ///
    /// An access token will only be attached if both predicates return
    /// [`PredicateResult::Attach`]. This predicate will short circuit
    /// if the first predicate indicates ther request should be ignored..
    #[inline]
    fn and<P>(self, other: P) -> AndPredicate<Self, P>
    where
        Self: Sized,
    {
        AndPredicate {
            first: self,
            second: other,
        }
    }

    /// Compose two predicates together using a logical or
    ///
    /// An access token will be attached if either predicates return
    /// [`PredicateResult::Attach`]. This predicate will short circuit
    /// if the first predicate requests attachment.
    #[inline]
    fn or<P>(self, other: P) -> OrPredicate<Self, P>
    where
        Self: Sized,
    {
        OrPredicate {
            first: self,
            second: other,
        }
    }

    /// Invert the decision of a predicate using a logical not
    ///
    /// An access token will be attached if either predicates return
    /// [`PredicateResult::Ignore`].
    #[inline]
    fn not(self) -> NotPredicate<Self>
    where
        Self: Sized,
    {
        NotPredicate { inner: self }
    }
}

impl AccessTokenPredicate for PredicateResult {
    #[inline]
    fn evaluate(&self, _: &Request) -> PredicateResult {
        *self
    }
}

/// Only attach an access token if the request is being sent over HTTPS
#[derive(Clone, Copy, Debug)]
pub struct HttpsOnly;

impl AccessTokenPredicate for HttpsOnly {
    #[inline]
    fn evaluate(&self, req: &Request) -> PredicateResult {
        if req.url().scheme() == "https" {
            PredicateResult::Attach
        } else {
            PredicateResult::Ignore
        }
    }
}

/// Only attach an access token if the request is being sent to the exact host specified
#[derive(Clone, Debug)]
pub struct ExactHostMatch {
    host: String,
}

impl ExactHostMatch {
    /// Construct a new predicate from a host string
    pub fn new<S>(host: S) -> Self
    where
        S: ToString,
    {
        Self {
            host: host.to_string(),
        }
    }
}

impl AccessTokenPredicate for ExactHostMatch {
    #[inline]
    fn evaluate(&self, req: &Request) -> PredicateResult {
        if req.url().host_str() == Some(&self.host) {
            PredicateResult::Attach
        } else {
            PredicateResult::Ignore
        }
    }
}

/// Logical and of two predicates
///
/// See [`AccessTokenPredicate::and()`]
#[derive(Clone, Copy, Debug)]
pub struct AndPredicate<P1, P2> {
    first: P1,
    second: P2,
}

impl<P1, P2> AccessTokenPredicate for AndPredicate<P1, P2>
where
    P1: AccessTokenPredicate,
    P2: AccessTokenPredicate,
{
    #[inline]
    fn evaluate(&self, request: &Request) -> PredicateResult {
        if self.first.evaluate(request) == PredicateResult::Attach {
            self.second.evaluate(request)
        } else {
            PredicateResult::Ignore
        }
    }
}

/// Logical or of two predicates
///
/// See [`AccessTokenPredicate::or()`]
#[derive(Clone, Copy, Debug)]
pub struct OrPredicate<P1, P2> {
    first: P1,
    second: P2,
}

impl<P1, P2> AccessTokenPredicate for OrPredicate<P1, P2>
where
    P1: AccessTokenPredicate,
    P2: AccessTokenPredicate,
{
    #[inline]
    fn evaluate(&self, request: &Request) -> PredicateResult {
        if self.first.evaluate(request) == PredicateResult::Ignore {
            self.second.evaluate(request)
        } else {
            PredicateResult::Attach
        }
    }
}

/// Logical or of two predicates
///
/// See [`AccessTokenPredicate::not()`]
#[derive(Clone, Copy, Debug)]
pub struct NotPredicate<P> {
    inner: P,
}

impl<P> AccessTokenPredicate for NotPredicate<P>
where
    P: AccessTokenPredicate,
{
    #[inline]
    fn evaluate(&self, request: &Request) -> PredicateResult {
        if self.inner.evaluate(request) == PredicateResult::Ignore {
            PredicateResult::Attach
        } else {
            PredicateResult::Ignore
        }
    }
}

impl<F> AccessTokenPredicate for F
where
    F: Fn(&Request) -> PredicateResult,
{
    #[inline]
    fn evaluate(&self, request: &Request) -> PredicateResult {
        self(request)
    }
}

/// Convenience function for typing a predicate as an access token predicate
#[inline]
pub fn fn_predicate<F>(predicate: F) -> F
where
    F: Fn(&Request) -> PredicateResult,
{
    predicate
}

#[cfg(test)]
mod tests {
    use super::*;
    use aliri_tokens::backoff::ErrorBackoffConfig;
    use aliri_tokens::jitter::NullJitter;
    use aliri_tokens::sources::ConstTokenSource;
    use http::StatusCode;
    use reqwest::Client;
    use reqwest_middleware::ClientBuilder;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const TEST_TOKEN: &str = "this-is-a-test-token";
    const BEARER_TEST_TOKEN: &str = "bearer this-is-a-test-token";

    struct AuthChecker {
        expected_authorization: String,
        checked: AtomicBool,
    }

    impl AuthChecker {
        pub fn new(expected: impl Into<String>) -> Self {
            Self {
                expected_authorization: expected.into(),
                checked: AtomicBool::new(false),
            }
        }
    }

    #[async_trait::async_trait]
    impl Middleware for AuthChecker {
        async fn handle(&self, req: Request, _: &mut Extensions, _: Next<'_>) -> Result<Response> {
            let authorization_header = req
                .headers()
                .get(header::AUTHORIZATION)
                .expect("no authorization header")
                .to_str()
                .expect("authorization header was not valid UTF-8");

            assert_eq!(authorization_header, self.expected_authorization);
            self.checked.store(true, Ordering::Release);

            Ok(http::Response::<&[u8]>::default().into())
        }
    }

    #[derive(Default)]
    struct NoAuthChecker {
        checked: AtomicBool,
    }

    #[async_trait::async_trait]
    impl Middleware for NoAuthChecker {
        async fn handle(&self, req: Request, _: &mut Extensions, _: Next<'_>) -> Result<Response> {
            assert_eq!(req.headers().get(header::AUTHORIZATION), None);
            self.checked.store(true, Ordering::Release);

            Ok(http::Response::<&[u8]>::default().into())
        }
    }

    async fn prepare_middleware() -> AccessTokenMiddleware<HttpsOnly> {
        let token_watcher = TokenWatcher::spawn_from_token_source(
            ConstTokenSource::new(TEST_TOKEN),
            NullJitter,
            ErrorBackoffConfig::default(),
        )
        .await
        .unwrap();

        AccessTokenMiddleware::new(token_watcher)
    }

    mod when_request_does_not_have_an_authorization_header {
        use super::*;

        #[tokio::test]
        async fn middleware_with_defaults_attaches_token_on_https_request() {
            let middleware = prepare_middleware().await;
            let auth_checker = Arc::new(AuthChecker::new(BEARER_TEST_TOKEN));

            let client = ClientBuilder::new(Client::default())
                .with(middleware)
                .with_arc(auth_checker.clone())
                .build();

            let resp = client.get("https://example.com").send().await.unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert!(auth_checker.checked.load(Ordering::Acquire));
        }

        mod and_predicate_evaluates_to_attach {
            use super::*;

            #[tokio::test]
            async fn middleware_attaches_access_token() {
                let middleware = prepare_middleware()
                    .await
                    .with_predicate(PredicateResult::Attach);
                let auth_checker = Arc::new(AuthChecker::new(BEARER_TEST_TOKEN));

                let client = ClientBuilder::new(Client::default())
                    .with(middleware)
                    .with_arc(auth_checker.clone())
                    .build();

                let resp = client.get("https://example.com").send().await.unwrap();

                assert_eq!(resp.status(), StatusCode::OK);
                assert!(auth_checker.checked.load(Ordering::Acquire));
            }
        }

        mod and_predicate_evaluates_to_ignore {
            use super::*;

            #[tokio::test]
            async fn middleware_does_not_attach_access_token() {
                let middleware = prepare_middleware()
                    .await
                    .with_predicate(PredicateResult::Ignore);
                let auth_checker = Arc::new(NoAuthChecker::default());

                let client = ClientBuilder::new(Client::default())
                    .with(middleware)
                    .with_arc(auth_checker.clone())
                    .build();

                let resp = client.get("https://example.com").send().await.unwrap();

                assert_eq!(resp.status(), StatusCode::OK);
                assert!(auth_checker.checked.load(Ordering::Acquire));
            }
        }
    }

    mod when_request_already_contains_an_authorization_header {
        use super::*;

        #[tokio::test]
        async fn middleware_does_not_attach_access_token() {
            const OVERRIDE_TOKEN: &str = "overriden!";
            // Reqwest uses a capital `B` bearer
            const BEARER_OVERRIDE_TOKEN: &str = "Bearer overriden!";

            let middleware = prepare_middleware().await;
            let auth_checker = Arc::new(AuthChecker::new(BEARER_OVERRIDE_TOKEN));

            let client = ClientBuilder::new(Client::default())
                .with(middleware)
                .with_arc(auth_checker.clone())
                .build();

            let resp = client
                .get("https://example.com")
                .bearer_auth(OVERRIDE_TOKEN)
                .send()
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert!(auth_checker.checked.load(Ordering::Acquire));
        }
    }

    mod predicate_and_predicate {
        use super::*;

        #[test]
        fn both_attach_results_in_attach() {
            let predicate = HttpsOnly.and(ExactHostMatch::new("example.com"));
            let request =
                reqwest::Request::new(reqwest::Method::GET, "https://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Attach);
        }

        #[test]
        fn only_first_attach_results_in_ignore() {
            let predicate = HttpsOnly.and(ExactHostMatch::new("definitely-not.com"));
            let request =
                reqwest::Request::new(reqwest::Method::GET, "https://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Ignore);
        }

        #[test]
        fn only_second_attach_results_in_ignore() {
            let predicate = HttpsOnly.and(ExactHostMatch::new("example.com"));
            let request =
                reqwest::Request::new(reqwest::Method::GET, "http://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Ignore);
        }

        #[test]
        fn both_ignore_results_in_ignore() {
            let predicate = HttpsOnly.and(ExactHostMatch::new("definitely-not.com"));
            let request =
                reqwest::Request::new(reqwest::Method::GET, "http://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Ignore);
        }

        #[test]
        fn short_circuits_on_first_ignore() {
            let predicate = HttpsOnly.and(fn_predicate(|_| panic!("evaluated second predicate")));
            let request =
                reqwest::Request::new(reqwest::Method::GET, "http://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Ignore);
        }
    }

    mod predicate_or_predicate {
        use super::*;

        #[test]
        fn both_attach_results_in_attach() {
            let predicate = HttpsOnly.or(ExactHostMatch::new("example.com"));
            let request =
                reqwest::Request::new(reqwest::Method::GET, "https://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Attach);
        }

        #[test]
        fn only_first_attach_results_in_attach() {
            let predicate = HttpsOnly.or(ExactHostMatch::new("definitely-not.com"));
            let request =
                reqwest::Request::new(reqwest::Method::GET, "https://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Attach);
        }

        #[test]
        fn only_second_attach_results_in_attach() {
            let predicate = HttpsOnly.or(ExactHostMatch::new("example.com"));
            let request =
                reqwest::Request::new(reqwest::Method::GET, "http://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Attach);
        }

        #[test]
        fn both_ignore_results_in_ignore() {
            let predicate = HttpsOnly.or(ExactHostMatch::new("definitely-not.com"));
            let request =
                reqwest::Request::new(reqwest::Method::GET, "http://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Ignore);
        }

        #[test]
        fn short_circuits_on_first_attach() {
            let predicate = HttpsOnly.or(fn_predicate(|_| panic!("evaluated second predicate")));
            let request =
                reqwest::Request::new(reqwest::Method::GET, "https://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Attach);
        }
    }

    mod predicate_not {
        use super::*;

        #[test]
        fn attach_results_in_ignore() {
            let predicate = HttpsOnly.not();
            let request =
                reqwest::Request::new(reqwest::Method::GET, "https://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Ignore);
        }

        #[test]
        fn ignore_results_in_attach() {
            let predicate = HttpsOnly.not();
            let request =
                reqwest::Request::new(reqwest::Method::GET, "http://example.com".parse().unwrap());

            assert_eq!(predicate.evaluate(&request), PredicateResult::Attach);
        }
    }
}
