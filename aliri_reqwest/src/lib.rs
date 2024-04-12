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
//! ```
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
//! # let token_watcher = TokenWatcher::spawn_from_token_source(token_source, jitter, backoff).await.unwrap();
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
//! ```
//! use aliri_reqwest::{
//!     AccessTokenMiddleware, ExactHostMatch, HttpsOnly
//! };
//! use predicates::prelude::PredicateBooleanExt;
//! # use aliri_tokens::{
//! #    backoff::ErrorBackoffConfig,
//! #    jitter::NullJitter,
//! #    sources::ConstTokenSource,
//! #    TokenWatcher,
//! # };
//! # #[tokio::main(flavor = "current_thread")] async fn main() {
//! # let (token_source, jitter, backoff)  = (ConstTokenSource::new("token"), NullJitter, ErrorBackoffConfig::default());
//! # let token_watcher = TokenWatcher::spawn_from_token_source(token_source, jitter, backoff).await.unwrap();
//!
//! AccessTokenMiddleware::new(token_watcher)
//!     .with_predicate(HttpsOnly.and(ExactHostMatch::new("example.com")));
//! # }
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

use std::fmt;

use aliri_clock::Clock;
use aliri_tokens::TokenWatcher;
use bytes::{BufMut, BytesMut};
use predicates::{prelude::*, reflection};
use reqwest::{header, Request, Response};
use reqwest_middleware::{Middleware, Next, Result};

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
        header_value.put_slice(b"Bearer ");
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
    P: Predicate<Request> + Send + Sync + 'static,
{
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        if self.predicate.eval(&req) {
            req.headers_mut()
                .entry(header::AUTHORIZATION)
                .or_insert_with(|| self.get_token_from_source());
        }

        next.run(req, extensions).await
    }
}

/// Only attach an access token if the request is being sent over HTTPS
#[derive(Clone, Copy, Debug)]
pub struct HttpsOnly;

impl Predicate<Request> for HttpsOnly {
    #[inline]
    fn eval(&self, req: &Request) -> bool {
        req.url().scheme() == "https"
    }

    fn find_case(&self, expected: bool, req: &Request) -> Option<reflection::Case> {
        let result = self.eval(req);
        if result != expected {
            Some(
                reflection::Case::new(Some(self), result).add_product(reflection::Product::new(
                    "scheme",
                    req.url().scheme().to_owned(),
                )),
            )
        } else {
            None
        }
    }
}

impl reflection::PredicateReflection for HttpsOnly {}
impl fmt::Display for HttpsOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("scheme is https")
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

impl Predicate<Request> for ExactHostMatch {
    #[inline]
    fn eval(&self, req: &Request) -> bool {
        req.url().host_str() == Some(&self.host)
    }

    fn find_case(&self, expected: bool, req: &Request) -> Option<reflection::Case> {
        let result = self.eval(req);
        if result != expected {
            Some(
                reflection::Case::new(Some(self), result).add_product(reflection::Product::new(
                    "host",
                    req.url()
                        .host_str()
                        .unwrap_or("<value not valid utf-8>")
                        .to_owned(),
                )),
            )
        } else {
            None
        }
    }
}

impl reflection::PredicateReflection for ExactHostMatch {}
impl fmt::Display for ExactHostMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("host == ")?;
        f.write_str(&self.host)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use aliri_tokens::{
        backoff::ErrorBackoffConfig, jitter::NullJitter, sources::ConstTokenSource,
    };
    use reqwest::Client;
    use reqwest_middleware::ClientBuilder;

    use super::*;

    const TEST_TOKEN: &str = "this-is-a-test-token";
    const BEARER_TEST_TOKEN: &str = "Bearer this-is-a-test-token";

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
        async fn handle(
            &self,
            req: Request,
            _: &mut http::Extensions,
            _: Next<'_>,
        ) -> Result<Response> {
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
        async fn handle(
            &self,
            req: Request,
            _: &mut http::Extensions,
            _: Next<'_>,
        ) -> Result<Response> {
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

            assert_eq!(resp.status(), http::StatusCode::OK);
            assert!(auth_checker.checked.load(Ordering::Acquire));
        }

        mod and_predicate_evaluates_to_attach {
            use super::*;

            #[tokio::test]
            async fn middleware_attaches_access_token() {
                let middleware = prepare_middleware()
                    .await
                    .with_predicate(predicate::always());
                let auth_checker = Arc::new(AuthChecker::new(BEARER_TEST_TOKEN));

                let client = ClientBuilder::new(Client::default())
                    .with(middleware)
                    .with_arc(auth_checker.clone())
                    .build();

                let resp = client.get("https://example.com").send().await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::OK);
                assert!(auth_checker.checked.load(Ordering::Acquire));
            }
        }

        mod and_predicate_evaluates_to_ignore {
            use super::*;

            #[tokio::test]
            async fn middleware_does_not_attach_access_token() {
                let middleware = prepare_middleware()
                    .await
                    .with_predicate(predicate::never());
                let auth_checker = Arc::new(NoAuthChecker::default());

                let client = ClientBuilder::new(Client::default())
                    .with(middleware)
                    .with_arc(auth_checker.clone())
                    .build();

                let resp = client.get("https://example.com").send().await.unwrap();

                assert_eq!(resp.status(), http::StatusCode::OK);
                assert!(auth_checker.checked.load(Ordering::Acquire));
            }
        }
    }

    mod when_request_already_contains_an_authorization_header {
        use super::*;

        #[tokio::test]
        async fn middleware_does_not_attach_access_token() {
            const OVERRIDE_TOKEN: &str = "overridden!";
            // Reqwest uses a capital `B` bearer
            const BEARER_OVERRIDE_TOKEN: &str = "Bearer overridden!";

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

            assert_eq!(resp.status(), http::StatusCode::OK);
            assert!(auth_checker.checked.load(Ordering::Acquire));
        }
    }

    mod https_only_predicate {
        use super::*;

        #[test]
        fn matches_when_request_has_https_scheme() {
            let request =
                Request::new(reqwest::Method::GET, "https://example.com".parse().unwrap());
            let predicate = HttpsOnly;
            let result = dbg!(predicate.find_case(true, &request));
            assert!(result.is_none())
        }

        #[test]
        fn does_not_match_when_request_has_http_scheme() {
            let request = Request::new(reqwest::Method::GET, "http://example.com".parse().unwrap());
            let predicate = HttpsOnly;
            let result = dbg!(predicate.find_case(false, &request));
            assert!(result.is_none())
        }
    }

    mod exact_host_match_predicate {
        use super::*;

        #[test]
        fn matches_when_request_has_same_host() {
            let request =
                Request::new(reqwest::Method::GET, "https://example.com".parse().unwrap());
            let predicate = ExactHostMatch::new("example.com");
            let result = dbg!(predicate.find_case(true, &request));
            assert!(result.is_none())
        }

        #[test]
        fn does_not_match_when_request_has_different_host() {
            let request = Request::new(
                reqwest::Method::GET,
                "http://does-not-match.com".parse().unwrap(),
            );
            let predicate = ExactHostMatch::new("example.com");
            let result = dbg!(predicate.find_case(false, &request));
            assert!(result.is_none())
        }
    }
}
