//! Authorizers for working with `tower_http` and other constructs in the
//! ecosystem, including `axum`.
//!
//! See the `examples` folder in the repository for a working example using
//! an `axum` web server.
//!
//! ```
//! # use axum::extract::Path;
//! # use axum::routing::{get, post};
//! use tower_http::auth::RequireAuthorizationLayer;
//! # use aliri::{jwa, jwk, jwt, Jwk, Jwks};
//! # use aliri_base64::Base64UrlRef;
//! # use aliri_clock::UnixTime;
//! use aliri_oauth2::{Scope, ScopePolicy};
//! use aliri_tower::{DefaultErrorHandler, VerifyJwt, VerifyScopes};
//!
//! # #[derive(Clone, Debug, serde::Deserialize)]
//! pub struct CustomClaims {
//!     // …
//! #     iss: aliri::jwt::Issuer,
//! #     aud: aliri::jwt::Audiences,
//! #     sub: aliri::jwt::Subject,
//! #     scope: aliri_oauth2::oauth2::Scope,
//! }
//!
//! impl jwt::CoreClaims for CustomClaims {
//!     // …
//! #     fn nbf(&self) -> Option<UnixTime> { None }
//! #     fn exp(&self) -> Option<UnixTime> { None }
//! #     fn aud(&self) -> &aliri::jwt::Audiences { &self.aud }
//! #     fn iss(&self) -> Option<&aliri::jwt::IssuerRef> { Some(&self.iss) }
//! #     fn sub(&self) -> Option<&aliri::jwt::SubjectRef> { Some(&self.sub) }
//! }
//!
//! # impl aliri_oauth2::oauth2::HasScope for CustomClaims {
//! #     fn scope(&self) -> &aliri_oauth2::oauth2::Scope { &self.scope }
//! # }
//! #
//! # fn construct_authority() -> aliri_oauth2::Authority {
//! #     // This authority might otherwise come from a well-known JWKS endpoint
//! #     let secret = Base64UrlRef::from_slice(b"test").to_owned();
//! #     let key = Jwk::from(jwa::Hmac::new(secret))
//! #         .with_algorithm(jwa::Algorithm::HS256)
//! #         .with_key_id(jwk::KeyId::new("test key"));
//! #
//! #     let mut jwks = Jwks::default();
//! #     jwks.add_key(key);
//! #
//! #     let validator = jwt::CoreValidator::default()
//! #         .ignore_expiration() // Only for demonstration purposes
//! #         .add_approved_algorithm(jwa::Algorithm::HS256)
//! #         .add_allowed_audience(jwt::Audience::new("my_api"))
//! #         .require_issuer(jwt::Issuer::new("authority"));
//! #
//! #     aliri_oauth2::Authority::new(jwks, validator)
//! # }
//!
//! let authority = construct_authority();
//!
//! let verify_jwt = VerifyJwt::<CustomClaims>::new(authority)
//!     .with_error_handler(DefaultErrorHandler::<_>::new());
//!
//! let require_scope = |scope: Scope| {
//!     let verify_scope = verify_jwt.scopes_verifier(ScopePolicy::allow_one(scope))
//!         .with_error_handler(DefaultErrorHandler::<_>::new());
//!     RequireAuthorizationLayer::custom(verify_scope)
//! };
//!
//! let check_jwt = RequireAuthorizationLayer::custom(verify_jwt.clone());
//!
//! let app = axum::Router::new()
//!     .route(
//!         "/users",
//!         post(handle_post)
//!             .layer(require_scope("post_user".parse().unwrap())),
//!     )
//!     .route(
//!         "/users/:id",
//!         get(handle_get)
//!             .layer(require_scope("get_user".parse().unwrap())),
//!     )
//!     .layer(&check_jwt);
//! #
//! # async fn handle_post() {}
//! #
//! # async fn handle_get(Path(id): Path<u64>) {}
//! #
//! # async {
//! # axum::Server::bind(&"".parse().unwrap()).serve(app.into_make_service()).await.unwrap();
//! # };
//! ```

use std::fmt;
use std::marker::PhantomData;

mod jwt;
mod oauth2;

pub use crate::jwt::*;
pub use crate::oauth2::*;

/// Default responders for authentication and authorization failures
pub struct DefaultErrorHandler<ResBody = http_body::Empty<bytes::Bytes>> {
    _ty: PhantomData<fn() -> ResBody>,
}

impl<ResBody> DefaultErrorHandler<ResBody> {
    /// Instantiates a new instance over a given body type
    #[inline]
    pub fn new() -> Self {
        Self { _ty: PhantomData }
    }
}

impl<ResBody> fmt::Debug for DefaultErrorHandler<ResBody> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("DefaultErrorHandler")
    }
}

impl<ResBody> Default for DefaultErrorHandler<ResBody> {
    #[inline]
    fn default() -> Self {
        Self { _ty: PhantomData }
    }
}

impl<ResBody> Clone for DefaultErrorHandler<ResBody> {
    #[inline]
    fn clone(&self) -> Self {
        Self { _ty: PhantomData }
    }
}

impl<ResBody> Copy for DefaultErrorHandler<ResBody> {}
