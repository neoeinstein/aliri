//! Authorizers for working with `tower_http` and other constructs in the
//! ecosystem, including `axum`.
//!
//! See the `examples` folder in the repository for a working example using
//! an `tonic` web server. For a more ergonomic experience in `axum`,
//! see the [`aliri_axum`](https://docs.rs/aliri_axum) crate.
//!
//! ```
//! # use axum::extract::Path;
//! use axum::handler::Handler;
//! # use axum::routing::{get, post};
//! # use aliri::{jwa, jwk, jwt, Jwk, Jwks};
//! # use aliri_base64::Base64UrlRef;
//! # use aliri_clock::UnixTime;
//! use aliri_oauth2::{scope, policy, ScopePolicy};
//! use aliri_tower::Oauth2Authorizer;
//!
//! # #[derive(Clone, Debug, serde::Deserialize)]
//! pub struct CustomClaims {
//!     // …
//! #     iss: aliri::jwt::Issuer,
//! #     aud: aliri::jwt::Audiences,
//! #     sub: aliri::jwt::Subject,
//! #     scope: aliri_oauth2::scope::Scope,
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
//! # impl aliri_oauth2::HasScope for CustomClaims {
//! #     fn scope(&self) -> &aliri_oauth2::scope::Scope { &self.scope }
//! # }
//! #
//! # fn construct_authority() -> aliri_oauth2::Authority {
//! #     // This authority might otherwise come from a well-known JWKS endpoint
//! #     let secret = Base64UrlRef::from_slice(b"test").to_owned();
//! #     let key = Jwk::from(jwa::Hmac::new(secret))
//! #         .with_algorithm(jwa::Algorithm::HS256)
//! #         .with_key_id(jwk::KeyId::from_static("test key"));
//! #
//! #     let mut jwks = Jwks::default();
//! #     jwks.add_key(key);
//! #
//! #     let validator = jwt::CoreValidator::default()
//! #         .ignore_expiration() // Only for demonstration purposes
//! #         .add_approved_algorithm(jwa::Algorithm::HS256)
//! #         .add_allowed_audience(jwt::Audience::from_static("my_api"))
//! #         .require_issuer(jwt::Issuer::from_static("authority"));
//! #
//! #     aliri_oauth2::Authority::new(jwks, validator)
//! # }
//! #
//! let authority = construct_authority();
//! let authorizer = Oauth2Authorizer::new()
//!     .with_claims::<CustomClaims>()
//!     .with_terse_error_handler();
//!
//! let app = axum::Router::new()
//!     .route(
//!         "/users",
//!         post(handle_post
//!             .layer(authorizer.scope_layer(policy![scope!["post_user"]]))),
//!     )
//!     .route(
//!         "/users/:id",
//!         get(handle_get
//!             .layer(authorizer.scope_layer(ScopePolicy::allow_one_from_static("get_user")))),
//!     )
//!     .layer(authorizer.jwt_layer(authority));
//! #
//! # async fn handle_post() {}
//! #
//! # async fn handle_get(Path(id): Path<u64>) {}
//! #
//! # async {
//! # axum::serve(tokio::net::TcpListener::bind("").await.unwrap(), app).await.unwrap();
//! # };
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

use std::{fmt, marker::PhantomData};

mod authorizer;
mod jwt;
mod oauth2;
pub mod util;

pub use crate::{authorizer::Oauth2Authorizer, jwt::OnJwtError, oauth2::OnScopeError};

/// Terse responders for authentication and authorization failures
///
/// This handler will generate a default error response containing the
/// relevant status code and `www-authenticate` header with an empty body.
///
/// This type _does not_ provide `error_description` data to avoid leaking
/// internal error information, but does provide `scope` information in
/// when an otherwise valid token lacks sufficient permissions.
pub struct TerseErrorHandler<ResBody> {
    _ty: PhantomData<fn() -> ResBody>,
}

impl<ResBody> TerseErrorHandler<ResBody> {
    /// Instantiates a new instance over a given body type
    #[inline]
    pub fn new() -> Self {
        Self { _ty: PhantomData }
    }
}

impl<ResBody> fmt::Debug for TerseErrorHandler<ResBody> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("TerseErrorHandler")
    }
}

impl<ResBody> Default for TerseErrorHandler<ResBody> {
    #[inline]
    fn default() -> Self {
        Self { _ty: PhantomData }
    }
}

impl<ResBody> Clone for TerseErrorHandler<ResBody> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<ResBody> Copy for TerseErrorHandler<ResBody> {}

/// Verbose responders for authentication and authorization failures
///
/// This handler will generate a default error response containing the
/// relevant status code and `www-authenticate` header with an empty body.
///
/// This type provides `error_description` data in the `www-authenticate`
/// header.
pub struct VerboseErrorHandler<ResBody> {
    _ty: PhantomData<fn() -> ResBody>,
}

impl<ResBody> VerboseErrorHandler<ResBody> {
    /// Instantiates a new instance over a given body type
    #[inline]
    pub fn new() -> Self {
        Self { _ty: PhantomData }
    }
}

impl<ResBody> fmt::Debug for VerboseErrorHandler<ResBody> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("VerboseErrorHandler")
    }
}

impl<ResBody> Default for VerboseErrorHandler<ResBody> {
    #[inline]
    fn default() -> Self {
        Self { _ty: PhantomData }
    }
}

impl<ResBody> Clone for VerboseErrorHandler<ResBody> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<ResBody> Copy for VerboseErrorHandler<ResBody> {}

/// ```
/// use aliri_tower::VerboseErrorHandler;
/// fn is_send_sync<T: Send + Sync>(_: T) {}
/// fn verbose_error_handler_is_send_sync<B>(v: VerboseErrorHandler<B>) {
///     is_send_sync(v)
/// }
/// ```
#[cfg(doctest)]
fn verbose_error_handler_is_send_sync() {}

/// ```
/// use aliri_tower::TerseErrorHandler;
/// fn is_send_sync<T: Send + Sync>(_: T) {}
/// fn terse_error_handler_is_send_sync<B>(v: TerseErrorHandler<B>) {
///     is_send_sync(v)
/// }
/// ```
#[cfg(doctest)]
fn terse_error_handler_is_send_sync() {}
