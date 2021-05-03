//! # aliri_actix
//!
//! Actix utilities for interacting with `aliri` authorities
//!
//! ## Usage
//!
//! In order to attach the validator to Actix, you will first need to
//!
//! ## Example
//!
//! ```
//! use aliri::{jwa, jwk, jwt, jwt::CoreClaims as _, Jwk, Jwks};
//! use aliri_actix::scope_policy;
//! use aliri_base64::Base64UrlRef;
//! use aliri_clock::UnixTime;
//! use aliri_oauth2::{HasScopes, Authority, Scopes};
//! use actix_web::{get, web, http::{header, StatusCode}, test, App, HttpResponse, Responder};
//! use futures::executor::block_on;
//! use serde::Deserialize;
//!
//! #[derive(Clone, Debug, Deserialize)]
//! pub struct CustomClaims {
//!     iss: jwt::Issuer,
//!     aud: jwt::Audiences,
//!     sub: jwt::Subject,
//!     #[serde(rename = "scope")]
//!     scopes: Scopes,
//! }
//!
//! impl jwt::CoreClaims for CustomClaims {
//!     fn nbf(&self) -> Option<UnixTime> { None }
//!     fn exp(&self) -> Option<UnixTime> { None }
//!     fn aud(&self) -> &jwt::Audiences { &self.aud }
//!     fn iss(&self) -> Option<&jwt::IssuerRef> { Some(&self.iss) }
//!     fn sub(&self) -> Option<&jwt::SubjectRef> { Some(&self.sub) }
//! }
//!
//! impl HasScopes for CustomClaims {
//!     fn scopes(&self) -> &Scopes { &self.scopes }
//! }
//!
//! // Define our initial scope
//! scope_policy!(AdminOnly / AdminOnlyScope (CustomClaims); "admin");
//!
//! // Define an endpoint that will require this scope
//! #[get("/test")]
//! async fn test_endpoint(token: AdminOnly) -> impl Responder {
//!     println!("Token subject: {}", token.claims().sub);
//!     HttpResponse::Ok()
//! }
//!
//! fn construct_authority() -> Authority {
//!     // This authority might otherwise come from a well-known JWKS endpoint
//!     let secret = Base64UrlRef::from_slice(b"test").to_owned();
//!     let key = Jwk::from(jwa::Hmac::new(secret))
//!         .with_algorithm(jwa::Algorithm::HS256)
//!         .with_key_id(jwk::KeyId::new("test key"));
//!
//!     let mut jwks = Jwks::default();
//!     jwks.add_key(key);
//!
//!     let validator = jwt::CoreValidator::default()
//!         .ignore_expiration() // Only for demonstration purposes
//!         .add_approved_algorithm(jwa::Algorithm::HS256)
//!         .add_allowed_audience(jwt::Audience::new("my_api"))
//!         .require_issuer(jwt::Issuer::new("authority"));
//!
//!     Authority::new(jwks, validator)
//! }
//!
//! // Construct our authority
//! let authority = construct_authority();
//!
//! # actix_rt::Runtime::new().unwrap().block_on(async move {
//! // Construct the server, providing the authority as `app_data`
//! let mut app = test::init_service(
//!     App::new()
//!         .app_data(authority.clone())
//!         .service(test_endpoint)
//! ).await;
//!
//! // Use a good token
//!
//! let token = concat!(
//!     "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qga2V5In0.",
//!     "eyJzdWIiOiJBbGlyaSIsImF1ZCI6Im15X2FwaSIsImlzcyI6ImF1dGhvcml0eSIsInNjb3BlIjoiYWRtaW4ifQ.",
//!     "Bql6D5kZiqQaW77M8J19jE8TuE3U51MiHjRBU_8NeeQ",
//! );
//!
//! let req = test::TestRequest::with_uri("/test")
//!     .header(header::AUTHORIZATION, format!("Bearer {}", token))
//!     .to_request();
//!
//! let mut resp = test::call_service(&mut app, req).await;
//! assert_eq!(resp.status(), StatusCode::OK);
//!
//! // Use a bad token
//!
//! let bad_token = concat!(
//!     "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qga2V5In0.",
//!     "eyJzdWIiOiJBbGlyaSIsImF1ZCI6Im15X2FwaSIsImlzcyI6ImF1dGhvcml0eSIsInNjb3BlIjoidXNlciJ9.",
//!     "n7SKlWcaNj6KP-e6pQdFFubbkqjEwEHzmoL2PVoxm2I",
//! );
//!
//! let req = test::TestRequest::with_uri("/test")
//!     .header(header::AUTHORIZATION, format!("Bearer {}", bad_token))
//!     .to_request();
//!
//! let mut resp = test::call_service(&mut app, req).await;
//! assert_eq!(resp.status(), StatusCode::FORBIDDEN);
//!
//! // Use a malformed token
//!
//! let req = test::TestRequest::with_uri("/test")
//!     .header(header::AUTHORIZATION, "Bearer totally-not-a-jwt")
//!     .to_request();
//!
//! let mut resp = test::call_service(&mut app, req).await;
//! assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
//! # })
//! ```

#![warn(
    missing_docs,
    unused_import_braces,
    unused_imports,
    unused_qualifications
)]
#![deny(
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_must_use
)]
#![forbid(unsafe_code)]

pub mod jwt;
mod macros;
