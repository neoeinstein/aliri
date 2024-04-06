//! This crate implements the Javascript/JSON Object Signing and Encryption (JOSE)
//! standards, including:
//!
//! * JSON Web Signature (JWS): [RFC7515][]
//! * JSON Web Key (JWK): [RFC7517][]
//! * JSON Web Algorithms (JWA): [RFC7518][]
//! * JSON Web Token (JWT): [RFC7519][]
//!
//! JSON Web Encryption (JWE), [RFC7516][], is not yet supported.
//!
//! [RFC7515]: https://tools.ietf.org/html/rfc7515
//! [RFC7516]: https://tools.ietf.org/html/rfc7516
//! [RFC7517]: https://tools.ietf.org/html/rfc7517
//! [RFC7518]: https://tools.ietf.org/html/rfc7518
//! [RFC7519]: https://tools.ietf.org/html/rfc7519
//!
//! # Example
//!
//! ```
//! use aliri_base64::Base64UrlRef;
//! use aliri::{jwa, jwk, jws, jwt, jwt::CoreHeaders, Jwk, JwtRef};
//! use regex::Regex;
//! use aliri::jwt::HasAlgorithm;
//!
//! let token = JwtRef::from_str(concat!(
//!     "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qga2V5In0.",
//!     "eyJzdWIiOiJBbGlyaSIsImF1ZCI6Im15X2FwaSIsImlzcyI6ImF1dGhvcml0eSJ9.",
//!     "yKDd4Ba3fdedqRKHrSUUMuF01-ctdXzEKM9oyWjSx9A"
//! ));
//!
//! let secret = Base64UrlRef::from_slice(b"test").to_owned();
//! let key = Jwk::from(jwa::Hmac::new(secret))
//!     .with_algorithm(jwa::Algorithm::HS256)
//!     .with_key_id(jwk::KeyId::from_static("test key"));
//!
//! let mut keys = aliri::Jwks::default();
//! keys.add_key(key);
//!
//! let validator = jwt::CoreValidator::default()
//!     .ignore_expiration()
//!     .add_approved_algorithm(jwa::Algorithm::HS256)
//!     .add_allowed_audience(jwt::Audience::from_static("my_api"))
//!     .require_issuer(jwt::Issuer::from_static("authority"))
//!     .check_subject(Regex::new("^Al.ri$").unwrap());
//!
//! let decomposed: jwt::Decomposed = token.decompose().unwrap();
//! let key_ref = keys.get_key_by_id(decomposed.kid().unwrap(), decomposed.alg()).unwrap();
//!
//! let data: jwt::Validated = token.verify(key_ref, &validator)
//!     .expect("JWT was invalid");
//! # let _ = data;
//! ```
//!
//! Inspect this token at [jwt.io][token] and verify with the shared secret `test`.
//!
//!   [token]: https://jwt.io/#debugger-io?token=eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qga2V5In0.eyJzdWIiOiJBbGlyaSIsImF1ZCI6Im15X2FwaSIsImlzcyI6ImF1dGhvcml0eSJ9.yKDd4Ba3fdedqRKHrSUUMuF01-ctdXzEKM9oyWjSx9A

#![cfg_attr(docsrs, feature(doc_cfg))]
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

pub mod error;
pub mod jwa;
pub mod jwk;
mod jwks;
pub mod jws;
pub mod jwt;

#[cfg(test)]
pub(crate) mod test;

#[doc(inline)]
pub use jwk::Jwk;
#[doc(inline)]
pub use jwks::Jwks;
#[doc(inline)]
pub use jwt::{Jwt, JwtRef};
