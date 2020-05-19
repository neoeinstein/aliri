//! # aliri_jose
//!
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

pub(crate) mod test;

#[doc(inline)]
pub use jwk::Jwk;

#[doc(inline)]
pub use jwks::Jwks;

#[doc(inline)]
pub use jwt::{Jwt, JwtRef};

#[cfg(not(any(feature = "rsa", feature = "hmac", feature = "ec")))]
compiler_error!(
    "At least one of `rsa`, `hmac`, or `ec` must be enabled for this crate to be of any use."
);
