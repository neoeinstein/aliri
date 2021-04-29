//! # aliri_warp
//!
//! Warp filters for interacting with `aliri_traits` authorities

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

pub mod jwks;
pub mod jwt;
pub mod oauth2;

#[doc(hidden)]
pub use jwt::jwt;

#[doc(hidden)]
pub use jwks::jwks;
