//! JWT authorization based on validating OAuth2 scopes
//!
//! This module uses the definition of OAuth2 as defined in
//! [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749).
//!
//! # Feature flags
//!
//! When using this crate and the `reqwest` feature to enable
//! automatic background refreshing of JWKS, this crate does
//! not automatically enable TLS support in `reqwest` itself.
//! If your application already uses `reqwest` with some TLS
//! settings (native/OpenSSL/rustls), then this crate will
//! use those settings automatically. However, if the only
//! reason you are using `reqwest` is transitively through
//! this crate, you may need to enable the `default-tls` or
//! `rustls-tls` feature to enable support for calling out to
//! an HTTPS endpoint.

#![cfg_attr(docsrs, feature(doc_cfg))]
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
    unsafe_code,
    unused_must_use
)]

mod authority;
pub mod scope;
mod policy;

pub use authority::{Authority, AuthorityError};
pub use scope::Scope;
pub use policy::{InsufficientScope, ScopePolicy};
