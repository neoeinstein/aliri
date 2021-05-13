//! JWT authorization based on validating OAuth2 scopes
//!
//! This module uses the definition of OAuth2 as defined in
//! [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749).

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
pub mod oauth2;
mod policy;

pub use authority::{Authority, AuthorityError};
pub use oauth2::Scope;
pub use policy::{InsufficientScope, ScopePolicy};
