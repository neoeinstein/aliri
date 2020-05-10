//! # aliri_oauth2
//!
//! JWT authorization based on validating OAuth2 scopes.

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

pub mod jwks;
mod policy;
mod scope;

pub use policy::ScopesPolicy;
pub use scope::{HasScopes, Scope, ScopeRef, Scopes};
