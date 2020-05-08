//! # aliri_oauth2
//!
//! Token-based authorization library based on validating OAuth2 scopes.

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

mod authority;
mod directive;
mod scope;

pub use authority::JwksAuthority;
pub use directive::Directive;
pub use scope::{HasScopes, Scope, ScopeRef};
