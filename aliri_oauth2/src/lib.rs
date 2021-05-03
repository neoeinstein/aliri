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
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_must_use
)]

mod authority;
pub mod jwt;
mod policy;
mod scope;

/// Indicates that the type has OAuth2 scopes
pub trait HasScopes {
    /// Scopes
    ///
    /// Scopes claimed by the underlying token, generally in the `scope`
    /// claim.
    fn scopes(&self) -> &Scopes;
}

pub use authority::{Authority, AuthorityError};
pub use policy::{InsufficientScopes, ScopesPolicy};
pub use scope::{Scope, ScopeRef, Scopes};
