//! Token-based authorization with authorities that verify access grants.

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
    unused_must_use
)]
#![forbid(unsafe_code)]

mod authority;
mod policy;

pub use authority::Authority;
pub use policy::Policy;
