//! # aliri_core
//!
//! Core types for the `aliri` family of crates.

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

pub mod base64;
pub mod clock;

/// A type representing one or more items, primarily for serialization
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single item
    One(T),

    /// Zero or more items, to be serialized/deserialized as an array
    Many(Vec<T>),
}
