#![deny(unsafe_code)]

mod b64;
pub mod clock;
//mod maybe;

pub use b64::{Base64Url, Base64UrlRef};
// pub use maybe::MaybeUnsupported;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}
