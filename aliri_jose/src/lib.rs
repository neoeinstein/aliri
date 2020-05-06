#![deny(unsafe_code)]

pub mod jwa;
pub mod jwk;
pub mod jwks;

mod types;
mod verify;

#[cfg(test)]
pub(crate) mod test_util;

pub use jwk::Jwk;
pub use jwks::Jwks;
pub use types::*;
pub use verify::{BasicValidation, CoreClaims, EmptyClaims};

use static_assertions::assert_cfg;

assert_cfg!(
    any(feature = "rsa", feature = "hmac", feature = "ec"),
    "At least one of `rsa`, `hmac`, or `ec` must be enabled for this crate to be of any use."
);
