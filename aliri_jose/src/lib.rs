#![deny(unsafe_code)]

pub mod jwa;
pub mod jwk;
pub mod jwks;
pub mod jws;
pub mod jwt;

pub mod test;

pub use jwk::Jwk;
pub use jwks::Jwks;
pub use jwt::{Jwt, JwtRef};

use static_assertions::assert_cfg;

assert_cfg!(
    any(feature = "rsa", feature = "hmac", feature = "ec"),
    "At least one of `rsa`, `hmac`, or `ec` must be enabled for this crate to be of any use."
);
