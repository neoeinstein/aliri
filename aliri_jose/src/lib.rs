#![deny(unsafe_code)]

pub mod jwa;
pub mod jwk;
pub mod jwks;
pub mod jws;
pub mod jwt;

pub(crate) mod test;

pub use jwk::Jwk;
pub use jwks::Jwks;
pub use jwt::{Jwt, JwtRef};

#[cfg(not(any(feature = "rsa", feature = "hmac", feature = "ec")))]
compiler_error!("At least one of `rsa`, `hmac`, or `ec` must be enabled for this crate to be of any use.");
