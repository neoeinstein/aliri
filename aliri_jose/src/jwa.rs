//! Implementations of the JSON Web Algorithms (JWA) standard
//!
//! The specifications for these algorithms can be found in [RFC7518][].
//!
//! [RFC7518]: https://tools.ietf.org/html/rfc7518

#[cfg(feature = "ec")]
pub mod ec;
#[cfg(feature = "hmac")]
pub mod hmac;
#[cfg(feature = "rsa")]
pub mod rsa;

#[cfg(feature = "ec")]
pub use ec::EllipticCurve;
#[cfg(feature = "hmac")]
pub use hmac::Hmac;
#[cfg(feature = "rsa")]
pub use rsa::Rsa;

#[cfg(feature = "private-keys")]
lazy_static::lazy_static! {
    static ref CRATE_RNG: ring::rand::SystemRandom = ring::rand::SystemRandom::new();
}
