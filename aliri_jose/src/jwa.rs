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
