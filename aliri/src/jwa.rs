//! Implementations of the JSON Web Algorithms (JWA) standard
//!
//! The specifications for these algorithms can be found in [RFC7518][].
//!
//! [RFC7518]: https://tools.ietf.org/html/rfc7518

#[cfg(feature = "ec")]
#[cfg_attr(docsrs, doc(cfg(feature = "ec")))]
pub mod ec;
#[cfg(feature = "hmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "hmac")))]
pub mod hmac;
#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
pub mod rsa;

#[cfg(feature = "ec")]
#[cfg_attr(docsrs, doc(cfg(feature = "ec")))]
#[doc(inline)]
pub use ec::EllipticCurve;
#[cfg(feature = "hmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "hmac")))]
#[doc(inline)]
pub use hmac::Hmac;
#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
#[doc(inline)]
pub use rsa::Rsa;

mod algorithm;
mod usage;

pub use algorithm::Algorithm;
pub use usage::Usage;
