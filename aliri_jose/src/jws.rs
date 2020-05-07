//! Implementations of the JSON Web Signature (JWS) standard
//!
//! The specifications for this standard can be found in [RFC7515][].
//!
//! [RFC7515]: https://tools.ietf.org/html/rfc7515

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::jwa;

/// JSON Web Signature signing algorithms
///
/// This list may be expanded in the future.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Algorithm {
    /// HMAC symmetric
    #[cfg(feature = "hmac")]
    Hmac(jwa::hmac::SigningAlgorithm),

    /// RSA public/private key pair
    #[cfg(feature = "rsa")]
    Rsa(jwa::rsa::SigningAlgorithm),

    /// Elliptic curve cryptography
    #[cfg(feature = "ec")]
    EllipticCurve(jwa::ec::SigningAlgorithm),

    #[doc(hidden)]
    Unknown,
}

#[cfg(feature = "hmac")]
impl Algorithm {
    /// The HS256 signing algorithm
    pub const HS256: Algorithm = Self::Hmac(jwa::hmac::SigningAlgorithm::HS256);
    /// The HS384 signing algorithm
    pub const HS384: Algorithm = Self::Hmac(jwa::hmac::SigningAlgorithm::HS384);
    /// The HS512 signing algorithm
    pub const HS512: Algorithm = Self::Hmac(jwa::hmac::SigningAlgorithm::HS512);
}

#[cfg(feature = "rsa")]
impl Algorithm {
    /// The RS256 signing algorithm
    pub const RS256: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::RS256);
    /// The RS384 signing algorithm
    pub const RS384: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::RS384);
    /// The RS512 signing algorithm
    pub const RS512: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::RS512);
    /// The PS256 signing algorithm
    pub const PS256: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::PS256);
    /// The PS384 signing algorithm
    pub const PS384: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::PS384);
    /// The PS512 signing algorithm
    pub const PS512: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::PS512);
}

#[cfg(feature = "ec")]
impl Algorithm {
    /// The ES256 signing algorithm
    pub const ES256: Algorithm = Self::EllipticCurve(jwa::ec::SigningAlgorithm::ES256);
    /// The ES384 signing algorithm
    pub const ES384: Algorithm = Self::EllipticCurve(jwa::ec::SigningAlgorithm::ES384);
}

impl Algorithm {
    /// The expected output size of the algorithm's signature in bytes
    pub fn signature_size(self) -> usize {
        match self {
            #[cfg(feature = "hmac")]
            Self::Hmac(alg) => alg.signature_size(),

            #[cfg(feature = "rsa")]
            Self::Rsa(alg) => alg.signature_size(),

            #[cfg(feature = "ec")]
            Self::EllipticCurve(alg) => alg.signature_size(),

            Self::Unknown => 0,
        }
    }
}

/// A JWS signer
pub trait Signer {
    /// The useable signature algorithms
    type Algorithm;

    /// The error returned on failure to sign
    type Error: fmt::Debug + fmt::Display + 'static;

    /// Attempts to sign the data provided using the specified algorithm
    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// A JWS verifier
pub trait Verifier {
    /// The verifiable signature algorithms
    type Algorithm;

    /// The error returned on a failure to verify
    type Error: fmt::Debug + fmt::Display + 'static;

    /// Attempts to verify the data against the signature using the
    /// specified algorithm
    fn verify(
        &self,
        alg: Self::Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error>;
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "hmac")]
            Self::Hmac(a) => fmt::Display::fmt(a, f),

            #[cfg(feature = "rsa")]
            Self::Rsa(a) => fmt::Display::fmt(a, f),

            #[cfg(feature = "ec")]
            Self::EllipticCurve(a) => fmt::Display::fmt(a, f),

            Self::Unknown => f.write_str("<unknown>"),
        }
    }
}
