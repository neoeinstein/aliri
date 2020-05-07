use std::fmt;

use serde::{Deserialize, Serialize};

use crate::jwa;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Algorithm {
    #[cfg(feature = "hmac")]
    Hmac(jwa::hmac::SigningAlgorithm),

    #[cfg(feature = "rsa")]
    Rsa(jwa::rsa::SigningAlgorithm),

    #[cfg(feature = "ec")]
    EllipticCurve(jwa::ec::SigningAlgorithm),

    #[doc(hidden)]
    Unknown,
}

#[cfg(feature = "hmac")]
impl Algorithm {
    pub const HS256: Algorithm = Self::Hmac(jwa::hmac::SigningAlgorithm::HS256);
    pub const HS384: Algorithm = Self::Hmac(jwa::hmac::SigningAlgorithm::HS384);
    pub const HS512: Algorithm = Self::Hmac(jwa::hmac::SigningAlgorithm::HS512);
}

#[cfg(feature = "rsa")]
impl Algorithm {
    pub const RS256: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::RS256);
    pub const RS384: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::RS384);
    pub const RS512: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::RS512);
    pub const PS256: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::PS256);
    pub const PS384: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::PS384);
    pub const PS512: Algorithm = Self::Rsa(jwa::rsa::SigningAlgorithm::PS512);
}

#[cfg(feature = "ec")]
impl Algorithm {
    pub const ES256: Algorithm = Self::EllipticCurve(jwa::ec::SigningAlgorithm::ES256);
    pub const ES384: Algorithm = Self::EllipticCurve(jwa::ec::SigningAlgorithm::ES384);
}

pub trait Signer {
    type Algorithm;
    type Error: fmt::Debug + fmt::Display + 'static;

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub trait Verifier {
    type Algorithm;
    type Error: fmt::Debug + fmt::Display + 'static;

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
