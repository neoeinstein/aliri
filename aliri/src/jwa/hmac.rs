//! HMAC JSON Web Algorithm implementations

use std::{convert::TryFrom, fmt};

use aliri_base64::{Base64Url, Base64UrlRef};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};

use crate::{error, jws};

/// HMAC secret
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
pub struct Hmac {
    #[serde(rename = "k")]
    secret: Base64Url,
}

impl fmt::Debug for Hmac {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Hmac { secret }")
    }
}

impl Hmac {
    /// HMAC using the provided secret
    pub fn new(secret: impl Into<Base64Url>) -> Self {
        let secret = secret.into();
        Self { secret }
    }

    /// Generates a new HMAC secret
    ///
    /// # Errors
    ///
    /// Unable to generate a new HMAC secret.
    pub fn generate(alg: SigningAlgorithm) -> Result<Self, error::Unexpected> {
        Self::generate_with_rng(alg, &ring::rand::SystemRandom::new())
    }

    /// Generates a new HMAC secret using the provided source of randomness
    ///
    /// # Errors
    ///
    /// Unable to generate a new HMAC secret from the provided RNG.
    pub fn generate_with_rng(
        alg: SigningAlgorithm,
        rng: &dyn SecureRandom,
    ) -> Result<Self, error::Unexpected> {
        let bytes = alg.recommended_key_size();
        let mut secret = Base64Url::from_raw(vec![0; bytes]);

        rng.fill(secret.as_mut_slice())
            .map_err(|_| error::unexpected("random number generator failure"))?;

        Ok(Self { secret })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn secret(&self) -> &Base64UrlRef {
        &self.secret
    }
}

/// HMAC signing algorithms
///
/// This list may be expanded in the future.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[allow(clippy::upper_case_acronyms)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
}

impl SigningAlgorithm {
    /// Recommended key size in bytes for an HMAC secret
    #[must_use]
    fn recommended_key_size(self) -> usize {
        match self {
            Self::HS256 => 256 / 8,
            Self::HS384 => 384 / 8,
            Self::HS512 => 512 / 8,
        }
    }

    /// The size in bytes of an HMAC signature
    #[must_use]
    pub fn signature_size(self) -> usize {
        match self {
            Self::HS256 => 256 / 8,
            Self::HS384 => 384 / 8,
            Self::HS512 => 512 / 8,
        }
    }

    fn into_ring_algorithm(self) -> ring::hmac::Algorithm {
        match self {
            SigningAlgorithm::HS256 => ring::hmac::HMAC_SHA256,
            SigningAlgorithm::HS384 => ring::hmac::HMAC_SHA384,
            SigningAlgorithm::HS512 => ring::hmac::HMAC_SHA512,
        }
    }
}

impl From<SigningAlgorithm> for jws::Algorithm {
    fn from(alg: SigningAlgorithm) -> Self {
        Self::Hmac(alg)
    }
}

impl TryFrom<jws::Algorithm> for SigningAlgorithm {
    type Error = error::IncompatibleAlgorithm;

    fn try_from(alg: jws::Algorithm) -> Result<Self, Self::Error> {
        match alg {
            jws::Algorithm::Hmac(alg) => Ok(alg),

            #[allow(unreachable_patterns)]
            _ => Err(error::incompatible_algorithm(alg)),
        }
    }
}

impl jws::Signer for Hmac {
    type Algorithm = SigningAlgorithm;
    type Error = std::convert::Infallible;

    fn can_sign(&self, _alg: Self::Algorithm) -> bool {
        true
    }

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = ring::hmac::Key::new(alg.into_ring_algorithm(), self.secret.as_slice());
        let digest = ring::hmac::sign(&key, data);
        Ok(digest.as_ref().to_owned())
    }
}

impl jws::Verifier for Hmac {
    type Algorithm = SigningAlgorithm;
    type Error = error::SignatureMismatch;

    fn can_verify(&self, _alg: Self::Algorithm) -> bool {
        true
    }

    fn verify(
        &self,
        alg: Self::Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let key = ring::hmac::Key::new(alg.into_ring_algorithm(), self.secret.as_slice());
        ring::hmac::verify(&key, data, signature).map_err(|_| error::signature_mismatch())
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
        };

        f.write_str(s)
    }
}
