//! HMAC JSON Web Algorithm implementations

use std::fmt;

use aliri_core::base64::Base64Url;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};

use crate::jws;

/// HMAC secret
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn new(secret: Base64Url) -> Self {
        Self { secret }
    }

    /// Generates a new HMAC secret
    #[cfg(feature = "private-keys")]
    pub fn generate(alg: SigningAlgorithm) -> anyhow::Result<Self> {
        Self::generate_with_rng(alg, &*super::CRATE_RNG)
    }

    /// Generates a new HMAC secret using the provided source of randomness
    #[cfg(feature = "private-keys")]
    pub fn generate_with_rng(
        alg: SigningAlgorithm,
        rng: &dyn SecureRandom,
    ) -> anyhow::Result<Self> {
        let bytes = alg.recommended_key_size();
        let mut secret = Base64Url::from_raw(vec![0; bytes]);

        rng.fill(secret.as_mut_slice())
            .map_err(|_| anyhow::anyhow!("unable to generate a random value"))?;

        Ok(Self { secret })
    }
}

/// HMAC signing algorithms
///
/// This list may be expanded in the future.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
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
    fn recommended_key_size(self) -> usize {
        match self {
            Self::HS256 => 256 / 8,
            Self::HS384 => 384 / 8,
            Self::HS512 => 512 / 8,
        }
    }

    /// The size in bytes of an HMAC signature
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

impl jws::Signer for Hmac {
    type Algorithm = SigningAlgorithm;
    type Error = std::convert::Infallible;

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = ring::hmac::Key::new(alg.into_ring_algorithm(), self.secret.as_slice());
        let digest = ring::hmac::sign(&key, data);
        Ok(digest.as_ref().to_owned())
    }
}

impl jws::Verifier for Hmac {
    type Algorithm = SigningAlgorithm;
    type Error = anyhow::Error;

    fn verify(
        &self,
        alg: Self::Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let key = ring::hmac::Key::new(alg.into_ring_algorithm(), self.secret.as_slice());
        ring::hmac::verify(&key, data, signature)
            .map_err(|_| anyhow::anyhow!("signature is not valid"))
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
