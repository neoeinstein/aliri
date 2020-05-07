use std::fmt;

use aliri_core::Base64Url;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};

use crate::jws;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hmac {
    #[serde(rename = "k")]
    key: Base64Url,
}

impl Hmac {
    #[cfg(feature = "private-keys")]
    pub fn generate(alg: SigningAlgorithm) -> anyhow::Result<Self> {
        Self::generate_with_rng(alg, &*super::CRATE_RNG)
    }

    #[cfg(feature = "private-keys")]
    pub fn generate_with_rng(
        alg: SigningAlgorithm,
        rng: &dyn SecureRandom,
    ) -> anyhow::Result<Self> {
        let bytes = alg.recommended_key_size();
        let mut key = Base64Url::from(vec![0; bytes]);

        rng.fill(key.as_mut_slice())
            .map_err(|_| anyhow::anyhow!("unable to generate a random value"))?;

        Ok(Self { key })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum SigningAlgorithm {
    HS256,
    HS384,
    HS512,
}

impl SigningAlgorithm {
    fn recommended_key_size(self) -> usize {
        match self {
            Self::HS256 => 256 / 8,
            Self::HS384 => 384 / 8,
            Self::HS512 => 512 / 8,
        }
    }

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
        let key = ring::hmac::Key::new(alg.into_ring_algorithm(), self.key.as_slice());
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
        let key = ring::hmac::Key::new(alg.into_ring_algorithm(), self.key.as_slice());
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
