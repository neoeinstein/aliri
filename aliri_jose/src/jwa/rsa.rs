use std::fmt;

use serde::{Deserialize, Serialize};

use crate::jws;

#[cfg(feature = "private-keys")]
mod private;
mod public;

#[cfg(feature = "private-keys")]
pub use private::PrivateKeyParameters;
pub use public::PublicKeyParameters;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Rsa {
    #[cfg(feature = "private-keys")]
    PublicAndPrivate(PrivateKeyParameters),
    PublicOnly(PublicKeyParameters),
}

impl Rsa {
    #[cfg(feature = "private-keys")]
    pub fn generate() -> anyhow::Result<Self> {
        PrivateKeyParameters::generate().map(Rsa::PublicAndPrivate)
    }

    #[cfg(feature = "private-keys")]
    pub fn private_key_from_pem(pem: &str) -> anyhow::Result<Self> {
        PrivateKeyParameters::from_pem(pem).map(Self::PublicAndPrivate)
    }

    #[cfg(feature = "openssl")]
    pub fn public_key_from_pem(pem: &str) -> anyhow::Result<Self> {
        PublicKeyParameters::from_pem(pem).map(Self::PublicOnly)
    }

    #[cfg(feature = "private-keys")]
    fn private_params(&self) -> Option<&PrivateKeyParameters> {
        match self {
            Self::PublicAndPrivate(p) => Some(p),
            Self::PublicOnly(_) => None,
        }
    }

    fn public_params(&self) -> &PublicKeyParameters {
        match self {
            #[cfg(feature = "private-keys")]
            Self::PublicAndPrivate(p) => &p.public_key,
            Self::PublicOnly(p) => p,
        }
    }

    pub fn remove_private_key(self) -> Self {
        match self {
            #[cfg(feature = "private-keys")]
            Self::PublicAndPrivate(p) => Self::PublicOnly(p.public_key),
            Self::PublicOnly(p) => Self::PublicOnly(p),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum SigningAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
}

impl From<SigningAlgorithm> for &'_ ring::signature::RsaParameters {
    fn from(alg: SigningAlgorithm) -> Self {
        match alg {
            SigningAlgorithm::RS256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            SigningAlgorithm::RS384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
            SigningAlgorithm::RS512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
            SigningAlgorithm::PS256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
            SigningAlgorithm::PS384 => &ring::signature::RSA_PSS_2048_8192_SHA384,
            SigningAlgorithm::PS512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
        }
    }
}

impl From<SigningAlgorithm> for &'_ dyn ring::signature::RsaEncoding {
    fn from(alg: SigningAlgorithm) -> Self {
        match alg {
            SigningAlgorithm::RS256 => &ring::signature::RSA_PKCS1_SHA256,
            SigningAlgorithm::RS384 => &ring::signature::RSA_PKCS1_SHA384,
            SigningAlgorithm::RS512 => &ring::signature::RSA_PKCS1_SHA512,
            SigningAlgorithm::PS256 => &ring::signature::RSA_PSS_SHA256,
            SigningAlgorithm::PS384 => &ring::signature::RSA_PSS_SHA384,
            SigningAlgorithm::PS512 => &ring::signature::RSA_PSS_SHA512,
        }
    }
}

impl jws::Signer for Rsa {
    type Algorithm = SigningAlgorithm;
    type Error = anyhow::Error;

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        if let Some(p) = self.private_params() {
            let pk = ring::signature::RsaKeyPair::from_der(p.der())
                .map_err(|e| anyhow::anyhow!("key rejected: {}", e))?;

            let mut buf = vec![0; pk.public_modulus_len()];
            pk.sign(alg.into(), &*super::CRATE_RNG, data, &mut buf)
                .map_err(|_| anyhow::anyhow!("error while signing message"))?;
            Ok(buf)
        } else {
            Err(anyhow::anyhow!("no private components, unable to sign"))
        }
    }
}

impl jws::Verifier for Rsa {
    type Algorithm = SigningAlgorithm;
    type Error = anyhow::Error;

    fn verify(
        &self,
        alg: Self::Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let p = self.public_params();
        let pk = ring::signature::RsaPublicKeyComponents {
            n: p.modulus.as_slice(),
            e: p.exponent.as_slice(),
        };

        pk.verify(alg.into(), data, signature)
            .map_err(|_| anyhow::anyhow!("invalid signature"))
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
        };

        f.write_str(s)
    }
}
