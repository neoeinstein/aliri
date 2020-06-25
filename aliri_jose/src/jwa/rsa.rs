//! RSA JSON Web Algorithm implementations

use std::{convert::TryFrom, fmt};

use aliri_core::base64::Base64Url;
use serde::{Deserialize, Serialize};

use crate::error;
use crate::jws;

#[cfg(feature = "private-keys")]
mod private;
mod public;

#[cfg(feature = "private-keys")]
pub use private::PrivateKey;
pub use public::PublicKey;

/// RSA key
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Rsa {
    #[cfg(feature = "private-keys")]
    key: MaybePrivate,

    #[cfg(not(feature = "private-keys"))]
    key: PublicKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
enum MaybePrivate {
    #[cfg(feature = "private-keys")]
    PublicAndPrivate(PrivateKey),
    PublicOnly(PublicKey),
}

impl Rsa {
    /// Generates a newly minted RSA public/private key pair
    #[cfg(feature = "private-keys")]
    pub fn generate() -> Result<Self, error::Unexpected> {
        let private_key = PrivateKey::generate()?;

        Ok(Self {
            key: MaybePrivate::PublicAndPrivate(private_key),
        })
    }

    /// Constructs a private key from a PEM file
    #[cfg(feature = "private-keys")]
    pub fn private_key_from_pem(pem: &str) -> Result<Self, error::KeyRejected> {
        let private_key = PrivateKey::from_pem(pem)?;

        Ok(Self::from(private_key))
    }

    /// Constructs a public key from a PEM file
    #[cfg(feature = "openssl")]
    pub fn public_key_from_pem(pem: &str) -> Result<Self, error::KeyRejected> {
        let public_key = PublicKey::from_pem(pem)?;

        Ok(Self::from(public_key))
    }

    /// Constructs a public key from the modulus and exponent
    pub fn from_public_components(
        modulus: impl Into<Base64Url>,
        exponent: impl Into<Base64Url>,
    ) -> Result<Self, error::KeyRejected> {
        let public_key = PublicKey::from_components(modulus, exponent)?;

        Ok(Self::from(public_key))
    }

    #[cfg(feature = "private-keys")]
    pub(crate) fn private_key(&self) -> Option<&PrivateKey> {
        match &self.key {
            MaybePrivate::PublicAndPrivate(p) => Some(p),
            MaybePrivate::PublicOnly(_) => None,
        }
    }

    #[cfg(feature = "private-keys")]
    pub(crate) fn public_key(&self) -> &PublicKey {
        match &self.key {
            MaybePrivate::PublicAndPrivate(p) => p.public_key(),
            MaybePrivate::PublicOnly(p) => p,
        }
    }

    #[cfg(not(feature = "private-keys"))]
    fn public_key(&self) -> &PublicKey {
        &self.key
    }

    #[cfg(feature = "private-keys")]
    /// Removes the private key components, if any
    pub fn public_only(self) -> Self {
        match self.key {
            MaybePrivate::PublicAndPrivate(p) => Self::from(p.into_public_key()),
            _ => self,
        }
    }

    #[cfg(not(feature = "private-keys"))]
    /// Removes the private key components, if any
    pub fn public_only(self) -> Self {
        self
    }
}

/// RSA public/private key signing algorithms
///
/// This list may be expanded in the future.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum SigningAlgorithm {
    /// RSA using a 2048-bit key, producing a 8192-bit signature, using SHA-256 and PKCS 1.5
    RS256,
    /// RSA using a 2048-bit key, producing a 8192-bit signature, using SHA-384 and PKCS 1.5
    RS384,
    /// RSA using a 2048-bit key, producing a 8192-bit signature, using SHA-512 and PKCS 1.5
    RS512,
    /// RSA using a 2048-bit key, producing a 8192-bit signature, using SHA-256 and PSS
    PS256,
    /// RSA using a 2048-bit key, producing a 8192-bit signature, using SHA-256 and PSS
    PS384,
    /// RSA using a 2048-bit key, producing a 8192-bit signature, using SHA-256 and PSS
    PS512,
}

impl SigningAlgorithm {
    /// The size in bytes of RSA signatures
    pub const fn signature_size(self) -> usize {
        256
    }

    fn into_verification_params(self) -> &'static ring::signature::RsaParameters {
        match self {
            SigningAlgorithm::RS256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            SigningAlgorithm::RS384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
            SigningAlgorithm::RS512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
            SigningAlgorithm::PS256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
            SigningAlgorithm::PS384 => &ring::signature::RSA_PSS_2048_8192_SHA384,
            SigningAlgorithm::PS512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
        }
    }

    #[cfg(feature = "private-keys")]
    fn into_signing_params(self) -> &'static dyn ring::signature::RsaEncoding {
        match self {
            SigningAlgorithm::RS256 => &ring::signature::RSA_PKCS1_SHA256,
            SigningAlgorithm::RS384 => &ring::signature::RSA_PKCS1_SHA384,
            SigningAlgorithm::RS512 => &ring::signature::RSA_PKCS1_SHA512,
            SigningAlgorithm::PS256 => &ring::signature::RSA_PSS_SHA256,
            SigningAlgorithm::PS384 => &ring::signature::RSA_PSS_SHA384,
            SigningAlgorithm::PS512 => &ring::signature::RSA_PSS_SHA512,
        }
    }
}

impl From<SigningAlgorithm> for jws::Algorithm {
    fn from(alg: SigningAlgorithm) -> Self {
        Self::Rsa(alg)
    }
}

impl TryFrom<jws::Algorithm> for SigningAlgorithm {
    type Error = error::IncompatibleAlgorithm;

    fn try_from(alg: jws::Algorithm) -> Result<Self, Self::Error> {
        match alg {
            jws::Algorithm::Rsa(alg) => Ok(alg),

            #[allow(unreachable_patterns)]
            _ => Err(error::incompatible_algorithm(alg)),
        }
    }
}

impl jws::Verifier for Rsa {
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
        self.public_key().verify(alg, data, signature)
    }
}

#[cfg(feature = "private-keys")]
impl jws::Signer for Rsa {
    type Algorithm = SigningAlgorithm;
    type Error = error::SigningError;

    fn can_sign(&self, alg: Self::Algorithm) -> bool {
        if let Some(p) = self.private_key() {
            p.can_sign(alg)
        } else {
            false
        }
    }

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        if let Some(p) = self.private_key() {
            Ok(p.sign(alg, data)?)
        } else {
            Err(error::missing_private_key().into())
        }
    }
}

#[cfg(not(feature = "private-keys"))]
impl jws::Signer for Rsa {
    type Algorithm = SigningAlgorithm;
    type Error = error::SigningError;

    fn can_sign(&self, alg: Self::Algorithm) -> bool {
        false
    }

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Err(error::missing_private_key().into())
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

#[cfg(feature = "private-keys")]
impl From<PublicKey> for Rsa {
    fn from(key: PublicKey) -> Self {
        Self {
            key: MaybePrivate::PublicOnly(key),
        }
    }
}

#[cfg(not(feature = "private-keys"))]
impl From<PublicKey> for Rsa {
    fn from(key: PublicKey) -> Self {
        Self { key }
    }
}

#[cfg(feature = "private-keys")]
impl From<PrivateKey> for Rsa {
    fn from(key: PrivateKey) -> Self {
        Self {
            key: MaybePrivate::PublicAndPrivate(key),
        }
    }
}
