//! ECC JSON Web Algorithm implementations

use std::{convert::TryFrom, fmt};

use lazy_static::lazy_static;
use openssl::{
    ec::{EcGroup, EcGroupRef},
    nid::Nid,
};
use serde::{Deserialize, Serialize};

use crate::error;
use crate::jws;

#[cfg(feature = "private-keys")]
mod private;
mod public;

#[cfg(feature = "private-keys")]
pub use private::PrivateKey;
pub use public::PublicKey;

lazy_static! {
    static ref P256: EcGroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    static ref P384: EcGroup = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    static ref P521: EcGroup = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
}

/// A named ECC curve
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum Curve {
    /// The P-256 curve (prime256v1/secp256r1)
    #[serde(rename = "P-256")]
    P256,

    /// The P-384 curve (secp384r1)
    #[serde(rename = "P-384")]
    P384,

    /// The P-521 curve (secp521r1)
    #[serde(rename = "P-521")]
    P521,
}

impl Curve {
    fn to_group(self) -> &'static EcGroupRef {
        match self {
            Curve::P256 => &P256,
            Curve::P384 => &P384,
            Curve::P521 => &P521,
        }
    }

    #[cfg(feature = "private-keys")]
    fn from_group(group: &EcGroupRef) -> Option<Self> {
        let nid = group.curve_name()?;
        if nid == P256.curve_name().unwrap() {
            Some(Curve::P256)
        } else if nid == P384.curve_name().unwrap() {
            Some(Curve::P384)
        } else if nid == P521.curve_name().unwrap() {
            Some(Curve::P521)
        } else {
            None
        }
    }
}

/// Elliptic curve cryptography key
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EllipticCurve {
    #[cfg(feature = "private-keys")]
    key: MaybePrivate,

    #[cfg(not(feature = "private-keys"))]
    key: PublicKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg(feature = "private-keys")]
enum MaybePrivate {
    PublicAndPrivate(PrivateKey),
    PublicOnly(PublicKey),
}

impl EllipticCurve {
    /// Generates a newly minted key pair using the specified curve
    #[cfg(feature = "private-keys")]
    pub fn generate(curve: Curve) -> Result<Self, error::Unexpected> {
        let private_key = PrivateKey::generate(curve)?;

        Ok(Self::from(private_key))
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
    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.key
    }

    #[cfg(feature = "private-keys")]
    /// Removes the private key components
    pub fn public_only(self) -> Self {
        match self.key {
            MaybePrivate::PublicAndPrivate(p) => Self::from(p.into_public_key()),
            _ => self,
        }
    }

    #[cfg(not(feature = "private-keys"))]
    /// Removes the private key components
    pub fn public_only(self) -> Self {
        self
    }
}

/// Elliptic curve cryptography signing algorithms
///
/// This list may be expanded in the future.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum SigningAlgorithm {
    /// Elliptic curve cryptography using the P-256 curve and SHA-256
    ES256,
    /// Elliptic curve cryptography using the P-384 curve and SHA-384
    ES384,
    /// Elliptic curve cryptography using the P-521 curve and SHA-512
    ES512,
}

impl From<SigningAlgorithm> for jws::Algorithm {
    fn from(alg: SigningAlgorithm) -> Self {
        Self::EllipticCurve(alg)
    }
}

impl TryFrom<jws::Algorithm> for SigningAlgorithm {
    type Error = error::IncompatibleAlgorithm;

    fn try_from(alg: jws::Algorithm) -> Result<Self, Self::Error> {
        match alg {
            jws::Algorithm::EllipticCurve(alg) => Ok(alg),

            #[allow(unreachable_patterns)]
            _ => Err(error::incompatible_algorithm(alg)),
        }
    }
}

impl SigningAlgorithm {
    fn verification_algorithm(self) -> &'static ring::signature::EcdsaVerificationAlgorithm {
        match self {
            Self::ES256 => &ring::signature::ECDSA_P256_SHA256_FIXED,
            Self::ES384 => &ring::signature::ECDSA_P384_SHA384_FIXED,
            Self::ES512 => unimplemented!(),
        }
    }

    #[cfg(feature = "private-keys")]
    fn signing_algorithm(self) -> &'static ring::signature::EcdsaSigningAlgorithm {
        match self {
            Self::ES256 => &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            Self::ES384 => &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            Self::ES512 => unimplemented!(),
        }
    }

    /// Size in bytes of an ECDSA signature
    pub fn signature_size(self) -> usize {
        match self {
            Self::ES256 => 64,
            Self::ES384 => 96,
            Self::ES512 => 131,
        }
    }
}

impl From<SigningAlgorithm> for Curve {
    fn from(alg: SigningAlgorithm) -> Self {
        match alg {
            SigningAlgorithm::ES256 => Self::P256,
            SigningAlgorithm::ES384 => Self::P384,
            SigningAlgorithm::ES512 => Self::P521,
        }
    }
}

impl From<Curve> for SigningAlgorithm {
    fn from(crv: Curve) -> Self {
        match crv {
            Curve::P256 => Self::ES256,
            Curve::P384 => Self::ES384,
            Curve::P521 => Self::ES512,
        }
    }
}

impl jws::Verifier for EllipticCurve {
    type Algorithm = SigningAlgorithm;
    type Error = error::SignatureMismatch;

    fn can_verify(&self, alg: Self::Algorithm) -> bool {
        self.public_key().can_verify(alg)
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
impl jws::Signer for EllipticCurve {
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
impl jws::Signer for EllipticCurve {
    type Algorithm = SigningAlgorithm;
    type Error = error::SigningError;

    fn can_sign(&self, _alg: Self::Algorithm) -> bool {
        false
    }

    fn sign(&self, _alg: Self::Algorithm, _data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Err(error::missing_private_key().into())
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
        };

        f.write_str(s)
    }
}

#[cfg(feature = "private-keys")]
impl From<PublicKey> for EllipticCurve {
    fn from(key: PublicKey) -> Self {
        Self {
            key: MaybePrivate::PublicOnly(key),
        }
    }
}

#[cfg(not(feature = "private-keys"))]
impl From<PublicKey> for EllipticCurve {
    fn from(key: PublicKey) -> Self {
        Self { key }
    }
}

#[cfg(feature = "private-keys")]
impl From<PrivateKey> for EllipticCurve {
    fn from(key: PrivateKey) -> Self {
        Self {
            key: MaybePrivate::PublicAndPrivate(key),
        }
    }
}
