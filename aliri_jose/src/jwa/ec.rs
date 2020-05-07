#[cfg(feature = "private-keys")]
use jsonwebtoken::EncodingKey;
use lazy_static::lazy_static;
use openssl::{
    ec::{EcGroup, EcGroupRef},
    nid::Nid,
};
use ring::signature::VerificationAlgorithm;
use serde::{Deserialize, Serialize};

use crate::jws;

#[cfg(feature = "private-keys")]
mod private;
mod public;

#[cfg(feature = "private-keys")]
pub use private::PrivateKeyParameters;
pub use public::PublicKeyParameters;

lazy_static! {
    static ref P256: EcGroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    static ref P384: EcGroup = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    static ref P521: EcGroup = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum Curve {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EllipticCurve {
    #[cfg(feature = "private-keys")]
    PublicAndPrivate(PrivateKeyParameters),
    PublicOnly(PublicKeyParameters),
}

impl EllipticCurve {
    #[cfg(feature = "private-keys")]
    pub fn generate(curve: Curve) -> anyhow::Result<Self> {
        PrivateKeyParameters::generate(curve).map(Self::PublicAndPrivate)
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

    #[cfg(feature = "private-keys")]
    pub(crate) fn signing_key(&self) -> Option<EncodingKey> {
        let pem = self.private_params()?.pem();

        println!("{}", pem);

        Some(EncodingKey::from_ec_pem(pem.as_bytes()).unwrap())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum SigningAlgorithm {
    ES256,
    ES384,
}

impl SigningAlgorithm {
    fn verification_algorithm(self) -> &'static ring::signature::EcdsaVerificationAlgorithm {
        match self {
            SigningAlgorithm::ES256 => &ring::signature::ECDSA_P256_SHA256_FIXED,
            SigningAlgorithm::ES384 => &ring::signature::ECDSA_P384_SHA384_FIXED,
        }
    }

    fn signing_algorithm(self) -> &'static ring::signature::EcdsaSigningAlgorithm {
        match self {
            SigningAlgorithm::ES256 => &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            SigningAlgorithm::ES384 => &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        }
    }
}

impl jws::Signer for EllipticCurve {
    type Algorithm = SigningAlgorithm;
    type Error = anyhow::Error;

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        if let Some(p) = self.private_params() {
            let pk = ring::signature::EcdsaKeyPair::from_pkcs8(
                alg.signing_algorithm(),
                p.pkcs8().as_slice(),
            )
            .map_err(|e| anyhow::anyhow!("key rejected: {}", e))?;

            let signature = pk
                .sign(&*super::CRATE_RNG, data)
                .map_err(|_| anyhow::anyhow!("error while signing message"))?;

            Ok(signature.as_ref().to_owned())
        } else {
            Err(anyhow::anyhow!("no private components, unable to sign"))
        }
    }
}

impl jws::Verifier for EllipticCurve {
    type Algorithm = SigningAlgorithm;
    type Error = anyhow::Error;

    fn verify(
        &self,
        alg: Self::Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let pk = self.public_params().uncompressed_point.as_slice();

        alg.verification_algorithm()
            .verify(pk.into(), data.into(), signature.into())
            .map_err(|_| anyhow::anyhow!("invalid signature"))
    }
}
