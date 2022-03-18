use std::convert::TryFrom;

use aliri_base64::{Base64Url, Base64UrlRef};
#[cfg(feature = "openssl")]
use openssl::{bn::BigNum, rsa::Rsa};
use serde::{Deserialize, Serialize};

use super::SigningAlgorithm;
use crate::{error, jws};

/// RSA public key components
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "PublicKeyDto")]
pub struct PublicKey {
    /// The public modulus
    #[serde(rename = "n")]
    modulus: Base64Url,

    /// The public exponent
    #[serde(rename = "e")]
    exponent: Base64Url,
}

impl PublicKey {
    /// The public key's modulus
    pub fn modulus(&self) -> &Base64UrlRef {
        &self.modulus
    }

    /// The public key's exponent
    pub fn exponent(&self) -> &Base64UrlRef {
        &self.exponent
    }

    /// Imports an RSA public key from a PEM file
    #[cfg(feature = "openssl")]
    #[cfg_attr(docsrs, doc(cfg(feature = "openssl")))]
    pub fn from_pem(pem: &str) -> Result<Self, error::KeyRejected> {
        let rsa = Rsa::public_key_from_pem(pem.as_bytes()).map_err(error::key_rejected)?;
        Ok(PublicKey {
            modulus: Base64Url::from_raw(rsa.n().to_vec()),
            exponent: Base64Url::from_raw(rsa.e().to_vec()),
        })
    }

    /// Exports an RSA public key to a PEM file
    #[cfg(feature = "openssl")]
    #[cfg_attr(docsrs, doc(cfg(feature = "openssl")))]
    pub fn to_pem(&self) -> Result<String, error::Unexpected> {
        let modulus = BigNum::from_slice(self.modulus.as_slice()).map_err(error::unexpected)?;
        let exponent = BigNum::from_slice(self.exponent.as_slice()).map_err(error::unexpected)?;

        let key = Rsa::from_public_components(modulus, exponent).map_err(error::unexpected)?;
        let pem = key.public_key_to_pem().map_err(error::unexpected)?;
        String::from_utf8(pem).map_err(error::unexpected)
    }

    /// Constructs a public key from the modulus and exponent
    pub fn from_components(
        modulus: impl Into<Base64Url>,
        exponent: impl Into<Base64Url>,
    ) -> Result<Self, error::KeyRejected> {
        let modulus = modulus.into();
        let exponent = exponent.into();
        if modulus.as_slice().len() != 256 {
            return Err(error::key_rejected("key modulus must be 2048 bits"));
        }

        // TODO: Better early validation of the public key component

        Ok(Self { modulus, exponent })
    }
}

impl jws::Verifier for PublicKey {
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
        let pk = ring::signature::RsaPublicKeyComponents {
            n: self.modulus.as_slice(),
            e: self.exponent.as_slice(),
        };

        pk.verify(alg.into_verification_params(), data, signature)
            .map_err(|_| error::signature_mismatch())
    }
}

impl TryFrom<PublicKeyDto> for PublicKey {
    type Error = error::KeyRejected;

    fn try_from(dto: PublicKeyDto) -> Result<Self, Self::Error> {
        Self::from_components(dto.modulus, dto.exponent)
    }
}

/// RSA public key components
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PublicKeyDto {
    /// The public modulus
    #[serde(rename = "n")]
    modulus: Base64Url,

    /// The public exponent
    #[serde(rename = "e")]
    exponent: Base64Url,
}
