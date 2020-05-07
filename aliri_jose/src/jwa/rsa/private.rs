use std::fmt;

use aliri_core::base64::Base64Url;
use openssl::{
    bn::BigNum,
    pkey::HasPrivate,
    rsa::{Rsa, RsaPrivateKeyBuilder},
};
use serde::{Deserialize, Serialize};

use super::PublicKeyParameters;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PrivateKeyDto {
    #[serde(rename = "d")]
    key: Base64Url,

    #[serde(flatten)]
    public_key: PublicKeyParameters,

    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    factors: Option<Factors>,

    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    crt: Option<ChineseRemainderTheorem>,
}

/// RSA private key components
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)] // Should we allow serialization here?
#[serde(try_from = "PrivateKeyDto", into = "PrivateKeyDto")]
pub struct PrivateKeyParameters {
    public_key: PublicKeyParameters,
    der: Vec<u8>,
}

impl fmt::Debug for PrivateKeyParameters {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PrivateKeyParameters")
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl From<PrivateKeyParameters> for PrivateKeyDto {
    fn from(pk: PrivateKeyParameters) -> Self {
        let rsa = Rsa::private_key_from_der(&pk.der).unwrap();

        let factors = match (rsa.p(), rsa.q()) {
            (Some(p), Some(q)) => Some(Factors {
                p: Base64Url::from_raw(p.to_vec()),
                q: Base64Url::from_raw(q.to_vec()),
            }),
            _ => None,
        };

        let crt = match (rsa.dmp1(), rsa.dmq1(), rsa.iqmp()) {
            (Some(dmp1), Some(dmq1), Some(iqmp)) => Some(ChineseRemainderTheorem {
                dmp1: Base64Url::from_raw(dmp1.to_vec()),
                dmq1: Base64Url::from_raw(dmq1.to_vec()),
                iqmp: Base64Url::from_raw(iqmp.to_vec()),
            }),
            _ => None,
        };

        Self {
            key: Base64Url::from_raw(rsa.d().to_vec()),
            public_key: PublicKeyParameters {
                modulus: Base64Url::from_raw(rsa.n().to_vec()),
                exponent: Base64Url::from_raw(rsa.e().to_vec()),
            },
            factors,
            crt,
        }
    }
}

impl std::convert::TryFrom<PrivateKeyDto> for PrivateKeyParameters {
    type Error = anyhow::Error;

    fn try_from(dto: PrivateKeyDto) -> anyhow::Result<Self> {
        let mut builder = RsaPrivateKeyBuilder::new(
            BigNum::from_slice(dto.public_key.modulus.as_slice())?,
            BigNum::from_slice(dto.public_key.exponent.as_slice())?,
            BigNum::from_slice(dto.key.as_slice())?,
        )?;

        if let Some(f) = &dto.factors {
            builder = builder.set_factors(
                BigNum::from_slice(f.p.as_slice())?,
                BigNum::from_slice(f.q.as_slice())?,
            )?;
        }

        if let Some(crt) = &dto.crt {
            builder = builder.set_crt_params(
                BigNum::from_slice(crt.dmp1.as_slice())?,
                BigNum::from_slice(crt.dmq1.as_slice())?,
                BigNum::from_slice(crt.iqmp.as_slice())?,
            )?;
        }

        let key = builder.build();

        Ok(Self {
            public_key: dto.public_key,
            der: key.private_key_to_der()?,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct Factors {
    pub p: Base64Url,
    pub q: Base64Url,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct ChineseRemainderTheorem {
    #[serde(rename = "dp")]
    pub dmp1: Base64Url,
    #[serde(rename = "dq")]
    pub dmq1: Base64Url,
    #[serde(rename = "qi")]
    pub iqmp: Base64Url,
}

impl<T: HasPrivate> From<Rsa<T>> for PrivateKeyParameters {
    fn from(rsa: Rsa<T>) -> Self {
        let der = rsa.private_key_to_der().unwrap();

        let public_key = PublicKeyParameters {
            modulus: Base64Url::from_raw(rsa.n().to_vec()),
            exponent: Base64Url::from_raw(rsa.e().to_vec()),
        };

        Self { public_key, der }
    }
}

#[cfg(feature = "private-keys")]
impl PrivateKeyParameters {
    /// Generates a new 2048-bit RSA key pair
    pub fn generate() -> anyhow::Result<Self> {
        let rsa = Rsa::generate(2048)?;
        Ok(Self::from(rsa))
    }

    /// Imports an RSA key pair from a PEM file
    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let rsa = Rsa::private_key_from_pem(pem.as_bytes())?;
        Ok(Self::from(rsa))
    }

    /// The RSA key pair in DER encoding
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Exports the RSA key pair as a PEM file
    pub fn to_pem(&self) -> String {
        let key = Rsa::private_key_from_der(&self.der).unwrap();
        let pem = key.private_key_to_pem().unwrap();
        String::from_utf8(pem).unwrap()
    }

    /// Provides access to the public key parameters
    pub fn public_key(&self) -> &PublicKeyParameters {
        &self.public_key
    }

    /// Extracts the public key
    pub fn into_public_key(self) -> PublicKeyParameters {
        self.public_key
    }
}
