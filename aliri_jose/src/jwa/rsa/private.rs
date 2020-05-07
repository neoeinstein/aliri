use std::fmt;

use aliri_core::Base64Url;
use openssl::{
    bn::BigNum,
    pkey::HasPrivate,
    rsa::{Rsa, RsaPrivateKeyBuilder},
};
use serde::{Deserialize, Serialize};

use super::PublicKeyParameters;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateKeyDto {
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

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)] // Should we allow serialization here?
#[serde(try_from = "PrivateKeyDto", into = "PrivateKeyDto")]
pub struct PrivateKeyParameters {
    pub public_key: PublicKeyParameters,
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
                p: Base64Url::new(p.to_vec()),
                q: Base64Url::new(q.to_vec()),
            }),
            _ => None,
        };

        let crt = match (rsa.dmp1(), rsa.dmq1(), rsa.iqmp()) {
            (Some(dmp1), Some(dmq1), Some(iqmp)) => Some(ChineseRemainderTheorem {
                dmp1: Base64Url::new(dmp1.to_vec()),
                dmq1: Base64Url::new(dmq1.to_vec()),
                iqmp: Base64Url::new(iqmp.to_vec()),
            }),
            _ => None,
        };

        Self {
            key: Base64Url::new(rsa.d().to_vec()),
            public_key: PublicKeyParameters {
                modulus: Base64Url::new(rsa.n().to_vec()),
                exponent: Base64Url::new(rsa.e().to_vec()),
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
pub struct Factors {
    pub p: Base64Url,
    pub q: Base64Url,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChineseRemainderTheorem {
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
            modulus: Base64Url::new(rsa.n().to_vec()),
            exponent: Base64Url::new(rsa.e().to_vec()),
        };

        Self { public_key, der }
    }
}

#[cfg(feature = "private-keys")]
impl PrivateKeyParameters {
    pub fn generate() -> anyhow::Result<Self> {
        let rsa = Rsa::generate(2_048)?;
        Ok(Self::from(rsa))
    }

    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let rsa = Rsa::private_key_from_pem(pem.as_bytes())?;
        Ok(Self::from(rsa))
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn to_pem(&self) -> String {
        let key = Rsa::private_key_from_der(&self.der).unwrap();
        let pem = key.private_key_to_pem().unwrap();
        String::from_utf8(pem).unwrap()
    }
}
