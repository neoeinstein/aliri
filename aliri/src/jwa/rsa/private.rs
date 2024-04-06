use std::{convert::TryFrom, fmt, sync::Arc};

use aliri_base64::Base64Url;
use openssl::{
    bn::BigNum,
    pkey::Private,
    rsa::{Rsa, RsaPrivateKeyBuilder},
};
use ring::signature::RsaKeyPair;
use serde::{Deserialize, Serialize};

use super::{PublicKey, SigningAlgorithm};
use crate::{error, jws};

/// RSA private key components
#[derive(Clone, Serialize, Deserialize)] // Should we allow serialization here?
#[serde(try_from = "PrivateKeyDto", into = "PrivateKeyDto")]
#[must_use]
pub struct PrivateKey {
    public_key: PublicKey,
    der: Vec<u8>,
    ring_cache: Arc<RsaKeyPair>,
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}

impl Eq for PrivateKey {}

#[cfg(feature = "private-keys")]
#[cfg_attr(docsrs, doc(cfg(feature = "private-keys")))]
impl PrivateKey {
    /// Generates a new 2048-bit RSA key pair
    ///
    /// # Errors
    ///
    /// Unable to generate a private key.
    pub fn generate() -> Result<Self, error::Unexpected> {
        let rsa = Rsa::generate(2048).map_err(error::unexpected)?;
        Self::from_openssl_key(&rsa).map_err(error::unexpected)
    }

    /// Imports an RSA key pair from a PEM file
    ///
    /// # Errors
    ///
    /// The provided PEM file is not a valid RSA private key.
    pub fn from_pem(pem: &str) -> Result<Self, error::KeyRejected> {
        let rsa = Rsa::private_key_from_pem(pem.as_bytes()).map_err(error::key_rejected)?;
        Self::from_openssl_key(&rsa)
    }

    fn from_openssl_key(rsa: &Rsa<Private>) -> Result<Self, error::KeyRejected> {
        let der = rsa.private_key_to_der().map_err(error::key_rejected)?;

        let public_key = PublicKey::from_components(
            Base64Url::from_raw(rsa.n().to_vec()),
            Base64Url::from_raw(rsa.e().to_vec()),
        )?;

        let ring_cache =
            Arc::new(RsaKeyPair::from_der(&der).map_err(|e| error::key_rejected(e.to_string()))?);

        Ok(Self {
            public_key,
            der,
            ring_cache,
        })
    }

    /// The RSA key pair in DER encoding
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Exports the RSA key pair as a PEM file
    #[must_use]
    pub fn to_pem(&self) -> String {
        let key = Rsa::private_key_from_der(&self.der).unwrap();
        let pem = key.private_key_to_pem().unwrap();
        String::from_utf8(pem).unwrap()
    }

    /// Provides access to the public key parameters
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Extracts the public key
    pub fn into_public_key(self) -> PublicKey {
        self.public_key
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl jws::Signer for PrivateKey {
    type Algorithm = SigningAlgorithm;
    type Error = error::Unexpected;

    fn can_sign(&self, _alg: Self::Algorithm) -> bool {
        true
    }

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut buf = vec![0; self.ring_cache.public().modulus_len()];
        self.ring_cache
            .sign(
                alg.into_signing_params(),
                &ring::rand::SystemRandom::new(),
                data,
                &mut buf,
            )
            .map_err(|e| error::unexpected(e.to_string()))?;
        Ok(buf)
    }
}

impl From<PrivateKey> for PrivateKeyDto {
    fn from(pk: PrivateKey) -> Self {
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
            public_key: PublicKey::from_components(
                Base64Url::from_raw(rsa.n().to_vec()),
                Base64Url::from_raw(rsa.e().to_vec()),
            )
            .unwrap(),
            factors,
            crt,
        }
    }
}

impl TryFrom<PrivateKeyDto> for PrivateKey {
    type Error = error::KeyRejected;

    fn try_from(dto: PrivateKeyDto) -> Result<Self, Self::Error> {
        let mut builder = RsaPrivateKeyBuilder::new(
            BigNum::from_slice(dto.public_key.modulus().as_slice()).map_err(error::key_rejected)?,
            BigNum::from_slice(dto.public_key.exponent().as_slice())
                .map_err(error::key_rejected)?,
            BigNum::from_slice(dto.key.as_slice()).map_err(error::key_rejected)?,
        )
        .map_err(error::key_rejected)?;

        if let Some(f) = &dto.factors {
            builder = builder
                .set_factors(
                    BigNum::from_slice(f.p.as_slice()).map_err(error::key_rejected)?,
                    BigNum::from_slice(f.q.as_slice()).map_err(error::key_rejected)?,
                )
                .map_err(error::key_rejected)?;
        }

        if let Some(crt) = &dto.crt {
            builder = builder
                .set_crt_params(
                    BigNum::from_slice(crt.dmp1.as_slice()).map_err(error::key_rejected)?,
                    BigNum::from_slice(crt.dmq1.as_slice()).map_err(error::key_rejected)?,
                    BigNum::from_slice(crt.iqmp.as_slice()).map_err(error::key_rejected)?,
                )
                .map_err(error::key_rejected)?;
        }

        let key = builder.build();

        let der = key.private_key_to_der().map_err(error::key_rejected)?;

        let ring_cache =
            Arc::new(RsaKeyPair::from_der(&der).map_err(|e| error::key_rejected(e.to_string()))?);

        Ok(Self {
            public_key: dto.public_key,
            der,
            ring_cache,
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PrivateKeyDto {
    #[serde(rename = "d")]
    key: Base64Url,

    #[serde(flatten)]
    public_key: PublicKey,

    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    factors: Option<Factors>,

    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    crt: Option<ChineseRemainderTheorem>,
}
