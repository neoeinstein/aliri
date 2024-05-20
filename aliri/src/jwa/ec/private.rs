use std::{convert::TryFrom, fmt, sync::Arc};

use aliri_base64::{Base64, Base64Url};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::EcKey,
    pkey::{PKey, Private},
};
use ring::signature::EcdsaKeyPair;
use serde::{Deserialize, Serialize};

use crate::{
    error,
    jwa::ec::{public::PublicKeyDto, Curve, PublicKey, SigningAlgorithm},
    jws,
};

/// ECC private key parameters
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "PrivateKeyDto", into = "PrivateKeyDto")]
#[must_use]
pub struct PrivateKey {
    public_key: PublicKey,
    pkcs8: Base64,
    ring_cache: Arc<EcdsaKeyPair>,
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.pkcs8 == other.pkcs8
    }
}

impl Eq for PrivateKey {}

impl PrivateKey {
    /// Generates a new ECC key pair using the specified curve
    ///
    /// # Errors
    ///
    /// Unable to generate a private key.
    pub fn generate(curve: Curve) -> Result<Self, error::Unexpected> {
        let key = EcKey::generate(curve.to_group()).map_err(error::unexpected)?;

        Self::from_openssl_eckey(key).map_err(error::unexpected)
    }

    /// Constructs an ECC key pair from a PEM file
    ///
    /// # Errors
    ///
    /// The provided PEM file is not a valid ECC private key.
    pub fn from_pem(pem: &str) -> Result<Self, error::KeyRejected> {
        let key = PKey::private_key_from_pem(pem.as_bytes()).map_err(error::key_rejected)?;
        Self::from_openssl_eckey(key.ec_key().map_err(error::key_rejected)?)
    }

    fn from_openssl_eckey(key: EcKey<Private>) -> Result<Self, error::KeyRejected> {
        let public_key = PublicKey::from_openssl_eckey(&*key);

        let pkey = PKey::from_ec_key(key).map_err(error::key_rejected)?;
        let pkcs8_bytes = pkey
            .private_key_to_pem_pkcs8()
            .map_err(error::key_rejected)?;
        let pkcs8_pem = String::from_utf8(pkcs8_bytes).map_err(error::key_rejected)?;

        let pkcs8_str = pkcs8_pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace('\n', "");

        let pkcs8 = Base64::from_encoded(pkcs8_str).map_err(error::key_rejected)?;

        let ring_cache = Arc::new(
            EcdsaKeyPair::from_pkcs8(
                SigningAlgorithm::from(public_key.curve()).signing_algorithm(),
                pkcs8.as_slice(),
                &ring::rand::SystemRandom::new(),
            )
            .map_err(|e| error::key_rejected(e.to_string()))?,
        );

        Ok(Self {
            public_key,
            pkcs8,
            ring_cache,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn to_pem(&self) -> Result<String, error::Unexpected> {
        let x = PKey::private_key_from_pkcs8(self.pkcs8.as_slice())
            .map_err(error::unexpected)?
            .private_key_to_pem_pkcs8()
            .map_err(error::unexpected)?;
        String::from_utf8(x).map_err(error::unexpected)
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

impl jws::Signer for PrivateKey {
    type Algorithm = SigningAlgorithm;
    type Error = error::SigningError;

    fn can_sign(&self, alg: Self::Algorithm) -> bool {
        self.public_key.curve() == Curve::from(alg)
    }

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        if !self.can_sign(alg) {
            return Err(error::incompatible_algorithm(alg).into());
        }

        let signature = self
            .ring_cache
            .sign(&ring::rand::SystemRandom::new(), data)
            .map_err(|e| error::unexpected(e.to_string()))?;

        Ok(signature.as_ref().to_owned())
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct PrivateKeyDto {
    #[serde(rename = "d")]
    key: Base64Url,

    #[serde(flatten)]
    public_key: PublicKeyDto,
}

impl From<PrivateKey> for PrivateKeyDto {
    fn from(pk: PrivateKey) -> Self {
        let key = PKey::private_key_from_der(pk.pkcs8.as_slice())
            .unwrap()
            .ec_key()
            .unwrap();
        let ctx = &mut BigNumContext::new().unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();

        key.public_key()
            .affine_coordinates_gfp(key.group(), &mut x, &mut y, ctx)
            .unwrap();

        Self {
            key: Base64Url::from_raw(key.private_key().to_vec()),
            public_key: PublicKeyDto::from(pk.into_public_key()),
        }
    }
}

impl TryFrom<PrivateKeyDto> for PrivateKey {
    type Error = error::KeyRejected;

    fn try_from(dto: PrivateKeyDto) -> Result<Self, Self::Error> {
        let group = dto.public_key.curve.to_group();
        let public = EcKey::from_public_key_affine_coordinates(
            group,
            &*BigNum::from_slice(dto.public_key.x.as_slice()).map_err(error::key_rejected)?,
            &*BigNum::from_slice(dto.public_key.y.as_slice()).map_err(error::key_rejected)?,
        )
        .map_err(error::key_rejected)?;

        let public_key = public.public_key();
        let private_number = BigNum::from_slice(dto.key.as_slice()).map_err(error::key_rejected)?;

        let key = EcKey::from_private_components(group, &private_number, public_key)
            .map_err(error::key_rejected)?;

        Self::from_openssl_eckey(key)
    }
}
