use std::convert::TryFrom;

use aliri_core::base64::Base64Url;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcKey, EcPoint, PointConversionForm},
    pkey::PKey,
};
use ring::signature::VerificationAlgorithm;
use serde::{Deserialize, Serialize};

#[cfg(feature = "private-keys")]
use openssl::{ec::EcKeyRef, pkey::HasPublic};

use crate::{
    error,
    jwa::ec::{Curve, SigningAlgorithm},
    jws,
};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct PublicKeyDto {
    #[serde(rename = "crv")]
    pub(super) curve: Curve,
    pub(super) x: Base64Url,
    pub(super) y: Base64Url,
}

/// Elliptic curve cryptography public key components
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "PublicKeyDto", into = "PublicKeyDto")]
pub struct PublicKey {
    curve: Curve,

    /// The public key represented as the uncompressed point on the curve
    public_key: Base64Url,
}

impl PublicKey {
    /// The named elliptic curve that this key is associated with
    pub fn curve(&self) -> Curve {
        self.curve
    }

    /// Constructs a public key from the public point
    pub fn from_public_point(curve: Curve, uncompressed_point: impl Into<Base64Url>) -> Self {
        Self {
            curve,
            public_key: uncompressed_point.into(),
        }
    }

    /// Exports the public key as a PEM
    pub fn to_pem(&self) -> String {
        let group = self.curve.to_group();
        let ctx = &mut BigNumContext::new().unwrap();
        let point = EcPoint::from_bytes(group, self.public_key.as_slice(), ctx).unwrap();

        let key = EcKey::from_public_key(group, &point).unwrap();
        let pem = PKey::from_ec_key(key).unwrap().public_key_to_pem().unwrap();
        String::from_utf8(pem).unwrap()
    }

    #[cfg(feature = "private-keys")]
    pub(super) fn from_openssl_eckey<T: HasPublic>(key: &'_ EcKeyRef<T>) -> Self {
        let group = key.group();

        let mut ctx = BigNumContext::new().unwrap();
        let public_key = key
            .public_key()
            .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();

        Self {
            curve: Curve::from_group(group).unwrap(),
            public_key: Base64Url::from_raw(public_key),
        }
    }
}

impl TryFrom<PublicKeyDto> for PublicKey {
    type Error = error::KeyRejected;

    fn try_from(dto: PublicKeyDto) -> Result<Self, Self::Error> {
        let group = dto.curve.to_group();
        let public = EcKey::from_public_key_affine_coordinates(
            &group,
            &*BigNum::from_slice(dto.x.as_slice()).map_err(error::key_rejected)?,
            &*BigNum::from_slice(dto.y.as_slice()).map_err(error::key_rejected)?,
        )
        .map_err(error::key_rejected)?;
        let mut ctx = BigNumContext::new().map_err(error::key_rejected)?;
        let public_key = public
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(error::key_rejected)?;

        Ok(Self {
            curve: dto.curve,
            public_key: Base64Url::from_raw(public_key),
        })
    }
}

impl From<PublicKey> for PublicKeyDto {
    fn from(p: PublicKey) -> Self {
        let group = p.curve.to_group();
        let mut ctx = BigNumContext::new().unwrap();
        let point = EcPoint::from_bytes(&group, p.public_key.as_slice(), &mut ctx).unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();

        point
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
            .unwrap();

        Self {
            curve: p.curve,
            x: Base64Url::from_raw(x.to_vec()),
            y: Base64Url::from_raw(y.to_vec()),
        }
    }
}

impl jws::Verifier for PublicKey {
    type Algorithm = SigningAlgorithm;
    type Error = error::SignatureMismatch;

    fn can_verify(&self, alg: Self::Algorithm) -> bool {
        Curve::from(alg) == self.curve
    }

    fn verify(
        &self,
        alg: Self::Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let pk = self.public_key.as_slice();

        alg.verification_algorithm()
            .verify(pk.into(), data.into(), signature.into())
            .map_err(|_| error::signature_mismatch())
    }
}
