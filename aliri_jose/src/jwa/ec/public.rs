use std::convert::TryFrom;

use aliri_core::Base64Url;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcKey, EcKeyRef, EcPoint, PointConversionForm},
    pkey::{HasPublic, PKey},
};
use serde::{Deserialize, Serialize};

use super::Curve;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyDto {
    #[serde(rename = "crv")]
    pub curve: Curve,
    pub x: Base64Url,
    pub y: Base64Url,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "PublicKeyDto", into = "PublicKeyDto")]
pub struct PublicKeyParameters {
    pub curve: Curve,
    pub uncompressed_point: Base64Url,
    pub pkcs8: Base64Url,
}

impl PublicKeyParameters {
    pub fn to_pem(&self) -> String {
        let group = self.curve.to_group();
        let ctx = &mut BigNumContext::new().unwrap();
        let point = EcPoint::from_bytes(group, self.uncompressed_point.as_slice(), ctx).unwrap();

        let key = EcKey::from_public_key(group, &point).unwrap();
        let pem = PKey::from_ec_key(key).unwrap().public_key_to_pem().unwrap();
        String::from_utf8(pem).unwrap()
    }
}

impl TryFrom<PublicKeyDto> for PublicKeyParameters {
    type Error = anyhow::Error;

    fn try_from(dto: PublicKeyDto) -> Result<Self, Self::Error> {
        let group = dto.curve.to_group();
        let public = EcKey::from_public_key_affine_coordinates(
            &group,
            &*BigNum::from_slice(dto.x.as_slice())?,
            &*BigNum::from_slice(dto.y.as_slice())?,
        )?;
        let mut ctx = BigNumContext::new()?;
        let uncompressed_point =
            public
                .public_key()
                .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

        let pkcs8 = PKey::from_ec_key(public)?.public_key_to_der()?;

        Ok(Self {
            curve: dto.curve,
            uncompressed_point: Base64Url::new(uncompressed_point),
            pkcs8: Base64Url::from(pkcs8),
        })
    }
}

impl From<PublicKeyParameters> for PublicKeyDto {
    fn from(p: PublicKeyParameters) -> Self {
        let group = p.curve.to_group();
        let mut ctx = BigNumContext::new().unwrap();
        let point = EcPoint::from_bytes(&group, p.uncompressed_point.as_slice(), &mut ctx).unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();

        point
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
            .unwrap();

        Self {
            curve: p.curve,
            x: Base64Url::new(x.to_vec()),
            y: Base64Url::new(y.to_vec()),
        }
    }
}

impl<T: HasPublic> From<&'_ EcKeyRef<T>> for PublicKeyParameters {
    fn from(key: &'_ EcKeyRef<T>) -> Self {
        let group = key.group();

        let mut ctx = BigNumContext::new().unwrap();
        let uncompressed_point = key
            .public_key()
            .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();

        let pkcs8 = PKey::from_ec_key(key.to_owned())
            .unwrap()
            .public_key_to_der()
            .unwrap();

        Self {
            curve: Curve::from_group(group).unwrap(),
            uncompressed_point: Base64Url::new(uncompressed_point),
            pkcs8: Base64Url::from(pkcs8),
        }
    }
}
