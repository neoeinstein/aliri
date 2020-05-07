use jsonwebtoken::DecodingKey;
#[cfg(feature = "private-keys")]
use jsonwebtoken::EncodingKey;
use lazy_static::lazy_static;
use openssl::{
    ec::{EcGroup, EcGroupRef},
    nid::Nid,
};
use serde::{Deserialize, Serialize};

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

    pub(crate) fn verify_key(&self) -> DecodingKey {
        let pk = self.public_params();

        DecodingKey::from_ec_der(pk.uncompressed_point.as_slice())
    }

    #[cfg(feature = "private-keys")]
    pub(crate) fn signing_key(&self) -> Option<EncodingKey> {
        let pem = self.private_params()?.pem();

        println!("{}", pem);

        Some(EncodingKey::from_ec_pem(pem.as_bytes()).unwrap())
    }
}
