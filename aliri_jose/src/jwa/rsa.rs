use jsonwebtoken::DecodingKey;
#[cfg(feature = "private-keys")]
use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};

#[cfg(feature = "private-keys")]
mod private;
mod public;

#[cfg(feature = "private-keys")]
pub use private::PrivateKeyParameters;
pub use public::PublicKeyParameters;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Rsa {
    #[cfg(feature = "private-keys")]
    PublicAndPrivate(PrivateKeyParameters),
    PublicOnly(PublicKeyParameters),
}

impl Rsa {
    #[cfg(feature = "private-keys")]
    pub fn generate() -> anyhow::Result<Self> {
        PrivateKeyParameters::generate().map(Rsa::PublicAndPrivate)
    }

    #[cfg(feature = "private-keys")]
    pub fn private_key_from_pem(pem: &str) -> anyhow::Result<Self> {
        PrivateKeyParameters::from_pem(pem).map(Self::PublicAndPrivate)
    }

    #[cfg(feature = "openssl")]
    pub fn public_key_from_pem(pem: &str) -> anyhow::Result<Self> {
        PublicKeyParameters::from_pem(pem).map(Self::PublicOnly)
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

        DecodingKey::from_rsa_raw_components(pk.modulus.as_slice(), pk.exponent.as_slice())
    }

    #[doc(hidden)]
    #[cfg(feature = "private-keys")]
    pub fn signing_key(&self) -> Option<EncodingKey> {
        let der = self.private_params()?.der();

        Some(EncodingKey::from_rsa_der(der))
    }
}
