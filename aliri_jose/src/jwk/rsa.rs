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
pub enum Parameters {
    #[cfg(feature = "private-keys")]
    PublicAndPrivate(PrivateKeyParameters),
    PublicOnly(PublicKeyParameters),
}

impl Parameters {
    #[cfg(feature = "private-keys")]
    pub fn generate() -> anyhow::Result<Self> {
        PrivateKeyParameters::generate().map(Parameters::PublicAndPrivate)
    }

    #[cfg(feature = "private-keys")]
    pub fn private_key_from_pem(pem: &str) -> anyhow::Result<Self> {
        PrivateKeyParameters::from_pem(pem).map(Parameters::PublicAndPrivate)
    }

    #[cfg(feature = "openssl")]
    pub fn public_key_from_pem(pem: &str) -> anyhow::Result<Self> {
        PublicKeyParameters::from_pem(pem).map(Parameters::PublicOnly)
    }

    #[cfg(feature = "private-keys")]
    fn private_params(&self) -> Option<&PrivateKeyParameters> {
        match self {
            Parameters::PublicAndPrivate(p) => Some(p),
            Parameters::PublicOnly(_) => None,
        }
    }

    fn public_params(&self) -> &PublicKeyParameters {
        match self {
            #[cfg(feature = "private-keys")]
            Parameters::PublicAndPrivate(p) => &p.public_key,
            Parameters::PublicOnly(p) => p,
        }
    }

    pub fn remove_private_key(self) -> Self {
        match self {
            #[cfg(feature = "private-keys")]
            Parameters::PublicAndPrivate(p) => Parameters::PublicOnly(p.public_key),
            Parameters::PublicOnly(p) => Parameters::PublicOnly(p),
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
