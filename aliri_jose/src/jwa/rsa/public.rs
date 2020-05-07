use aliri_core::Base64Url;
#[cfg(feature = "openssl")]
use openssl::{bn::BigNum, pkey::HasPublic, rsa::Rsa};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyParameters {
    #[serde(rename = "n")]
    pub modulus: Base64Url,

    #[serde(rename = "e")]
    pub exponent: Base64Url,
}

impl PublicKeyParameters {
    #[cfg(feature = "openssl")]
    pub fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let rsa = Rsa::public_key_from_pem(pem.as_bytes())?;
        Ok(Self::from(rsa))
    }

    #[cfg(feature = "openssl")]
    pub fn to_pem(&self) -> anyhow::Result<String> {
        let modulus = BigNum::from_slice(self.modulus.as_slice())?;
        let exponent = BigNum::from_slice(self.exponent.as_slice())?;

        let key = Rsa::from_public_components(modulus, exponent)?;
        let pem = key.public_key_to_pem()?;
        Ok(String::from_utf8(pem)?)
    }
}

#[cfg(feature = "openssl")]
impl<T: HasPublic> From<Rsa<T>> for PublicKeyParameters {
    fn from(rsa: Rsa<T>) -> Self {
        PublicKeyParameters {
            modulus: Base64Url::new(rsa.n().to_vec()),
            exponent: Base64Url::new(rsa.e().to_vec()),
        }
    }
}
