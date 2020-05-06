use aliri_core::Base64Url;
use jsonwebtoken::DecodingKey;
#[cfg(feature = "private-keys")]
use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameters {
    #[serde(rename = "k")]
    key: Base64Url,
}

impl Parameters {
    #[cfg(feature = "private-keys")]
    pub fn generate(bits: usize) -> anyhow::Result<Self> {
        let mut buf = Vec::new();
        buf.resize_with(bits.saturating_add(1) / 8, || 0);
        openssl::rand::rand_bytes(&mut buf[..])?;
        Ok(Self {
            key: Base64Url::new(buf),
        })
    }

    pub(crate) fn verify_key(&self) -> DecodingKey {
        DecodingKey::from_secret(self.key.as_slice())
    }

    #[doc(hidden)]
    #[cfg(feature = "private-keys")]
    pub fn signing_key(&self) -> EncodingKey {
        EncodingKey::from_secret(self.key.as_slice())
    }
}
