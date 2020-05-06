use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    #[cfg(feature = "rsa")]
    #[serde(rename = "RSA")]
    Rsa,

    #[cfg(feature = "ec")]
    #[serde(rename = "EC")]
    EllipticCurve,

    #[cfg(feature = "hmac")]
    #[serde(rename = "oct")]
    Hmac,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum Algorithm {
    #[cfg(feature = "hmac")]
    HS256,
    #[cfg(feature = "hmac")]
    HS384,
    #[cfg(feature = "hmac")]
    HS512,

    #[cfg(feature = "rsa")]
    RS256,
    #[cfg(feature = "rsa")]
    RS384,
    #[cfg(feature = "rsa")]
    RS512,
    #[cfg(feature = "rsa")]
    PS256,
    #[cfg(feature = "rsa")]
    PS384,
    #[cfg(feature = "rsa")]
    PS512,

    #[cfg(feature = "ec")]
    ES256,
    #[cfg(feature = "ec")]
    ES384,

    #[serde(other)]
    #[doc(hidden)]
    Unknown,
}

impl Algorithm {
    pub(crate) fn to_jsonwebtoken(self) -> Option<jsonwebtoken::Algorithm> {
        match self {
            #[cfg(feature = "hmac")]
            Self::HS256 => Some(jsonwebtoken::Algorithm::HS256),
            #[cfg(feature = "hmac")]
            Self::HS384 => Some(jsonwebtoken::Algorithm::HS384),
            #[cfg(feature = "hmac")]
            Self::HS512 => Some(jsonwebtoken::Algorithm::HS512),

            #[cfg(feature = "rsa")]
            Self::RS256 => Some(jsonwebtoken::Algorithm::RS256),
            #[cfg(feature = "rsa")]
            Self::RS384 => Some(jsonwebtoken::Algorithm::RS384),
            #[cfg(feature = "rsa")]
            Self::RS512 => Some(jsonwebtoken::Algorithm::RS512),
            #[cfg(feature = "rsa")]
            Self::PS256 => Some(jsonwebtoken::Algorithm::PS256),
            #[cfg(feature = "rsa")]
            Self::PS384 => Some(jsonwebtoken::Algorithm::PS384),
            #[cfg(feature = "rsa")]
            Self::PS512 => Some(jsonwebtoken::Algorithm::PS512),

            #[cfg(feature = "ec")]
            Self::ES256 => Some(jsonwebtoken::Algorithm::ES256),
            #[cfg(feature = "ec")]
            Self::ES384 => Some(jsonwebtoken::Algorithm::ES384),

            _ => None,
        }
    }
}
