use std::{convert::TryFrom, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{error, jwa, jws};

/// An algorithm
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Algorithm {
    /// A signing/verification algorithm
    Signing(jws::Algorithm),
}

impl Algorithm {
    /// Gets the usage related to this algorithm
    pub fn to_usage(self) -> jwa::Usage {
        match self {
            Self::Signing(_) => jwa::Usage::Signing,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Signing(x) => fmt::Display::fmt(x, f),
        }
    }
}

#[cfg(feature = "hmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "hmac")))]
impl Algorithm {
    /// The HS256 signing algorithm
    pub const HS256: Algorithm = Self::Signing(jws::Algorithm::HS256);
    /// The HS384 signing algorithm
    pub const HS384: Algorithm = Self::Signing(jws::Algorithm::HS384);
    /// The HS512 signing algorithm
    pub const HS512: Algorithm = Self::Signing(jws::Algorithm::HS512);
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl Algorithm {
    /// The RS256 signing algorithm
    pub const RS256: Algorithm = Self::Signing(jws::Algorithm::RS256);
    /// The RS384 signing algorithm
    pub const RS384: Algorithm = Self::Signing(jws::Algorithm::RS384);
    /// The RS512 signing algorithm
    pub const RS512: Algorithm = Self::Signing(jws::Algorithm::RS512);
    /// The PS256 signing algorithm
    pub const PS256: Algorithm = Self::Signing(jws::Algorithm::PS256);
    /// The PS384 signing algorithm
    pub const PS384: Algorithm = Self::Signing(jws::Algorithm::PS384);
    /// The PS512 signing algorithm
    pub const PS512: Algorithm = Self::Signing(jws::Algorithm::PS512);
}

#[cfg(feature = "ec")]
#[cfg_attr(docsrs, doc(cfg(feature = "ec")))]
impl Algorithm {
    /// The ES256 signing algorithm
    pub const ES256: Algorithm = Self::Signing(jws::Algorithm::ES256);
    /// The ES384 signing algorithm
    pub const ES384: Algorithm = Self::Signing(jws::Algorithm::ES384);
    /// The ES512 signing algorithm
    pub const ES512: Algorithm = Self::Signing(jws::Algorithm::ES512);
}

impl TryFrom<&'_ str> for Algorithm {
    type Error = error::UnknownAlgorithm;

    #[inline]
    fn try_from(value: &'_ str) -> Result<Self, Self::Error> {
        match value {
            #[cfg(feature = "ec")]
            "ES256" => Ok(Algorithm::ES256),
            #[cfg(feature = "ec")]
            "ES384" => Ok(Algorithm::ES384),
            #[cfg(feature = "ec")]
            "ES512" => Ok(Algorithm::ES512),
            #[cfg(feature = "rsa")]
            "RS256" => Ok(Algorithm::RS256),
            #[cfg(feature = "rsa")]
            "RS384" => Ok(Algorithm::RS384),
            #[cfg(feature = "rsa")]
            "RS512" => Ok(Algorithm::RS512),
            #[cfg(feature = "rsa")]
            "PS256" => Ok(Algorithm::PS256),
            #[cfg(feature = "rsa")]
            "PS384" => Ok(Algorithm::PS384),
            #[cfg(feature = "rsa")]
            "PS512" => Ok(Algorithm::PS512),
            #[cfg(feature = "hmac")]
            "HS256" => Ok(Algorithm::HS256),
            #[cfg(feature = "hmac")]
            "HS384" => Ok(Algorithm::HS384),
            #[cfg(feature = "hmac")]
            "HS512" => Ok(Algorithm::HS512),
            _ => Err(error::unknown_algorithm(value.to_string())),
        }
    }
}

impl TryFrom<String> for Algorithm {
    type Error = error::UnknownAlgorithm;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = error::UnknownAlgorithm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl<T> From<T> for Algorithm
where
    jws::Algorithm: From<T>,
{
    #[inline]
    fn from(alg: T) -> Self {
        Self::Signing(jws::Algorithm::from(alg))
    }
}

impl TryFrom<Algorithm> for jws::Algorithm {
    type Error = error::IncompatibleAlgorithm;

    #[inline]
    fn try_from(alg: Algorithm) -> Result<Self, Self::Error> {
        match alg {
            Algorithm::Signing(alg) => Ok(alg),

            #[allow(unreachable_patterns)]
            _ => Err(error::incompatible_algorithm(alg)),
        }
    }
}
