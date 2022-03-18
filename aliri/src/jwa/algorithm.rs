use std::{convert::TryFrom, fmt};

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
