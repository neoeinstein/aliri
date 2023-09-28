//! Common errors

#![allow(missing_copy_implementations)]

use std::error::Error as StdError;

use thiserror::Error;

/// The JWK cannot be used with the requested algorithm
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Error)]
#[error("key incompatible with algorithm '{alg}'")]
pub struct IncompatibleAlgorithm {
    alg: crate::jwa::Algorithm,
}

#[inline]
pub(crate) fn incompatible_algorithm(
    alg: impl Into<crate::jwa::Algorithm>,
) -> IncompatibleAlgorithm {
    IncompatibleAlgorithm { alg: alg.into() }
}

/// The provided name could not be matched with supported algorithms
#[derive(Debug, Error)]
#[error("'{alg}' does not match supported algorithms")]
pub struct UnknownAlgorithm {
    alg: String,
}

#[inline]
pub(crate) fn unknown_algorithm(alg: String) -> UnknownAlgorithm {
    UnknownAlgorithm { alg }
}

/// The JWK has a specific usage that disallows this use
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Error)]
#[error("JWK cannot be used in this way")]
pub struct JwkUsageMismatch {
    _p: (),
}

pub(crate) const fn jwk_usage_mismatch() -> JwkUsageMismatch {
    JwkUsageMismatch { _p: () }
}

/// The JWT is malformed and cannot be parsed out into header, payload, and signature sections
#[derive(Clone, Copy, Debug, Error)]
#[error("malformed JWT")]
pub struct MalformedJwt {
    _p: (),
}

pub(crate) fn malformed_jwt() -> MalformedJwt {
    MalformedJwt { _p: () }
}

/// The JWT header section is malformed
#[derive(Debug, Error)]
#[error("malformed JWT header")]
pub struct MalformedJwtHeader {
    #[from]
    source: Box<dyn StdError + Send + Sync + 'static>,
}

pub(crate) fn malformed_jwt_header(
    source: impl Into<Box<dyn StdError + Send + Sync + 'static>>,
) -> MalformedJwtHeader {
    MalformedJwtHeader {
        source: source.into(),
    }
}
/// The JWT payload section is malformed
#[derive(Debug, Error)]
#[error("malformed JWT payload")]
pub struct MalformedJwtPayload {
    #[from]
    source: Box<dyn StdError + Send + Sync + 'static>,
}

pub(crate) fn malformed_jwt_payload(
    source: impl Into<Box<dyn StdError + Send + Sync + 'static>>,
) -> MalformedJwtPayload {
    MalformedJwtPayload {
        source: source.into(),
    }
}

/// The JWT signature section is malformed
#[derive(Debug, Error)]
#[error("malformed JWT signature")]
pub struct MalformedJwtSignature {
    #[from]
    source: Box<dyn StdError + Send + Sync + 'static>,
}

pub(crate) fn malformed_jwt_signature(
    source: impl Into<Box<dyn StdError + Send + Sync + 'static>>,
) -> MalformedJwtSignature {
    MalformedJwtSignature {
        source: source.into(),
    }
}

/// The signature did not match
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Error)]
#[error("signature mismatch")]
pub struct SignatureMismatch {
    _p: (),
}

pub(crate) const fn signature_mismatch() -> SignatureMismatch {
    SignatureMismatch { _p: () }
}

/// The key was rejected
#[derive(Debug, Error)]
#[error("key rejected")]
pub struct KeyRejected {
    #[from]
    source: Box<dyn StdError + Send + Sync + 'static>,
}

pub(crate) fn key_rejected(
    source: impl Into<Box<dyn StdError + Send + Sync + 'static>>,
) -> KeyRejected {
    KeyRejected {
        source: source.into(),
    }
}

/// Missing private key
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Error)]
#[error("cannot sign without a private key")]
pub struct MissingPrivateKey {
    _p: (),
}

pub(crate) const fn missing_private_key() -> MissingPrivateKey {
    MissingPrivateKey { _p: () }
}

/// Unexpected error (possibly a bug)
#[derive(Debug, Error)]
#[error("unexpected error")]
pub struct Unexpected {
    #[from]
    source: Box<dyn StdError + Send + Sync + 'static>,
}

pub(crate) fn unexpected(
    source: impl Into<Box<dyn StdError + Send + Sync + 'static>>,
) -> Unexpected {
    Unexpected {
        source: source.into(),
    }
}

/// An error occurring while creating a signature
#[derive(Debug, Error)]
pub enum SigningError {
    /// The key cannot be used for signing operations
    #[error(transparent)]
    MissingPrivateKey(#[from] MissingPrivateKey),

    /// JWK cannot be used for signature creation
    #[error(transparent)]
    JwkUsageMismatch(#[from] JwkUsageMismatch),

    /// Algorithm be used with this algorithm
    #[error(transparent)]
    IncompatibleAlgorithm(#[from] IncompatibleAlgorithm),

    /// An unexpected error
    #[error(transparent)]
    Unexpected(#[from] Unexpected),
}

impl From<std::convert::Infallible> for SigningError {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!("infallible result")
    }
}

/// An error occurring while verifying a signature with a JWK
#[derive(Debug, Error)]
pub enum JwkVerifyError {
    /// JWT cannot be used with this algorithm
    #[error(transparent)]
    IncompatibleAlgorithm(#[from] IncompatibleAlgorithm),

    /// JWK cannot be used for signature verification
    #[error(transparent)]
    JwkUsageMismatch(#[from] JwkUsageMismatch),

    /// Signature is invalid
    #[error(transparent)]
    SignatureMismatch(#[from] SignatureMismatch),

    /// An unexpected error
    #[error(transparent)]
    Unexpected(#[from] Unexpected),
}

impl JwkVerifyError {
    /// Whether the error is due to an incompatible algorithm
    #[must_use]
    pub fn is_incompatible_alg(&self) -> bool {
        matches!(self, Self::IncompatibleAlgorithm(_))
    }

    /// Whether the error is due to a usage mismatch
    #[must_use]
    pub fn is_usage_mismatch(&self) -> bool {
        matches!(self, Self::JwkUsageMismatch(_))
    }

    /// Whether the error is due to a signature mismatch
    #[must_use]
    pub fn is_signature_mismatch(&self) -> bool {
        matches!(self, Self::SignatureMismatch(_))
    }
}

/// An error occurring while verifying a JWT
#[derive(Debug, Error)]
pub enum JwtVerifyError {
    /// The JWT was rejected by the JWK
    #[error("token rejected by JWK")]
    JwkVerifyError(#[from] JwkVerifyError),

    /// The JWT is malformed, without a discernible header, payload, and signature
    #[error(transparent)]
    MalformedToken(#[from] MalformedJwt),

    /// The JWT header is malformed
    #[error(transparent)]
    MalformedTokenHeader(#[from] MalformedJwtHeader),

    /// The JWT payload is malformed
    #[error(transparent)]
    MalformedTokenPayload(#[from] MalformedJwtPayload),

    /// The JWT signature is malformed
    #[error(transparent)]
    MalformedTokenSignature(#[from] MalformedJwtSignature),

    /// The JWT was rejected by the claims validator
    #[error("token rejected by claims validator")]
    ClaimsRejected(#[from] ClaimsRejected),

    /// An unexpected error
    #[error(transparent)]
    Unexpected(#[from] Unexpected),
}

/// An error occurring while verifying a JWT
#[derive(Debug, Error)]
pub enum JwtSigningError {
    /// The JWT was rejected by the JWK
    #[error(transparent)]
    SigningError(#[from] SigningError),

    /// The JWT header was malformed and could not be serialized
    #[error(transparent)]
    MalformedJwtHeader(#[from] MalformedJwtHeader),

    /// The JWT payload was malformed and could not be serialized
    #[error(transparent)]
    MalformedJwtPayload(#[from] MalformedJwtPayload),

    /// An unexpected error
    #[error(transparent)]
    Unexpected(#[from] Unexpected),
}

/// An error occurring when validating the claims of a JWT
#[derive(Debug, Error)]
pub enum ClaimsRejected {
    /// The token algorithm is not acceptable
    #[error("invalid algorithm")]
    InvalidAlgorithm,

    /// The token audience is not acceptable
    #[error("invalid audience")]
    InvalidAudience,

    /// The token issuer is not acceptable
    #[error("invalid issuer")]
    InvalidIssuer,

    /// The token audience is not acceptable
    #[error("invalid subject")]
    InvalidSubject,

    /// The token is expired according to the `exp` claim
    #[error("token expired")]
    TokenExpired,

    /// The token is not yet valid according to the `nbf` claim
    #[error("token not yet valid")]
    TokenNotYetValid,

    /// A required claim is missing
    #[error("required {_0} claim missing")]
    MissingRequiredClaim(&'static str),

    /// Custom validation error
    #[error(transparent)]
    Custom(Box<dyn StdError + Send + Sync>),
}
