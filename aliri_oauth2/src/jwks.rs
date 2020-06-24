//! OAuth2 authorities using JWTs and JWKs to validate access

use thiserror::Error;

mod local;
#[cfg(feature = "reqwest")]
mod remote;

pub use local::LocalAuthority;
#[cfg(feature = "reqwest")]
pub use remote::RemoteAuthority;

/// Indicates the requestor held insufficient scopes to be granted access
/// to a controlled resource
#[derive(Debug, Error)]
pub enum AuthorityError {
    /// Indicates that the authority cannot verify the JWT because it cannot
    /// find a key which matches the specifications in the token header
    #[error("no matching key found to validate JWT")]
    UnknownKeyId,
    /// Indicates that the JWT was malformed or otherwise defective
    #[error("invalid JWT")]
    JwtVerifyError(#[from] aliri_jose::error::JwtVerifyError),
    /// Indicates that, while the JWT was acceptable, it does not grant the
    /// level of authorization requested.
    #[error("access denied by policy")]
    PolicyDenial(#[from] crate::InsufficientScopes),
}
