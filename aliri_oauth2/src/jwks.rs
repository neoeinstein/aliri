//! OAuth2 authorities using JWTs and JWKs to validate access

mod local;
#[cfg(feature = "reqwest")]
mod remote;

pub use local::LocalAuthority;
#[cfg(feature = "reqwest")]
pub use remote::RemoteAuthority;
