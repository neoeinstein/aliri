//! Warp filters for validating JWTs against OAuth2 authorities and scopes

use aliri::{jwt, Jwt};
use aliri_oauth2::{Authority, AuthorityError, HasScopes, ScopesPolicy};
use serde::Deserialize;
use thiserror::Error;
use warp::Filter;

/// An error during JWT verification
#[derive(Debug, Error)]
#[error("error verifying jwt")]
pub struct AuthFailed(#[from] pub AuthorityError);

impl warp::reject::Reject for AuthFailed {}

/// Require the JWT to be valid according to the JWKS authority and scope
/// scopesets
pub fn require_scopes<C, F, P>(
    jwt: F,
    authority: Authority,
    policy: P,
) -> impl Filter<Extract = (C,), Error = warp::Rejection> + Clone
where
    C: for<'de> Deserialize<'de> + jwt::CoreClaims + HasScopes,
    F: Filter<Extract = (Jwt,), Error = warp::Rejection> + Clone,
    P: AsRef<ScopesPolicy> + Clone + Send + Sync + 'static,
{
    jwt.and_then(move |jwt: Jwt| {
        let authority = authority.clone();
        let policy = policy.clone();
        async move {
            let result = authority
                .verify_token(&jwt, policy.as_ref())
                .map_err(AuthFailed);
            result.map_err(warp::reject::custom)
        }
    })
}
