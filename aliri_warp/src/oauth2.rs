//! Warp filters for validating JWTs against OAuth2 authorities and scopes

use aliri::Authority;
use aliri_jose::Jwt;
use aliri_oauth2::{Directive, HasScopes, JwksAuthority};
use thiserror::Error;
use warp::Filter;

/// Unspecified error verifying the JWT
#[derive(Debug, Error)]
#[error("error verifying jwt")]
pub struct Unspecified(#[from] anyhow::Error);

impl warp::reject::Reject for Unspecified {}

async fn check_jwt<C: for<'de> serde::Deserialize<'de> + HasScopes>(
    jwt: Jwt,
    authority: &JwksAuthority,
    directives: &[Directive],
) -> Result<C, Unspecified> {
    let c: C = authority.verify(&jwt, &directives).await?;
    Ok(c)
}

/// Require the JWT to be valid according to the JWKS authority and scope
/// directives
pub fn require_scopes<C, F, A, D, G>(
    jwt: F,
    authority: A,
    directives: D,
) -> impl Filter<Extract = (C,), Error = warp::reject::Rejection> + Clone
where
    C: for<'de> serde::Deserialize<'de> + HasScopes,
    F: Filter<Extract = (Jwt,), Error = warp::reject::Rejection> + Clone,
    A: AsRef<JwksAuthority> + Clone + Send + Sync + 'static,
    D: AsRef<G> + Clone + Send + Sync + 'static,
    G: AsRef<[Directive]> + Send + Sync + 'static,
{
    jwt.and_then(move |jwt: Jwt| {
        let authority = authority.clone();
        let directives = directives.clone();
        async move {
            check_jwt(jwt, authority.as_ref(), directives.as_ref().as_ref())
                .await
                .map_err(warp::reject::custom)
        }
    })
}
