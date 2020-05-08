use aliri::Authority;
use aliri_jose::Jwt;
use aliri_oauth2::{Directive, HasScopes, JwksAuthority};
use thiserror::Error;
use warp::Filter;

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

pub fn jwks_auth<C, F, A, D, G>(
    jwt_source: F,
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
    jwt_source.and_then(move |jwt: Jwt| {
        let authority = authority.clone();
        let directives = directives.clone();
        async move {
            check_jwt(jwt, authority.as_ref(), directives.as_ref().as_ref())
                .await
                .map_err(warp::reject::custom)
        }
    })
}
