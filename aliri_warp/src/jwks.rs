use aliri_jose::{
    jwt::{self, CoreHeaders, HasSigningAlgorithm},
    Jwks, Jwt,
};
use thiserror::Error;
use warp::Filter;

#[derive(Debug, Error)]
#[error("error verifying jwt")]
pub struct Unspecified(#[from] anyhow::Error);

impl warp::reject::Reject for Unspecified {}

async fn check_jwt<C: for<'de> serde::Deserialize<'de>>(
    jwt: Jwt,
    jwks: &Jwks,
    validator: &jwt::Validation,
) -> Result<C, Unspecified> {
    let decomposed: jwt::Decomposed<jwt::Empty> = jwt.decompose()?;
    let jwk = jwks
        .get_key_by_opt(decomposed.kid(), decomposed.alg())
        .next()
        .ok_or_else(|| anyhow::anyhow!("no key found"))?;
    let v: jwt::Validated<C> = decomposed.verify(jwk, validator)?;
    let (_, c) = v.take();
    Ok(c)
}

pub fn jwks(
    jwt_source: impl Filter<Extract = (Jwt,), Error = warp::reject::Rejection> + Clone,
    jwks: impl AsRef<Jwks> + Clone + Send + Sync + 'static,
    validator: impl AsRef<jwt::Validation> + Clone + Send + Sync + 'static,
) -> impl Filter<Extract = (), Error = warp::reject::Rejection> + Clone {
    jwks_claims(jwt_source, jwks, validator)
        .map(|_: jwt::Empty| ())
        .untuple_one()
}

pub fn jwks_claims<C, F, JWKS, V>(
    jwt_source: F,
    jwks: JWKS,
    validator: V,
) -> impl Filter<Extract = (C,), Error = warp::reject::Rejection> + Clone
where
    C: for<'de> serde::Deserialize<'de>,
    F: Filter<Extract = (Jwt,), Error = warp::reject::Rejection> + Clone,
    JWKS: AsRef<Jwks> + Clone + Send + Sync + 'static,
    V: AsRef<jwt::Validation> + Clone + Send + Sync + 'static,
{
    jwt_source.and_then(move |jwt: Jwt| {
        let jwks = jwks.clone();
        let validator = validator.clone();
        async move {
            check_jwt(jwt, jwks.as_ref(), validator.as_ref())
                .await
                .map_err(warp::reject::custom)
        }
    })
}
