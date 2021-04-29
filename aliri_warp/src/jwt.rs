//! Warp filters for extracting JSON Web Tokens (JWTs)

use aliri::Jwt;
use thiserror::Error;
use warp::Filter;

/// An error while attempting to extract a JWT from headers
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Error)]
pub enum JwtError {
    /// The request does not have an authorization header
    #[error("authorization header missing")]
    MissingAuthorizationHeader,

    /// The authorization scheme is incorrect
    #[error("authorization scheme is not 'bearer'")]
    IncorrectAuthorizationScheme,
}

impl warp::reject::Reject for JwtError {}

async fn try_extract_jwt(auth: Option<String>) -> Result<Option<Jwt>, warp::reject::Rejection> {
    if let Some(auth) = auth {
        Ok(Some(extract_jwt(auth).await?))
    } else {
        Ok(None)
    }
}

async fn extract_jwt(auth: String) -> Result<Jwt, warp::reject::Rejection> {
    if auth.len() <= 7 || !auth[..7].eq_ignore_ascii_case("bearer ") {
        return Err(warp::reject::custom(JwtError::IncorrectAuthorizationScheme));
    }

    Ok(Jwt::new(auth[7..].trim()))
}

/// Extracts a JWT token from the `Authorization` header
pub fn jwt() -> impl Filter<Extract = (Jwt,), Error = warp::reject::Rejection> + Copy {
    warp::header::optional("authorization")
        .and_then(|hdr: Option<String>| async move {
            if let Some(hdr) = hdr {
                Ok(hdr)
            } else {
                Err(warp::reject::custom(JwtError::MissingAuthorizationHeader))
            }
        })
        .and_then(extract_jwt)
}

/// Attempts to extract a JWT token from the `Authorization` header
pub fn optional() -> impl Filter<Extract = (Option<Jwt>,), Error = warp::reject::Rejection> + Copy {
    warp::header::optional("authorization").and_then(try_extract_jwt)
}
