//! Warp filters for extracting JSON Web Tokens (JWTs)

use std::fmt;

use aliri_jose::Jwt;
use warp::Filter;

#[derive(Copy, Clone, Debug, Default, Hash, Eq, PartialEq)]
struct InvalidAuthorizationHeader;

impl warp::reject::Reject for InvalidAuthorizationHeader {}

impl fmt::Display for InvalidAuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid authorization header")
    }
}

async fn try_extract_jwt(auth: Option<String>) -> Result<Option<Jwt>, warp::reject::Rejection> {
    if let Some(auth) = auth {
        Ok(Some(extract_jwt(auth).await?))
    } else {
        Ok(None)
    }
}

async fn extract_jwt(auth: String) -> Result<Jwt, warp::reject::Rejection> {
    if auth.len() <= 7 || !auth[..7].eq_ignore_ascii_case("bearer ") {
        return Err(warp::reject::custom(InvalidAuthorizationHeader));
    }

    Ok(Jwt::new(auth[7..].trim()))
}

/// Extracts a JWT token from the `Authorization` header
pub fn jwt() -> impl Filter<Extract = (Jwt,), Error = warp::reject::Rejection> + Copy {
    warp::header("authorization").and_then(extract_jwt)
}

/// Attempts to extract a JWT token from the `Authorization` header
pub fn optional() -> impl Filter<Extract = (Option<Jwt>,), Error = warp::reject::Rejection> + Copy {
    warp::header::optional("authorization").and_then(try_extract_jwt)
}
