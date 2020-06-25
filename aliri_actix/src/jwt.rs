//! Warp filters for extracting JSON Web Tokens (JWTs)

use actix_web::{
    dev::Payload,
    http::{header, StatusCode},
    FromRequest, HttpRequest, ResponseError,
};
use aliri_jose::{jwt, JwtRef};
use aliri_oauth2::{Authority, AuthorityError, HasScopes, ScopesPolicy};
use serde::Deserialize;
use thiserror::Error;

/// An error while attempting to extract a JWT from headers
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Error)]
pub enum JwtError {
    /// The request has a malformed authorization header
    #[error("authorization header is malformed")]
    MalformedAuthorizationHeader,

    /// The request does not have an authorization header
    #[error("authorization header missing")]
    MissingAuthorizationHeader,

    /// The authorization scheme is incorrect
    #[error("authorization scheme is not 'bearer'")]
    IncorrectAuthorizationScheme,
}

impl ResponseError for JwtError {
    fn status_code(&self) -> StatusCode {
        StatusCode::UNAUTHORIZED
    }
}

/// An error during JWT verification
#[derive(Debug, Error)]
pub enum AuthFailed {
    /// The JWT was missing or otherwise unable to be extracted from the request
    #[error(transparent)]
    JwtError(#[from] JwtError),

    /// The token was deficient in some way
    #[error(transparent)]
    VerificationError(#[from] AuthorityError),

    /// The server is missing an authority to authenticate the request
    #[error("missing token authority")]
    MissingAuthority,
}

impl ResponseError for AuthFailed {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::JwtError(err) => err.status_code(),
            Self::VerificationError(err) => match err {
                AuthorityError::PolicyDenial(_) => StatusCode::FORBIDDEN,
                _ => StatusCode::UNAUTHORIZED,
            },
            Self::MissingAuthority => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// A configuration for evaluating request authorization against a certain
/// scopes policy
#[derive(Debug)]
pub struct OAuth2Config {
    policy: ScopesPolicy,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            policy: ScopesPolicy::allow_all(),
        }
    }
}

impl OAuth2Config {
    /// Constructs a new configuration from a scopes policy
    pub fn new(policy: ScopesPolicy) -> Self {
        Self { policy }
    }
}

fn get_jwt_from_req(request: &HttpRequest) -> Result<&JwtRef, JwtError> {
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or(JwtError::MissingAuthorizationHeader)?
        .to_str()
        .map_err(|_| JwtError::MalformedAuthorizationHeader)?;

    if authorization.len() > 7 && (&authorization[0..7]).eq_ignore_ascii_case("bearer ") {
        Ok(JwtRef::from_str(&authorization[7..]))
    } else {
        Err(JwtError::IncorrectAuthorizationScheme)
    }
}

fn from_req_inner<C>(request: &HttpRequest) -> Result<Claims<C>, AuthFailed>
where
    C: for<'de> Deserialize<'de> + HasScopes + 'static,
{
    let tmp;
    let authority = request
        .app_data::<Authority>()
        .ok_or(AuthFailed::MissingAuthority)?;
    let config = if let Some(cfg) = request.app_data::<OAuth2Config>() {
        cfg
    } else {
        tmp = OAuth2Config::default();
        &tmp
    };

    let token: &JwtRef = get_jwt_from_req(request)?;

    let claims: jwt::Claims<C> = authority.verify_token(token, &config.policy)?;

    Ok(Claims(claims))
}

/// An extractor for a JWT claims payload
#[derive(Debug)]
pub struct Claims<C>(pub jwt::Claims<C>);

impl<C> FromRequest for Claims<C>
where
    C: for<'de> Deserialize<'de> + HasScopes + 'static,
{
    type Error = AuthFailed;
    type Future = futures::future::Ready<Result<Self, Self::Error>>;
    type Config = OAuth2Config;
    fn from_request(request: &HttpRequest, _: &mut Payload) -> Self::Future {
        futures::future::ready(from_req_inner(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App, HttpResponse};
    use aliri_core::base64::Base64Url;
    use aliri_jose::{jwa, jwk, Jwk, Jwks};
    use aliri_oauth2::Scopes;
    use color_eyre::Result;

    #[derive(Clone, Debug, Deserialize)]
    struct ScopeClaims {
        #[serde(rename = "scope")]
        scopes: Scopes,
    }

    impl HasScopes for ScopeClaims {
        fn scopes(&self) -> &Scopes {
            &self.scopes
        }
    }

    #[actix_rt::test]
    async fn test_with_missing_authority() -> Result<()> {
        let mut app = test::init_service(App::new().service(
            web::resource("/test").to(|_: Claims<ScopeClaims>| async { HttpResponse::Ok() }),
        ))
        .await;

        let req = test::TestRequest::with_uri("/test").to_request();

        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    }

    #[actix_rt::test]
    async fn test_with_no_scopes() -> Result<()> {
        let jwk = Jwk::from(jwa::Hmac::new(Base64Url::from_encoded(
            "your-512-bit-secrets",
        )?))
        .with_key_id(jwk::KeyId::from("test"))
        .with_algorithm(jwa::Algorithm::HS512);
        let mut jwks = Jwks::default();
        jwks.add_key(jwk.clone());

        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20vIiwiYXVkIjoiaHR0cHM6Ly9hcGkucmVzb3VyY2UuY29tLyIsInNjb3BlIjoidGVzdCJ9.I3flhtZWU6BrNq6DDP92qph-JLruAVh3C19BunkJx4bc_zw3l95FdQReU3qmcnH6z5M2xX8kmXJ1Mz4eDMwl5w";

        let validator = jwt::CoreValidator::default()
            .ignore_expiration()
            .require_issuer(jwt::Issuer::new("https://issuer.example.com/"))
            .add_approved_algorithm(jwa::Algorithm::HS512)
            .add_allowed_audience(jwt::Audience::new("https://api.resource.com/"));

        let authority = Authority::new(jwks, validator);
        let mut app = test::init_service(App::new().app_data(authority).service(
            web::resource("/test").to(|_: Claims<ScopeClaims>| async { HttpResponse::Ok() }),
        ))
        .await;

        let req = test::TestRequest::with_uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .to_request();

        let mut resp = test::call_service(&mut app, req).await;
        println!("{:?}", resp.response());
        println!(
            "{}",
            std::str::from_utf8(test::load_stream(resp.take_body()).await.unwrap().as_ref())?
        );
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }

    #[actix_rt::test]
    async fn test_with_missing_scopes() -> Result<()> {
        let jwk = Jwk::from(jwa::Hmac::new(Base64Url::from_encoded(
            "your-512-bit-secrets",
        )?))
        .with_key_id(jwk::KeyId::from("test"))
        .with_algorithm(jwa::Algorithm::HS512);
        let mut jwks = Jwks::default();
        jwks.add_key(jwk.clone());

        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20vIiwiYXVkIjoiaHR0cHM6Ly9hcGkucmVzb3VyY2UuY29tLyIsInNjb3BlIjoidGVzdCJ9.I3flhtZWU6BrNq6DDP92qph-JLruAVh3C19BunkJx4bc_zw3l95FdQReU3qmcnH6z5M2xX8kmXJ1Mz4eDMwl5w";

        let validator = jwt::CoreValidator::default()
            .ignore_expiration()
            .require_issuer(jwt::Issuer::new("https://issuer.example.com/"))
            .add_approved_algorithm(jwa::Algorithm::HS512)
            .add_allowed_audience(jwt::Audience::new("https://api.resource.com/"));

        let authority = Authority::new(jwks, validator);
        let mut app = test::init_service(
            App::new().service(
                web::resource("/test")
                    .app_data(authority)
                    .app_data(OAuth2Config::new(ScopesPolicy::allow_one(Scopes::single(
                        "missing",
                    ))))
                    .to(|_: Claims<ScopeClaims>| async { HttpResponse::Ok() }),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .to_request();

        let mut resp = test::call_service(&mut app, req).await;
        println!("{:?}", resp.response());
        println!(
            "{}",
            std::str::from_utf8(test::load_stream(resp.take_body()).await.unwrap().as_ref())?
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[actix_rt::test]
    async fn test_with_matching_scopes() -> Result<()> {
        let jwk = Jwk::from(jwa::Hmac::new(Base64Url::from_encoded(
            "your-512-bit-secrets",
        )?))
        .with_key_id(jwk::KeyId::from("test"))
        .with_algorithm(jwa::Algorithm::HS512);
        let mut jwks = Jwks::default();
        jwks.add_key(jwk.clone());

        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20vIiwiYXVkIjoiaHR0cHM6Ly9hcGkucmVzb3VyY2UuY29tLyIsInNjb3BlIjoidGVzdCJ9.I3flhtZWU6BrNq6DDP92qph-JLruAVh3C19BunkJx4bc_zw3l95FdQReU3qmcnH6z5M2xX8kmXJ1Mz4eDMwl5w";

        let validator = jwt::CoreValidator::default()
            .ignore_expiration()
            .require_issuer(jwt::Issuer::new("https://issuer.example.com/"))
            .add_approved_algorithm(jwa::Algorithm::HS512)
            .add_allowed_audience(jwt::Audience::new("https://api.resource.com/"));

        let authority = Authority::new(jwks, validator);
        let mut app = test::init_service(
            App::new().app_data(authority.clone()).service(
                web::resource("/test")
                    .app_data(authority)
                    .app_data(OAuth2Config::new(ScopesPolicy::allow_one(Scopes::single(
                        "test",
                    ))))
                    .to(|_: Claims<ScopeClaims>| async { HttpResponse::Ok() }),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/test")
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .to_request();

        let mut resp = test::call_service(&mut app, req).await;
        println!("{:?}", resp.response());
        println!(
            "{}",
            std::str::from_utf8(test::load_stream(resp.take_body()).await.unwrap().as_ref())?
        );
        assert_eq!(resp.status(), StatusCode::OK);
        Ok(())
    }
}
