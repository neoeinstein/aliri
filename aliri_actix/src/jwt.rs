//! Warp filters for extracting JSON Web Tokens (JWTs)

use actix_web::{
    dev::Payload,
    http::{header, StatusCode},
    FromRequest, HttpRequest, ResponseError,
};
use aliri::{jwt, JwtRef};
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

/// A trait for defining a guard to protect an endpoint based on a policy requiring certain scopes
/// to be present in the token
///
/// In order to work, an `Authority` must have been established in `actix_web`. This can be done using
/// `App::app_data()` to attach the authority for verifying tokens.
///
/// ## Examples
///
/// ```
/// use actix_web::{get, HttpResponse, Responder};
/// use aliri_actix::jwt::{ScopesGuard, Scoped};
/// use aliri::jwt;
/// use aliri_oauth2::{JustScope, Scopes, ScopesPolicy};
/// use once_cell::sync::OnceCell;
/// use serde::Deserialize;
///
/// #[derive(Debug)]
/// struct TestScope;
///
/// impl ScopesGuard for TestScope {
///     type Claims = JustScope;
///
///     #[inline]
///     fn from_claims(_: jwt::Claims<Self::Claims>) -> Self {
///         TestScope
///     }
///
///     fn scopes_policy() -> &'static ScopesPolicy {
///         static POLICY: OnceCell<ScopesPolicy> = OnceCell::new();
///         POLICY.get_or_init(|| {
///             ScopesPolicy::deny_all()
///                 .or_allow(Scopes::single("admin:all"))
///                 .or_allow(Scopes::single("admin:area"))
///                 .or_allow(Scopes::single("read:area").and("update:area"))
///                 .or_allow(Scopes::single("read:area").and("upsert:area"))
///         })
///     }
/// }
///
/// #[get("/test")]
/// async fn test_endpoint(_: Scoped<TestScope>) -> impl Responder {
///     HttpResponse::Ok()
/// }
///
/// ```
pub trait ScopesGuard: Sized {
    /// The custom claims payload, which contains the required scopes
    type Claims: for<'de> Deserialize<'de> + HasScopes + 'static;

    /// Constructs the type from the claims extracted from the authorization token
    fn from_claims(claims: jwt::Claims<Self::Claims>) -> Self;

    /// Returns the policy applied to types guarded by this scope
    ///
    /// It is recommended to construct the value a single time, and then reuse that
    /// value for the lifetime of the program. This can be done by constructing and
    /// leaking a value, or by using a lazy construction method, like `OnceCell` or
    /// `Lazy`, as in the following example.
    ///
    /// ```
    /// use aliri_oauth2::{Scopes, ScopesPolicy};
    /// use once_cell::sync::OnceCell;
    ///
    /// static POLICY: OnceCell<ScopesPolicy> = OnceCell::new();
    /// let policy_ref = POLICY.get_or_init(|| {
    ///     ScopesPolicy::deny_all()
    ///         .or_allow(Scopes::single("admin:all"))
    ///         .or_allow(Scopes::single("admin:area"))
    ///         .or_allow(Scopes::single("read:area").and("update:area"))
    ///         .or_allow(Scopes::single("read:area").and("upsert:area"))
    /// });
    /// ```
    fn scopes_policy() -> &'static ScopesPolicy;
}

fn extract_and_verify_jwt<T>(request: &HttpRequest) -> Result<Scoped<T>, AuthFailed>
where
    T: ScopesGuard,
{
    let authority = request
        .app_data::<Authority>()
        .ok_or(AuthFailed::MissingAuthority)?;

    let token: &JwtRef = get_jwt_from_req(request)?;

    let claims: jwt::Claims<T::Claims> = authority.verify_token(token, T::scopes_policy())?;

    Ok(Scoped(T::from_claims(claims)))
}

/// Convenience wrapper which implements `FromRequest` for types that implement `ScopesGuard`
#[derive(Debug)]
pub struct Scoped<T: ScopesGuard>(T);

impl<T: ScopesGuard> Scoped<T> {
    /// Borrows a reference to the inner ScopesGuard value
    pub fn inner(&self) -> &T {
        &self.0
    }

    /// Takes ownership of the inner ScopesGuard value
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> FromRequest for Scoped<T>
where
    T: ScopesGuard,
{
    type Error = AuthFailed;
    type Future = futures::future::Ready<Result<Self, Self::Error>>;
    type Config = ();
    fn from_request(request: &HttpRequest, _: &mut Payload) -> Self::Future {
        futures::future::ready(extract_and_verify_jwt(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{get, test, App, HttpResponse, Responder};
    use aliri::{jwa, jwk, Jwk, Jwks};
    use aliri_base64::Base64Url;
    use aliri_oauth2::Scopes;
    use color_eyre::Result;
    use once_cell::sync::OnceCell;

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
        let mut app = test::init_service(App::new().service(test_endpoint)).await;

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
        let mut app =
            test::init_service(App::new().app_data(authority).service(test_endpoint)).await;

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

    #[derive(Debug)]
    struct TestScope;

    impl ScopesGuard for TestScope {
        type Claims = ScopeClaims;

        #[inline]
        fn from_claims(_: jwt::Claims<Self::Claims>) -> Self {
            TestScope
        }

        fn scopes_policy() -> &'static ScopesPolicy {
            static POLICY: OnceCell<ScopesPolicy> = OnceCell::new();
            POLICY.get_or_init(|| {
                ScopesPolicy::deny_all()
                    .or_allow(Scopes::single("test"))
                    .or_allow(Scopes::single("peter").and("paul"))
                    .or_allow(Scopes::single("peter").and("steve"))
                    .or_allow(Scopes::single("roger"))
            })
        }
    }

    #[get("/test")]
    async fn test_endpoint(_: Scoped<TestScope>) -> impl Responder {
        HttpResponse::Ok()
    }

    #[actix_rt::test]
    async fn test_proc_with_matching_scopes_test() -> Result<()> {
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
        let mut app =
            test::init_service(App::new().app_data(authority).service(test_endpoint)).await;

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
    async fn test_proc_with_matching_scopes_roger() -> Result<()> {
        let jwk = Jwk::from(jwa::Hmac::new(Base64Url::from_encoded(
            "your-512-bit-secrets",
        )?))
        .with_key_id(jwk::KeyId::from("test"))
        .with_algorithm(jwa::Algorithm::HS512);
        let mut jwks = Jwks::default();
        jwks.add_key(jwk.clone());

        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20vIiwiYXVkIjoiaHR0cHM6Ly9hcGkucmVzb3VyY2UuY29tLyIsInNjb3BlIjoicm9nZXIifQ.YvjxgvSeiVStMnjzj3kIeUp_iPz9AhWMpODaVM5-rY3vbocwKNOQBf67hpj1Fnas8v4edbvqPQS_BmaifYcO1w";

        let validator = jwt::CoreValidator::default()
            .ignore_expiration()
            .require_issuer(jwt::Issuer::new("https://issuer.example.com/"))
            .add_approved_algorithm(jwa::Algorithm::HS512)
            .add_allowed_audience(jwt::Audience::new("https://api.resource.com/"));

        let authority = Authority::new(jwks, validator);
        let mut app =
            test::init_service(App::new().app_data(authority).service(test_endpoint)).await;

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
    async fn test_proc_with_matching_scopes_peter_and_paul() -> Result<()> {
        let jwk = Jwk::from(jwa::Hmac::new(Base64Url::from_encoded(
            "your-512-bit-secrets",
        )?))
        .with_key_id(jwk::KeyId::from("test"))
        .with_algorithm(jwa::Algorithm::HS512);
        let mut jwks = Jwks::default();
        jwks.add_key(jwk.clone());

        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20vIiwiYXVkIjoiaHR0cHM6Ly9hcGkucmVzb3VyY2UuY29tLyIsInNjb3BlIjoicGV0ZXIgcGF1bCJ9.yPM0wyB94ezJ03ryDuMgDwH3sBmVbyh0nG8_nDLE_ZXXI2S3686TVTrL6Fl_69cKhuvCDUrln6E2hQewUxya5Q";

        let validator = jwt::CoreValidator::default()
            .ignore_expiration()
            .require_issuer(jwt::Issuer::new("https://issuer.example.com/"))
            .add_approved_algorithm(jwa::Algorithm::HS512)
            .add_allowed_audience(jwt::Audience::new("https://api.resource.com/"));

        let authority = Authority::new(jwks, validator);
        let mut app =
            test::init_service(App::new().app_data(authority).service(test_endpoint)).await;

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
    async fn test_proc_with_matching_scopes_peter_and_steve() -> Result<()> {
        let jwk = Jwk::from(jwa::Hmac::new(Base64Url::from_encoded(
            "your-512-bit-secrets",
        )?))
        .with_key_id(jwk::KeyId::from("test"))
        .with_algorithm(jwa::Algorithm::HS512);
        let mut jwks = Jwks::default();
        jwks.add_key(jwk.clone());

        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20vIiwiYXVkIjoiaHR0cHM6Ly9hcGkucmVzb3VyY2UuY29tLyIsInNjb3BlIjoicGV0ZXIgc3RldmUifQ.Z-sTxIGo9RVASSdzub1xCafaSB1ody9Vgqn8yCcLhUEkuACyn5Bs2Da2-ZH6gw0p3yU7TLMAcZcfK1c0M1kAEg";

        let validator = jwt::CoreValidator::default()
            .ignore_expiration()
            .require_issuer(jwt::Issuer::new("https://issuer.example.com/"))
            .add_approved_algorithm(jwa::Algorithm::HS512)
            .add_allowed_audience(jwt::Audience::new("https://api.resource.com/"));

        let authority = Authority::new(jwks, validator);
        let mut app =
            test::init_service(App::new().app_data(authority).service(test_endpoint)).await;

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
    async fn test_proc_with_matching_scopes_peter_and_roger() -> Result<()> {
        let jwk = Jwk::from(jwa::Hmac::new(Base64Url::from_encoded(
            "your-512-bit-secrets",
        )?))
        .with_key_id(jwk::KeyId::from("test"))
        .with_algorithm(jwa::Algorithm::HS512);
        let mut jwks = Jwks::default();
        jwks.add_key(jwk.clone());

        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20vIiwiYXVkIjoiaHR0cHM6Ly9hcGkucmVzb3VyY2UuY29tLyIsInNjb3BlIjoicGV0ZXIgcm9nZXIifQ.PE3g-5GgkvPpD7nhX0zvt5vInefPBPQNvPoVQrtoEz3EAEmZhsiBKsnIpmROxdZHzy9XUkbOn8a3rmg5ruQQ0w";

        let validator = jwt::CoreValidator::default()
            .ignore_expiration()
            .require_issuer(jwt::Issuer::new("https://issuer.example.com/"))
            .add_approved_algorithm(jwa::Algorithm::HS512)
            .add_allowed_audience(jwt::Audience::new("https://api.resource.com/"));

        let authority = Authority::new(jwks, validator);
        let mut app =
            test::init_service(App::new().app_data(authority).service(test_endpoint)).await;

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
    async fn test_proc_with_missing_scopes_peter_and_not_paul_or_steve() -> Result<()> {
        let jwk = Jwk::from(jwa::Hmac::new(Base64Url::from_encoded(
            "your-512-bit-secrets",
        )?))
        .with_key_id(jwk::KeyId::from("test"))
        .with_algorithm(jwa::Algorithm::HS512);
        let mut jwks = Jwks::default();
        jwks.add_key(jwk.clone());

        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20vIiwiYXVkIjoiaHR0cHM6Ly9hcGkucmVzb3VyY2UuY29tLyIsInNjb3BlIjoicGV0ZXIgZ3JlZyJ9.YC-VHXjqordW8i_T82tL5queygIA61NjwiQK8VMSc54OhtceRoNy_nFb0WLUGxzMW-EVJ8YVOfwVXSUOuYGDcw";

        let validator = jwt::CoreValidator::default()
            .ignore_expiration()
            .require_issuer(jwt::Issuer::new("https://issuer.example.com/"))
            .add_approved_algorithm(jwa::Algorithm::HS512)
            .add_allowed_audience(jwt::Audience::new("https://api.resource.com/"));

        let authority = Authority::new(jwks, validator);
        let mut app =
            test::init_service(App::new().app_data(authority).service(test_endpoint)).await;

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
    async fn test_proc_with_missing_scopes_steve_but_not_peter() -> Result<()> {
        let jwk = Jwk::from(jwa::Hmac::new(Base64Url::from_encoded(
            "your-512-bit-secrets",
        )?))
        .with_key_id(jwk::KeyId::from("test"))
        .with_algorithm(jwa::Algorithm::HS512);
        let mut jwks = Jwks::default();
        jwks.add_key(jwk.clone());

        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20vIiwiYXVkIjoiaHR0cHM6Ly9hcGkucmVzb3VyY2UuY29tLyIsInNjb3BlIjoic3RldmUgZ3JlZyJ9.ZnEAIJwTlQFHwmyfgC2b4ONEsx5p9GAHUZhPi171fmqyJyJBIui2IJH4osc9Z-4hHyeEkOLQYrsjX2I2kWbBJA";

        let validator = jwt::CoreValidator::default()
            .ignore_expiration()
            .require_issuer(jwt::Issuer::new("https://issuer.example.com/"))
            .add_approved_algorithm(jwa::Algorithm::HS512)
            .add_allowed_audience(jwt::Audience::new("https://api.resource.com/"));

        let authority = Authority::new(jwks, validator);
        let mut app =
            test::init_service(App::new().app_data(authority).service(test_endpoint)).await;

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
    async fn test_proc_with_missing_scopes_paul_but_not_peter() -> Result<()> {
        let jwk = Jwk::from(jwa::Hmac::new(Base64Url::from_encoded(
            "your-512-bit-secrets",
        )?))
        .with_key_id(jwk::KeyId::from("test"))
        .with_algorithm(jwa::Algorithm::HS512);
        let mut jwks = Jwks::default();
        jwks.add_key(jwk.clone());

        let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20vIiwiYXVkIjoiaHR0cHM6Ly9hcGkucmVzb3VyY2UuY29tLyIsInNjb3BlIjoic3RldmUgZ3JlZyJ9.ZnEAIJwTlQFHwmyfgC2b4ONEsx5p9GAHUZhPi171fmqyJyJBIui2IJH4osc9Z-4hHyeEkOLQYrsjX2I2kWbBJA";

        let validator = jwt::CoreValidator::default()
            .ignore_expiration()
            .require_issuer(jwt::Issuer::new("https://issuer.example.com/"))
            .add_approved_algorithm(jwa::Algorithm::HS512)
            .add_allowed_audience(jwt::Audience::new("https://api.resource.com/"));

        let authority = Authority::new(jwks, validator);
        let mut app =
            test::init_service(App::new().app_data(authority).service(test_endpoint)).await;

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
}
