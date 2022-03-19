use crate::oauth2::VerifyScopes;
use crate::DefaultErrorHandler;
use aliri::error::JwtVerifyError;
use aliri::Jwt;
use aliri_oauth2::oauth2::HasScope;
use aliri_oauth2::{Authority, AuthorityError, ScopePolicy};
use http::{Request, Response, StatusCode};
use http_body::Body;
use std::fmt;
use std::marker::PhantomData;
use tower_http::auth::AuthorizeRequest;

/// Authorizer that verifies the validity of a JWT
///
/// The JWT will be parsed from the request `Authorization` header and
/// checked for validity by an [`Authority`].
///
/// The extracted `Claims` in the JWT payload will be made available through
/// request extensions.
pub struct VerifyJwt<Claims, OnError> {
    authority: Authority,
    on_error: OnError,
    _claim: PhantomData<fn() -> Claims>,
}

impl<Claims, OnError> Clone for VerifyJwt<Claims, OnError>
where
    OnError: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            authority: self.authority.clone(),
            on_error: self.on_error.clone(),
            _claim: PhantomData,
        }
    }
}

impl<Claims, OnError> fmt::Debug for VerifyJwt<Claims, OnError>
where
    OnError: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VerifyJwt")
            .field("authority", &self.authority)
            .field("on_error", &self.on_error)
            .finish()
    }
}

impl<Claims, ResBody> VerifyJwt<Claims, DefaultErrorHandler<ResBody>> {
    /// Constructs a new JWT verifier from an authority
    #[inline]
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            on_error: DefaultErrorHandler::<ResBody>::new(),
            _claim: PhantomData,
        }
    }

    /// Attaches a custom error handler to generate responses
    /// in the event of a verification failure
    #[inline]
    pub fn with_error_handler<OnError>(self, on_error: OnError) -> VerifyJwt<Claims, OnError> {
        VerifyJwt {
            authority: self.authority,
            on_error,
            _claim: self._claim,
        }
    }
}

impl<Claims, OnError> VerifyJwt<Claims, OnError> {
    /// Generate a scopes verifier with the given scope policy
    ///
    /// This function is a convenience which helps ensure the `Claims`
    /// object extracted by the JWT verifier is what will be expected
    /// by the scopes verifier
    pub fn scopes_verifier<ResBody>(
        &self,
        policy: ScopePolicy,
    ) -> VerifyScopes<Claims, DefaultErrorHandler<ResBody>> {
        VerifyScopes::new(policy)
    }
}

impl<Claims, OnError> VerifyJwt<Claims, OnError>
where
    OnError: OnJwtError,
    OnError::Body: Body + Default,
{
    fn handle_jwt_invalid(&self, error: AuthorityError) -> Response<OnError::Body> {
        match error {
            AuthorityError::UnknownKeyId => self.on_error.on_no_matching_jwk(),
            AuthorityError::JwtVerifyError(err) => self.on_error.on_jwt_invalid(err),
            AuthorityError::PolicyDenial(_) => {
                unreachable!("called only when policy is set to allow all")
            }
        }
    }
}

impl<Claims, OnError, ReqBody> AuthorizeRequest<ReqBody> for VerifyJwt<Claims, OnError>
where
    OnError: OnJwtError,
    OnError::Body: Body + Default,
    Claims: for<'de> serde::Deserialize<'de>
        + HasScope
        + aliri::jwt::CoreClaims
        + Send
        + Sync
        + 'static,
{
    type ResponseBody = OnError::Body;

    fn authorize(
        &mut self,
        request: &mut Request<ReqBody>,
    ) -> Result<(), Response<Self::ResponseBody>> {
        let jwt = if let Some(jwt) = request.extensions().get::<Jwt>() {
            tracing::trace!("found cached jwt");
            jwt
        } else {
            tracing::trace!("extracting jwt from headers");
            let jwt = request
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(extract_jwt)
                .ok_or_else(|| self.on_error.on_missing_or_malformed())?;

            let _ = request.extensions_mut().insert(jwt);
            request
                .extensions()
                .get::<Jwt>()
                .expect("jwt was just inserted")
        };

        let claims = self
            .authority
            .verify_token::<Claims>(jwt, &ScopePolicy::allow_all())
            .map_err(|err| self.handle_jwt_invalid(err))?;

        let _ = request.extensions_mut().insert(claims);

        tracing::trace!("jwt was valid");

        Ok(())
    }
}

/// Handler for responding to failures while verifying a JWT
pub trait OnJwtError {
    /// The body type returned on an error
    type Body;

    /// Response when the JWT was not found or was otherwise malformed
    fn on_missing_or_malformed(&self) -> Response<Self::Body>;

    /// Response when the JWT names a JWK that was not found in the authority
    fn on_no_matching_jwk(&self) -> Response<Self::Body>;

    /// Response when the JWT was rejected by the authority as invalid
    fn on_jwt_invalid(&self, error: JwtVerifyError) -> Response<Self::Body>;
}

/// Returns a 401 Unauthorized response with an empty body in all cases
impl<ResBody> OnJwtError for DefaultErrorHandler<ResBody>
where
    ResBody: Body + Default,
{
    type Body = ResBody;

    #[inline]
    fn on_missing_or_malformed(&self) -> Response<Self::Body> {
        unauthorized()
    }

    #[inline]
    fn on_no_matching_jwk(&self) -> Response<Self::Body> {
        unauthorized()
    }

    #[inline]
    fn on_jwt_invalid(&self, _: JwtVerifyError) -> Response<Self::Body> {
        unauthorized()
    }
}

fn extract_jwt(auth: &str) -> Option<Jwt> {
    if auth.len() <= 7 || !auth[..7].eq_ignore_ascii_case("bearer ") {
        return None;
    }

    Some(Jwt::new(auth[7..].trim()))
}

fn unauthorized<T: Body + Default>() -> Response<T> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(T::default())
        .expect("response to build successfully")
}
