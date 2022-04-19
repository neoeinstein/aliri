use crate::util::unauthorized;
use crate::DefaultErrorHandler;
use aliri::error::JwtVerifyError;
use aliri::jwt::CoreClaims;
use aliri::Jwt;
use aliri_oauth2::oauth2::HasScope;
use aliri_oauth2::{Authority, AuthorityError, ScopePolicy};
use http::{Request, Response};
use http_body::Body;
use std::fmt;
use std::marker::PhantomData;
use tower_http::auth::AuthorizeRequest;

pub(crate) struct VerifyJwt<Claims, OnError> {
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

impl<Claims, OnError> VerifyJwt<Claims, OnError> {
    #[inline]
    pub(crate) fn new(authority: Authority, on_error: OnError) -> Self {
        Self {
            authority,
            on_error,
            _claim: PhantomData,
        }
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
    Claims: for<'de> serde::Deserialize<'de> + HasScope + CoreClaims + Send + Sync + 'static,
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

macro_rules! delegate_impls {
    ($($ty:ty)*) => {
        $(
            impl<T> OnJwtError for $ty
            where
                T: OnJwtError,
            {
                type Body = T::Body;

                fn on_missing_or_malformed(&self) -> Response<Self::Body> {
                    T::on_missing_or_malformed(self)
                }

                fn on_no_matching_jwk(&self) -> Response<Self::Body> {
                    T::on_no_matching_jwk(self)
                }

                fn on_jwt_invalid(&self, error: JwtVerifyError) -> Response<Self::Body> {
                    T::on_jwt_invalid(self, error)
                }
            }
        )*
    }
}

delegate_impls!(
    &'_ T
    Box<T>
    std::rc::Rc<T>
    std::sync::Arc<T>
);

/// Returns a 401 Unauthorized response with an empty body in all cases
impl<ResBody> OnJwtError for DefaultErrorHandler<ResBody>
where
    ResBody: Default,
{
    type Body = ResBody;

    #[inline]
    fn on_missing_or_malformed(&self) -> Response<Self::Body> {
        unauthorized("authorization token is missing or malformed")
    }

    #[inline]
    fn on_no_matching_jwk(&self) -> Response<Self::Body> {
        unauthorized("token signing key (kid) is not trusted")
    }

    #[inline]
    fn on_jwt_invalid(&self, _: JwtVerifyError) -> Response<Self::Body> {
        unauthorized("token is not valid")
    }
}

fn extract_jwt(auth: &str) -> Option<Jwt> {
    if auth.len() <= 7 || !auth[..7].eq_ignore_ascii_case("bearer ") {
        return None;
    }

    Some(Jwt::new(auth[7..].trim()))
}
