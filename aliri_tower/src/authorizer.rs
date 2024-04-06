use std::{fmt, marker::PhantomData};

use aliri::jwt::CoreClaims;
use aliri_oauth2::{
    scope::{BasicClaimsWithScope, HasScope},
    Authority, ScopePolicy,
};
use http_body::Body;
use tower_http::validate_request::{ValidateRequest, ValidateRequestHeaderLayer};

use crate::{OnJwtError, OnScopeError, TerseErrorHandler, VerboseErrorHandler};

/// Builder for generating layers that authenticate JWTs and authorize access
/// based on oauth2 scope grants
pub struct Oauth2Authorizer<Claims, OnError> {
    on_error: OnError,
    _claim: PhantomData<fn() -> Claims>,
}

impl<Claims, OnError> Clone for Oauth2Authorizer<Claims, OnError>
where
    OnError: Clone,
{
    fn clone(&self) -> Self {
        Self {
            on_error: self.on_error.clone(),
            _claim: PhantomData,
        }
    }
}

impl<Claims, OnError> Copy for Oauth2Authorizer<Claims, OnError> where OnError: Copy {}

impl<Claims, OnError> fmt::Debug for Oauth2Authorizer<Claims, OnError>
where
    OnError: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Authorizer")
            .field("on_error", &self.on_error)
            .finish()
    }
}

impl Oauth2Authorizer<BasicClaimsWithScope, ()> {
    /// Constructs a new scopes verifier with the default deny all scopes policy
    #[inline]
    pub fn new() -> Oauth2Authorizer<BasicClaimsWithScope, ()> {
        Self {
            on_error: (),
            _claim: PhantomData,
        }
    }
}

impl<OnError> Oauth2Authorizer<BasicClaimsWithScope, OnError> {
    /// Verification will expect the given custom claims object in request extensions
    #[inline]
    pub fn with_claims<Claims: HasScope>(self) -> Oauth2Authorizer<Claims, OnError> {
        Oauth2Authorizer {
            on_error: self.on_error,
            _claim: PhantomData,
        }
    }
}

impl<Claims> Oauth2Authorizer<Claims, ()> {
    /// Attaches a custom error handler to generate responses
    /// in the event of a verification failure
    #[inline]
    pub fn with_error_handler<OnError>(
        self,
        on_error: OnError,
    ) -> Oauth2Authorizer<Claims, OnError> {
        Oauth2Authorizer {
            on_error,
            _claim: self._claim,
        }
    }

    /// Attaches the default terse error handler: [`TerseErrorHandler`]
    ///
    /// This error handler generates responses containing the relevant
    /// status code with an empty body
    #[inline]
    pub fn with_terse_error_handler<ResBody: Body + Default>(
        self,
    ) -> Oauth2Authorizer<Claims, TerseErrorHandler<ResBody>> {
        Oauth2Authorizer {
            on_error: TerseErrorHandler::new(),
            _claim: self._claim,
        }
    }

    /// Attaches the default verbose error handler: [`VerboseErrorHandler`]
    ///
    /// This error handler generates responses containing the relevant
    /// status code with an empty body
    #[inline]
    pub fn with_verbose_error_handler<ResBody: Body + Default>(
        self,
    ) -> Oauth2Authorizer<Claims, VerboseErrorHandler<ResBody>> {
        Oauth2Authorizer {
            on_error: VerboseErrorHandler::new(),
            _claim: self._claim,
        }
    }
}

impl<Claims, OnError> Oauth2Authorizer<Claims, OnError>
where
    OnError: OnJwtError + Clone,
    OnError::Body: Body + Default,
    Claims:
        for<'de> serde::Deserialize<'de> + HasScope + CoreClaims + Clone + Send + Sync + 'static,
{
    /// Authorizer layer that verifies the validity of a JWT
    ///
    /// The JWT will be parsed from the request `Authorization` header and
    /// checked for validity by an [`Authority`].
    ///
    /// The extracted `Claims` in the JWT payload will be made available
    /// through [`Request::extensions`][http::Request::extensions].
    pub fn jwt_layer<ReqBody>(
        &self,
        authority: Authority,
    ) -> ValidateRequestHeaderLayer<
        impl ValidateRequest<ReqBody, ResponseBody = OnError::Body> + Clone,
    > {
        ValidateRequestHeaderLayer::custom(crate::jwt::VerifyJwt::<Claims, _>::new(
            authority,
            self.on_error.clone(),
        ))
    }
}

impl<Claims, OnError> Oauth2Authorizer<Claims, OnError>
where
    OnError: OnScopeError + Clone,
    OnError::Body: Body + Default,
    Claims: HasScope + Send + Sync + 'static,
{
    /// Authorizer layer that checks the access granted by a scopes claim
    /// against a scopes policy
    ///
    /// The `Claims` object is expected to have already been added to
    /// the [`Request::extensions`][http::Request::extensions].
    pub fn scope_layer<ReqBody>(
        &self,
        policy: ScopePolicy,
    ) -> ValidateRequestHeaderLayer<
        impl ValidateRequest<ReqBody, ResponseBody = OnError::Body> + Clone,
    > {
        ValidateRequestHeaderLayer::custom(crate::oauth2::VerifyScope::<Claims, _>::new(
            policy,
            self.on_error.clone(),
        ))
    }
}

impl Default for Oauth2Authorizer<BasicClaimsWithScope, ()> {
    fn default() -> Self {
        Self::new()
    }
}
