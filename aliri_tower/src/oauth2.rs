use crate::DefaultErrorHandler;
use aliri_oauth2::oauth2::HasScope;
use aliri_oauth2::{InsufficientScope, ScopePolicy};
use aliri_traits::Policy;
use http::{Request, Response, StatusCode};
use http_body::Body;
use std::fmt;
use std::marker::PhantomData;
use tower_http::auth::AuthorizeRequest;

/// Authorizer that checks the access granted by a scopes claim against
/// a scopes policy
///
/// The `Claims` object is expected to have already been processed by the
/// [`VerifyJwt`](crate::jwt::VerifyJwt) or been otherwise added to
/// the extensions on the [`Request`] object.
pub struct VerifyScopes<Claims, OnError> {
    policy: ScopePolicy,
    on_error: OnError,
    _claim: PhantomData<fn() -> Claims>,
}

impl<Claims, OnError> Clone for VerifyScopes<Claims, OnError>
where
    OnError: Clone,
{
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
            on_error: self.on_error.clone(),
            _claim: PhantomData,
        }
    }
}

impl<Claims, OnError> fmt::Debug for VerifyScopes<Claims, OnError>
where
    OnError: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VerifyScopes")
            .field("policy", &self.policy)
            .field("on_error", &self.on_error)
            .finish()
    }
}

impl<Claims, ResBody> VerifyScopes<Claims, DefaultErrorHandler<ResBody>> {
    /// Constructs a new scopes verifier from a scope policy
    #[inline]
    pub fn new(policy: ScopePolicy) -> Self {
        Self {
            policy,
            on_error: DefaultErrorHandler::<ResBody>::new(),
            _claim: PhantomData,
        }
    }

    /// Attaches a custom error handler to generate responses
    /// in the event of a verification failure
    #[inline]
    pub fn with_error_handler<OnError>(self, on_error: OnError) -> VerifyScopes<Claims, OnError> {
        VerifyScopes {
            policy: self.policy,
            on_error,
            _claim: self._claim,
        }
    }
}

impl<Claims, OnError, ReqBody> AuthorizeRequest<ReqBody> for VerifyScopes<Claims, OnError>
where
    OnError: OnScopesError,
    OnError::Body: Body + Default,
    Claims: HasScope + Send + Sync + 'static,
{
    type ResponseBody = OnError::Body;

    fn authorize(
        &mut self,
        request: &mut Request<ReqBody>,
    ) -> Result<(), Response<Self::ResponseBody>> {
        let scope = request
            .extensions()
            .get::<Claims>()
            .map(|c| c.scope())
            .ok_or_else(|| self.on_error.on_missing_scope_claim())?;

        tracing::trace!(scope = ?scope, policy = ?self.policy, "evaluating scopes policy");

        self.policy
            .evaluate(scope)
            .map_err(|err| self.on_error.on_scope_policy_failure(err))?;

        Ok(())
    }
}

/// Handler for responding to failures while verifying scope claims
pub trait OnScopesError {
    /// The body type returned on an error
    type Body;

    /// Response when the scope claim is missing
    ///
    /// This can also happen if the appropriate `Claim` value
    /// wasn't attached to the request prior to executing the scopes
    /// verifier.
    fn on_missing_scope_claim(&self) -> Response<Self::Body>;

    /// Response when access is rejected due to insufficient permissions
    fn on_scope_policy_failure(&self, error: InsufficientScope) -> Response<Self::Body>;
}

/// Returns a 403 Forbidden response with an empty body in all cases
impl<ResBody> OnScopesError for DefaultErrorHandler<ResBody>
where
    ResBody: Body + Default,
{
    type Body = ResBody;

    #[inline]
    fn on_missing_scope_claim(&self) -> Response<Self::Body> {
        forbidden()
    }

    #[inline]
    fn on_scope_policy_failure(&self, _: InsufficientScope) -> Response<Self::Body> {
        forbidden()
    }
}

fn forbidden<T: Body + Default>() -> Response<T> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(T::default())
        .expect("response to build successfully")
}
