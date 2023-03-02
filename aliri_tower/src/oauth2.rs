use std::{fmt, marker::PhantomData};

use aliri_oauth2::{oauth2::HasScope, Scope, ScopePolicy};
use aliri_traits::Policy;
use http::{Request, Response};
use http_body::Body;
use tower_http::validate_request::ValidateRequest;

use crate::{util::forbidden, TerseErrorHandler, VerboseErrorHandler};

pub(crate) struct VerifyScope<Claims, OnError> {
    policy: ScopePolicy,
    on_error: OnError,
    _claim: PhantomData<fn() -> Claims>,
}

impl<Claims, OnError> Clone for VerifyScope<Claims, OnError>
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

impl<Claims, OnError> fmt::Debug for VerifyScope<Claims, OnError>
where
    OnError: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VerifyScope")
            .field("policy", &self.policy)
            .field("on_error", &self.on_error)
            .finish()
    }
}

impl<Claims, OnError> VerifyScope<Claims, OnError> {
    /// Constructs a new scopes verifier with the default deny all scopes policy
    pub(crate) fn new(policy: ScopePolicy, on_error: OnError) -> Self {
        Self {
            policy,
            on_error,
            _claim: PhantomData,
        }
    }
}

impl<Claims, OnError, ReqBody> ValidateRequest<ReqBody> for VerifyScope<Claims, OnError>
where
    OnError: OnScopeError,
    OnError::Body: Body + Default,
    Claims: HasScope + Send + Sync + 'static,
{
    type ResponseBody = OnError::Body;

    fn validate(
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
            .map_err(|_| self.on_error.on_scope_policy_failure(scope, &self.policy))?;

        Ok(())
    }
}

/// Handler for responding to failures while verifying scope claims
pub trait OnScopeError {
    /// The body type returned on an error
    type Body;

    /// Response when the scope claim is missing
    ///
    /// This can also happen if the appropriate `Claim` value
    /// wasn't attached to the request prior to executing the scopes
    /// verifier.
    fn on_missing_scope_claim(&self) -> Response<Self::Body>;

    /// Response when access is rejected due to insufficient permissions
    fn on_scope_policy_failure(&self, held: &Scope, policy: &ScopePolicy) -> Response<Self::Body>;
}

macro_rules! delegate_impls {
    ($($ty:ty)*) => {
        $(
            impl<T> OnScopeError for $ty
            where
                T: OnScopeError,
            {
                type Body = T::Body;

                fn on_missing_scope_claim(&self) -> Response<Self::Body> {
                    T::on_missing_scope_claim(self)
                }

                fn on_scope_policy_failure(&self, held: &Scope, policy: &ScopePolicy) -> Response<Self::Body> {
                    T::on_scope_policy_failure(self, held, policy)
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

impl<ResBody> OnScopeError for TerseErrorHandler<ResBody>
where
    ResBody: Default,
{
    type Body = ResBody;

    #[inline]
    fn on_missing_scope_claim(&self) -> Response<Self::Body> {
        forbidden("", None)
    }

    #[inline]
    fn on_scope_policy_failure(&self, _: &Scope, policy: &ScopePolicy) -> Response<Self::Body> {
        forbidden("", Some(policy))
    }
}

impl<ResBody> OnScopeError for VerboseErrorHandler<ResBody>
where
    ResBody: Default,
{
    type Body = ResBody;

    #[inline]
    fn on_missing_scope_claim(&self) -> Response<Self::Body> {
        forbidden(
            "authorization token is missing an expected scope claim",
            None,
        )
    }

    #[inline]
    fn on_scope_policy_failure(&self, _: &Scope, policy: &ScopePolicy) -> Response<Self::Body> {
        forbidden(
            "authorization token has insufficient scope to access this endpoint",
            Some(policy),
        )
    }
}
