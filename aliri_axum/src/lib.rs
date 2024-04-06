//! Axum utilities that make it easier to enforce OAuth2 authorization scopes in
//! your application.
//!
//! # Full Example
//!
//! ```no_run
//! use aliri::jwt;
//! use aliri_clock::UnixTime;
//! use aliri_oauth2::{Authority, HasScope, Scope};
//! use aliri_tower::Oauth2Authorizer;
//! use axum::{
//!     extract::Path,
//!     http::StatusCode,
//!     response::{IntoResponse, Response},
//!     routing::{get, post},
//!     Router,
//! };
//! use std::net::SocketAddr;
//! use serde::Deserialize;
//!
//! #[derive(Clone, Debug, Deserialize)]
//! pub struct CustomClaims {
//!     iss: jwt::Issuer,
//!     aud: jwt::Audiences,
//!     sub: jwt::Subject,
//!     scope: Scope,
//! }
//!
//! impl jwt::CoreClaims for CustomClaims {
//!     fn nbf(&self) -> Option<UnixTime> { None }
//!     fn exp(&self) -> Option<UnixTime> { None }
//!     fn aud(&self) -> &jwt::Audiences { &self.aud }
//!     fn iss(&self) -> Option<&jwt::IssuerRef> { Some(&self.iss) }
//!     fn sub(&self) -> Option<&jwt::SubjectRef> { Some(&self.sub) }
//! }
//!
//! impl HasScope for CustomClaims {
//!     fn scope(&self) -> &Scope {
//!        &self.scope
//!     }
//! }
//!
//! mod scope {
//!     aliri_axum::scope_guards! {
//!         type Claims = super::CustomClaims;
//!
//!         pub scope AdminOnly = "admin";
//!         pub scope List = "list";
//!         pub scope Read = "read";
//!         pub scope Write = "write";
//!         pub scope ReadWrite = "read write";
//!         pub scope ReadOrList = ["read" || "list"];
//!     }
//! }
//!
//! async fn admin_action(guard: scope::AdminOnly) -> String {
//!     format!("You're an admin, {}!", guard.claims().sub)
//! }
//!
//! async fn create_resource(_: scope::Write) -> Response {
//!     (StatusCode::CREATED, "Created resource").into_response()
//! }
//!
//! async fn read_resource(
//!     scope::Read(claims): scope::Read,
//!     Path(id): Path<String>,
//! ) -> String {
//!     format!("{} read resource {id}", claims.sub)
//! }
//!
//! async fn construct_authority() -> Result<Authority, Box<dyn std::error::Error>> {
//!     // Construct an authority
//! #   todo!()
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let authority = construct_authority().await?;
//!     let authorizer = Oauth2Authorizer::new()
//!         .with_claims::<CustomClaims>()
//!         .with_terse_error_handler();
//!     // For verbose error handling, use `with_verbose_error_handler()`
//!     // or your own custom handler.
//!
//!     // Build the router
//!     let router = Router::new()
//!         .route("/admin", get(admin_action))
//!         .route("/resource", post(create_resource))
//!         .route("/resource/{id}", get(read_resource))
//!         .layer(authorizer.jwt_layer(authority));
//!     // For verbose scope errors, add the following layer:
//!     // .layer(axum::Extension(aliri_axum::VerboseAuthxErrors));
//!
//!     // Construct the server
//!     let listener = tokio::net::TcpListener::bind(&SocketAddr::new([0, 0, 0, 0].into(), 3000))
//!         .await?;
//!     axum::serve(listener, router).await?;
//!
//!     Ok(())
//! }
//! ```

use std::{error::Error, fmt};

use aliri_oauth2::{HasScope, ScopePolicy};
use axum_core::response::{IntoResponse, Response};
use http::StatusCode;

mod macros;

/// Defines a scope policy for a given endpoint guard
pub trait EndpointScopePolicy {
    /// The claims structure to extract from the request extensions and return if authorized
    type Claims: HasScope;

    /// The scope policy to be enforced when this type is used as an endpoint guard
    fn scope_policy() -> &'static ScopePolicy;
}

/// An error indicating that the request could not be authorized
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthFailed {
    /// The server is missing the token claims expected to verify the request
    MissingClaims,

    /// The claims included in the token did not satisfy the scope policy
    ///
    /// If a policy is specified, then the error response will include a list
    /// of the allowable scopes.
    InsufficientScopes {
        policy: Option<&'static ScopePolicy>,
    },
}

impl fmt::Display for AuthFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::fmt::Write;
        match self {
            AuthFailed::MissingClaims => f.write_str("token claims missing"),
            AuthFailed::InsufficientScopes { policy: None } => f.write_str("insufficient scopes"),
            AuthFailed::InsufficientScopes {
                policy: Some(policy),
            } => {
                f.write_str("insufficient scopes; one of the following scopes is required: [")?;
                let mut scopes = policy.into_iter();
                let mut maybe_scope = scopes.next();
                while let Some(scope) = maybe_scope {
                    let next = scopes.next();

                    write!(f, "{}{}", scope, if next.is_some() { ", " } else { "" })?;
                    maybe_scope = next;
                }
                f.write_char(']')
            }
        }
    }
}

impl Error for AuthFailed {}

impl IntoResponse for AuthFailed {
    fn into_response(self) -> Response {
        match self {
            AuthFailed::MissingClaims => {
                (StatusCode::INTERNAL_SERVER_ERROR, "token claims missing").into_response()
            }
            AuthFailed::InsufficientScopes { policy: None } => {
                (StatusCode::FORBIDDEN, "insufficient scopes").into_response()
            }
            AuthFailed::InsufficientScopes {
                policy: Some(policy),
            } => {
                let mut message = String::new();
                message.push_str("insufficient scopes; one of the following scopes is required: [");
                let mut scopes = policy.into_iter();
                let mut maybe_scope = scopes.next();
                while let Some(scope) = maybe_scope {
                    use std::fmt::Write;
                    let next = scopes.next();

                    write!(
                        message,
                        "{}{}",
                        scope,
                        if next.is_some() { ", " } else { "" }
                    )
                    .expect("writing to string");
                    maybe_scope = next;
                }
                message.push(']');

                (StatusCode::FORBIDDEN, message).into_response()
            }
        }
    }
}

/// Add this type as an extension to produce verbose errors when
/// authentication or authorization fails
///
/// When this extension is not present, terse errors are produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerboseAuthxErrors;

#[doc(hidden)]
pub mod __private {
    use aliri_oauth2::HasScope;
    pub use aliri_oauth2::ScopePolicy;
    use aliri_traits::Policy;
    use http::request::Parts;
    pub use once_cell::sync::OnceCell;

    use crate::{AuthFailed, VerboseAuthxErrors};

    pub fn from_request<Claims>(
        req: &mut Parts,
        policy: &'static ScopePolicy,
    ) -> Result<Claims, AuthFailed>
    where
        Claims: HasScope + Send + Sync + 'static,
    {
        let claims = req
            .extensions
            .remove::<Claims>()
            .ok_or(AuthFailed::MissingClaims)?;

        policy.evaluate(claims.scope()).map_err(|_| {
            if req.extensions.get::<VerboseAuthxErrors>().is_some() {
                AuthFailed::InsufficientScopes {
                    policy: Some(policy),
                }
            } else {
                AuthFailed::InsufficientScopes { policy: None }
            }
        })?;

        Ok(claims)
    }
}
