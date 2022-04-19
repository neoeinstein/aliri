//! Utilities for generating HTTP responses on authorization falures

use aliri_oauth2::{Scope, ScopePolicy};
use http::{header, response, Response, StatusCode};

/// Build a `401 Unauthorized` response with the appropriate `www-authenticate` header
///
/// The prepared builder will have the form:
///
/// ```http
/// HTTP/1.1 401 Unauthorized
/// www-authenticate: Bearer error="invalid_token" error_description="{description}"
/// ```
pub fn unauthorized(description: &str) -> response::Builder {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, invalid_token(description))
}

/// Build a `403 Forbidden` response with the appropriate `www-authenticate` header
///
/// When no policy is given, the prepared builder will have the form:
///
/// ```http
/// HTTP/1.1 403 Forbidden
/// www-authenticate: Bearer error="insufficient_scopes" error_description="{description}"
/// ```
///
/// If a `policy` is given, then a `www-authenticate` header will be added for each
/// scope alternative allowed by the policy.
///
/// ```http
/// HTTP/1.1 403 Forbidden
/// www-authenticate: Bearer error="insufficient_scopes" error_description="{description}" scope="get_user"
/// www-authenticate: Bearer error="insufficient_scopes" error_description="{description}" scope="admin"
/// ```
pub fn forbidden(description: &str, policy: Option<&ScopePolicy>) -> response::Builder {
    let mut builder = Response::builder().status(StatusCode::FORBIDDEN);

    match policy {
        Some(policy) if policy != &ScopePolicy::deny_all() => {
            for scope in policy {
                builder = builder.header(
                    http::header::WWW_AUTHENTICATE,
                    insufficient_scope(description, scope),
                );
            }
        }
        _ => {
            builder = builder.header(
                http::header::WWW_AUTHENTICATE,
                insufficient_scope_no_policy(description),
            );
        }
    }

    builder
}

fn invalid_token(description: &str) -> String {
    format!(
        r#"Bearer error="invalid_token" error_description="{}""#,
        description.replace('\\', "\\\\").replace('"', "\\\"")
    )
}

fn insufficient_scope(description: &str, scope: &Scope) -> String {
    format!(
        r#"Bearer error="insufficient_scope" error_description="{}" scope="{scope}""#,
        description.replace('"', "\\\"")
    )
}

fn insufficient_scope_no_policy(description: &str) -> String {
    format!(
        r#"Bearer error="insufficient_scope" error_description="{}""#,
        description.replace('\\', "\\\\").replace('"', "\\\"")
    )
}
