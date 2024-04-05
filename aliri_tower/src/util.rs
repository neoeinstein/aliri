//! Utilities for generating HTTP responses on authorization falures

use aliri_oauth2::{Scope, ScopePolicy};
use http::{header, HeaderValue, Response, StatusCode};

/// Build a `401 Unauthorized` response with the appropriate `www-authenticate`
/// header
///
/// The description provided will be automatically escaped to make sure it
/// is header-friendly.
///
/// The prepared response will have the form:
///
/// ```http
/// HTTP/1.1 401 Unauthorized
/// www-authenticate: Bearer error="invalid_token" error_description="{description}"
/// ```
///
/// `error_description` is omitted if `description` is empty.
pub fn unauthorized<Body: Default>(description: &str) -> Response<Body> {
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, invalid_token(description));
    resp
}

/// Build a `403 Forbidden` response with the appropriate `www-authenticate` header(s)
///
/// The description provided will be automatically escaped to make sure it
/// is header-friendly.
///
/// When no policy is given, the prepared response will have the form:
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
///
/// `error_description` is omitted if `description` is empty.
pub fn forbidden<Body: Default>(description: &str, policy: Option<&ScopePolicy>) -> Response<Body> {
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::FORBIDDEN;

    match policy {
        Some(policy) if policy != &ScopePolicy::deny_all() => {
            for scope in policy {
                resp.headers_mut().append(
                    header::WWW_AUTHENTICATE,
                    insufficient_scope(description, scope),
                );
            }
        }
        _ => {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                insufficient_scope_no_policy(description),
            );
        }
    }

    resp
}

fn invalid_token(description: &str) -> HeaderValue {
    if description.is_empty() {
        HeaderValue::from_static(r#"Bearer error="invalid_token""#)
    } else {
        HeaderValue::try_from(format!(
            r#"Bearer error="invalid_token" error_description="{}""#,
            description.escape_default()
        ))
        .expect("escaped description is a valid header value")
    }
}

// Because of the definition of a `Scope`, this never needs to escape `scope`,
// as `Scope` can only be printable ASCII characters and won't include `\` or `"`.
// Thus `scope` is always usable as a valid `HeaderValue`.
fn insufficient_scope(description: &str, scope: &Scope) -> HeaderValue {
    if description.is_empty() {
        HeaderValue::try_from(format!(
            r#"Bearer error="insufficient_scope" scope="{scope}""#
        ))
        .expect("scope is always a valid header value")
    } else {
        HeaderValue::try_from(format!(
            r#"Bearer error="insufficient_scope" error_description="{}" scope="{scope}""#,
            description.escape_default()
        ))
        .expect("escaped description is a valid header value")
    }
}

fn insufficient_scope_no_policy(description: &str) -> HeaderValue {
    if description.is_empty() {
        HeaderValue::from_static(r#"Bearer error="insufficient_scope""#)
    } else {
        HeaderValue::try_from(format!(
            r#"Bearer error="insufficient_scope" error_description="{}""#,
            description.escape_default()
        ))
        .expect("escaped description is a valid header value")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use aliri_oauth2::{policy, scope};

    use super::*;

    #[test]
    fn in_unauthorized_description_unicode_and_non_printing_description_does_not_panic() {
        let resp = unauthorized::<()>(
            "\0\n\ttest™: \"Ĉu oni povas bone ŝanĝi ĉi tiu mesaĝon en respondon?\"",
        );

        let headers = extract_www_authenticate_headers(&resp);

        let expected = BTreeSet::from([
            r#"Bearer error="invalid_token" error_description="\u{0}\n\ttest\u{2122}: \"\u{108}u oni povas bone \u{15d}an\u{11d}i \u{109}i tiu mesa\u{11d}on en respondon?\"""#,
        ]);

        assert_eq!(headers, expected);
    }

    #[test]
    fn in_unauthorized_with_empty_description_doesnt_include_description() {
        let resp = unauthorized::<()>("");

        let headers = extract_www_authenticate_headers(&resp);

        let expected = BTreeSet::from([r#"Bearer error="invalid_token""#]);

        assert_eq!(headers, expected);
    }

    #[test]
    fn in_forbidden_description_unicode_and_non_printing_description_does_not_panic() {
        let resp = forbidden::<()>(
            "\0\n\ttest™: \"Ĉu oni povas bone ŝanĝi ĉi tiu mesaĝon en respondon?\"",
            Some(&ScopePolicy::allow_one_from_static("test1 test2")),
        );

        let headers = extract_www_authenticate_headers(&resp);

        let expected = BTreeSet::from([
            r#"Bearer error="insufficient_scope" error_description="\u{0}\n\ttest\u{2122}: \"\u{108}u oni povas bone \u{15d}an\u{11d}i \u{109}i tiu mesa\u{11d}on en respondon?\"" scope="test1 test2""#,
        ]);

        assert_eq!(headers, expected);
    }

    #[test]
    fn in_forbidden_with_multiple_alternatives_returns_multiple_headers() {
        let resp = forbidden::<()>(
            "descriptive error",
            Some(&policy![scope!["test1", "test2"], scope!["admin"]]),
        );

        let headers = extract_www_authenticate_headers(&resp);

        let expected = BTreeSet::from([
            r#"Bearer error="insufficient_scope" error_description="descriptive error" scope="test1 test2""#,
            r#"Bearer error="insufficient_scope" error_description="descriptive error" scope="admin""#,
        ]);

        assert_eq!(headers, expected);
    }

    #[test]
    fn in_forbidden_with_deny_all_returns_one_header_without_scope() {
        let resp = forbidden::<()>("descriptive error", Some(&policy![]));

        let headers = extract_www_authenticate_headers(&resp);

        let expected = BTreeSet::from([
            r#"Bearer error="insufficient_scope" error_description="descriptive error""#,
        ]);

        assert_eq!(headers, expected);
    }

    #[test]
    fn in_forbidden_with_empty_description_doesnt_include_description() {
        let resp = forbidden::<()>("", Some(&policy![]));

        let headers = extract_www_authenticate_headers(&resp);

        let expected = BTreeSet::from([r#"Bearer error="insufficient_scope""#]);

        assert_eq!(headers, expected);
    }

    #[test]
    fn in_forbidden_with_no_policy_returns_one_header_without_scope() {
        let resp = forbidden::<()>("descriptive error", None);

        let headers = extract_www_authenticate_headers(&resp);

        let expected = BTreeSet::from([
            r#"Bearer error="insufficient_scope" error_description="descriptive error""#,
        ]);

        assert_eq!(headers, expected);
    }

    #[test]
    fn in_forbidden_with_no_policy_and_empty_description_doesnt_include_description() {
        let resp = forbidden::<()>("", None);

        let headers = extract_www_authenticate_headers(&resp);

        let expected = BTreeSet::from([r#"Bearer error="insufficient_scope""#]);

        assert_eq!(headers, expected);
    }

    fn extract_www_authenticate_headers<B>(resp: &Response<B>) -> BTreeSet<&str> {
        resp.headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<BTreeSet<_>>()
    }
}
