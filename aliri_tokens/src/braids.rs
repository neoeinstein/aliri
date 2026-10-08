use std::fmt;

use aliri_braid::braid;

macro_rules! limited_reveal {
    ($ty:ty: $hidden:literal, $default:literal) => {
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                if f.alternate() {
                    f.write_str("\"")?;
                    limited_reveal(&self.0, &mut *f, $default)?;
                    f.write_str("\"")
                } else {
                    f.write_str(concat!("***", $hidden, "***"))
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                if f.alternate() {
                    limited_reveal(&self.0, &mut *f, usize::MAX)
                } else {
                    f.write_str(concat!("***", $hidden, "***"))
                }
            }
        }
    };
}

fn limited_reveal(unprotected: &str, f: &mut fmt::Formatter, default_len: usize) -> fmt::Result {
    let max_len = f.width().unwrap_or(default_len);
    if max_len <= 1 {
        f.write_str("…")
    } else if max_len > unprotected.len() {
        f.write_str(unprotected)
    } else {
        match unprotected.char_indices().nth(max_len - 2) {
            Some((idx, c)) if idx + c.len_utf8() < unprotected.len() => {
                f.write_str(&unprotected[0..idx + c.len_utf8()])?;
                f.write_str("…")
            }
            _ => f.write_str(unprotected),
        }
    }
}

/// A client ID
#[braid(serde)]
pub struct ClientId;

/// A client secret
#[braid(serde, debug = "owned", display = "owned", ord = "omit")]
pub struct ClientSecret;

limited_reveal!(ClientSecretRef: "CLIENT SECRET", 5);

// /// An OAuth2 authorization code
// #[braid(serde)]
// pub struct AuthorizationCode;
//
// /// An OAuth2 proof key, used for the authorization code with PKCE flow
// #[braid(serde, debug_impl = "owned", display_impl = "owned")]
// pub struct ProofKey;
//
// limited_reveal!(ProofKeyRef: "PROOF KEY", 5);
//
// /// A device code
// #[braid(serde)]
// pub struct DeviceCode;
//
/// An OAuth2 scope request
///
/// A space-delimited, case-sensitive list of scope tokens, as described by
/// [RFC 6749 §3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3).
///
/// An authority is free to grant less than what was requested, so the scope on the
/// token response may be narrower than the scope on the request.
#[braid(serde)]
pub struct Scope;

impl Scope {
    /// Builds a scope request out of individual scope tokens, delimiting them with spaces
    ///
    /// Returns `None` if the iterator yields no tokens, as an OAuth2 request either
    /// carries a non-empty scope or omits the parameter entirely.
    pub fn from_tokens<I>(tokens: I) -> Option<Self>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut joined = String::new();
        for token in tokens {
            if !joined.is_empty() {
                joined.push(' ');
            }
            joined.push_str(token.as_ref());
        }

        if joined.is_empty() {
            None
        } else {
            Some(Self::new(joined))
        }
    }
}

impl ScopeRef {
    /// Iterates over the individual scope tokens
    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        self.as_str().split(' ').filter(|t| !t.is_empty())
    }
}

/// An access token
#[braid(serde, debug = "owned", display = "owned", ord = "omit")]
pub struct AccessToken;

limited_reveal!(AccessTokenRef: "ACCESS TOKEN", 15);

/// An OAuth2 ID token
#[braid(serde)]
pub struct IdToken;

/// A refresh token
#[braid(serde, debug = "owned", display = "owned", ord = "omit")]
pub struct RefreshToken;

limited_reveal!(RefreshTokenRef: "REFRESH TOKEN", 5);
