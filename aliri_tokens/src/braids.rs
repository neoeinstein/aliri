use aliri_braid::braid;
use std::fmt;

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
#[braid(serde, debug_impl = "owned", display_impl = "owned")]
pub struct ClientSecret;

limited_reveal!(ClientSecretRef: "CLIENT SECRET", 5);

// /// An OAuth2 authorization code
// #[braid(serde)]
// pub struct AuthorizationCode;
//
// /// An OAuth2 proof key, used for the authorizaiton code with PKCE flow
// #[braid(serde, debug_impl = "owned", display_impl = "owned")]
// pub struct ProofKey;
//
// limited_reveal!(ProofKeyRef: "PROOF KEY", 5);
//
// /// A device code
// #[braid(serde)]
// pub struct DeviceCode;
//
/// An access token
#[braid(serde, debug_impl = "owned", display_impl = "owned")]
pub struct AccessToken;

limited_reveal!(AccessTokenRef: "ACCESS TOKEN", 15);

/// An OAuth2 ID token
#[braid(serde)]
pub struct IdToken;

/// A refresh token
#[braid(serde, debug_impl = "owned", display_impl = "owned")]
pub struct RefreshToken;

limited_reveal!(RefreshTokenRef: "REFRESH TOKEN", 5);
