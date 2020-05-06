use std::collections::HashSet;

use aliri_core::clock::UnixTime;
use lazy_static::lazy_static;

use crate::{Audiences, CoreClaims};

#[cfg(feature = "rsa")]
pub mod rsa {
    pub const TEST_KEY_ID: &str = "EkKhyPqtd";
    pub const JWK: &str = include_str!("../data/rsa/jwk.json");
    pub const JWK_MINIMAL: &str = include_str!("../data/rsa/jwk-min.json");
    #[cfg(feature = "private-keys")]
    pub const JWK_WITH_PRIVATE_KEY: &str = include_str!("../data/rsa/jwk-priv.json");
    #[cfg(feature = "private-keys")]
    pub const JWK_WITH_MINIMAL_PRIVATE_KEY: &str = include_str!("../data/rsa/jwk-priv-min.json");

    pub const JWKS: &str = include_str!("../data/rsa/jwks.json");
}

#[cfg(feature = "ec")]
pub mod ec {
    pub const TEST_KEY_ID: &str = "VJUjkP9KO";
    pub const JWK: &str = include_str!("../data/ec/jwk.json");
    pub const JWK_MINIMAL: &str = include_str!("../data/ec/jwk-min.json");
    #[cfg(feature = "private-keys")]
    pub const JWK_WITH_PRIVATE_KEY: &str = include_str!("../data/ec/jwk-priv.json");
    #[cfg(feature = "private-keys")]
    pub const JWK_WITH_MINIMAL_PRIVATE_KEY: &str = include_str!("../data/ec/jwk-priv-min.json");
}

#[cfg(feature = "hmac")]
pub mod hmac {
    pub const TEST_KEY_ID: &str = "4y_2kKqYO";
    pub const JWK: &str = include_str!("../data/hmac/jwk.json");
    pub const JWK_MINIMAL: &str = include_str!("../data/hmac/jwk-min.json");
}

#[cfg(all(feature = "hmac", feature = "rsa", feature = "ec"))]
pub mod mixed {
    pub const JWKS: &str = include_str!("../data/jwks.json");
}

lazy_static! {
    pub static ref TEST_AUD: &'static crate::AudienceRef =
        &crate::AudienceRef::from_str("TEST_AUDIENCE");
    pub static ref VALID_AUD: HashSet<String> = [TEST_AUD.as_str()]
        .iter()
        .map(|&s| String::from(s))
        .collect();
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct MinimalClaims {
    #[serde(default, skip_serializing_if = "Audiences::is_empty")]
    aud: Audiences,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exp: Option<UnixTime>,
}

impl CoreClaims for MinimalClaims {
    fn aud(&self) -> &Audiences {
        &self.aud
    }

    fn exp(&self) -> Option<UnixTime> {
        self.exp
    }
}

impl MinimalClaims {
    pub fn with_audience(mut self, aud: impl Into<crate::Audience>) -> Self {
        self.aud = Audiences::from(vec![aud.into()]);
        self
    }

    pub fn with_future_expiration(mut self, secs: u64) -> Self {
        let n = UnixTime::from(std::time::SystemTime::now());
        self.exp = Some(UnixTime(n.0 + secs));
        self
    }
}
