#![allow(dead_code)]

use std::collections::HashSet;

use lazy_static::lazy_static;

use crate::jwt;

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
    pub const JWK_P256: &str = include_str!("../data/ec/jwk-p256.json");
    pub const JWK_P256_MINIMAL: &str = include_str!("../data/ec/jwk-p256-min.json");
    #[cfg(feature = "private-keys")]
    pub const JWK_P256_WITH_PRIVATE_KEY: &str = include_str!("../data/ec/jwk-p256-priv.json");
    #[cfg(feature = "private-keys")]
    pub const JWK_P256_WITH_MINIMAL_PRIVATE_KEY: &str =
        include_str!("../data/ec/jwk-p256-priv-min.json");

    pub const JWK_P384: &str = include_str!("../data/ec/jwk-p384.json");
    pub const JWK_P384_MINIMAL: &str = include_str!("../data/ec/jwk-p384-min.json");
    #[cfg(feature = "private-keys")]
    pub const JWK_P384_WITH_PRIVATE_KEY: &str = include_str!("../data/ec/jwk-p384-priv.json");
    #[cfg(feature = "private-keys")]
    pub const JWK_P384_WITH_MINIMAL_PRIVATE_KEY: &str =
        include_str!("../data/ec/jwk-p384-priv-min.json");

    pub const JWK_P521: &str = include_str!("../data/ec/jwk-p521.json");
    pub const JWK_P521_MINIMAL: &str = include_str!("../data/ec/jwk-p521-min.json");
    #[cfg(feature = "private-keys")]
    pub const JWK_P521_WITH_PRIVATE_KEY: &str = include_str!("../data/ec/jwk-p521-priv.json");
    #[cfg(feature = "private-keys")]
    pub const JWK_P521_WITH_MINIMAL_PRIVATE_KEY: &str =
        include_str!("../data/ec/jwk-p521-priv-min.json");
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
    pub static ref TEST_AUD: &'static jwt::AudienceRef =
        jwt::AudienceRef::from_str("TEST_AUDIENCE");
    pub static ref VALID_AUD: HashSet<String> = [TEST_AUD.as_str()]
        .iter()
        .map(|&s| String::from(s))
        .collect();
}
