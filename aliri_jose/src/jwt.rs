use std::time::Duration;

use aliri_core::{
    clock::{Clock, System, UnixTime},
    OneOrMany,
};
use aliri_macros::typed_string;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::{jwk, jws};

pub trait CoreClaims {
    fn nbf(&self) -> Option<UnixTime> {
        None
    }

    fn exp(&self) -> Option<UnixTime> {
        None
    }

    fn aud(&self) -> &Audiences {
        Audiences::EMPTY_AUD
    }

    fn iss(&self) -> Option<&IssuerRef> {
        None
    }
}

pub trait CoreHeaders {
    fn alg(&self) -> jws::Algorithm;

    fn kid(&self) -> Option<&jwk::KeyIdRef> {
        None
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct HeaderWithBasicClaims<H> {
    #[serde(flatten)]
    basic: BasicHeader,
    #[serde(flatten)]
    pub header: H,
}

impl<H> CoreHeaders for HeaderWithBasicClaims<H> {
    fn alg(&self) -> jws::Algorithm {
        self.basic.alg()
    }

    fn kid(&self) -> Option<&jwk::KeyIdRef> {
        self.basic.kid()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BasicHeader {
    #[serde(rename = "alg")]
    algorithm: jws::Algorithm,
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    key_id: Option<jwk::KeyId>,
}

impl CoreHeaders for BasicHeader {
    fn alg(&self) -> jws::Algorithm {
        self.algorithm
    }

    fn kid(&self) -> Option<&jwk::KeyIdRef> {
        self.key_id.as_deref()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct PayloadWithBasicClaims<P> {
    #[serde(flatten)]
    basic: BasicClaims,
    #[serde(flatten)]
    pub payload: P,
}

impl<P> CoreClaims for PayloadWithBasicClaims<P> {
    fn nbf(&self) -> Option<UnixTime> {
        self.basic.nbf()
    }

    fn exp(&self) -> Option<UnixTime> {
        self.basic.exp()
    }

    fn aud(&self) -> &Audiences {
        self.basic.aud()
    }

    fn iss(&self) -> Option<&IssuerRef> {
        self.basic.iss()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BasicClaims {
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    not_before: Option<UnixTime>,
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    expiration: Option<UnixTime>,
    #[serde(rename = "aud", default, skip_serializing_if = "Audiences::is_empty")]
    audience: Audiences,
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    issuer: Option<Issuer>,
}

impl CoreClaims for BasicClaims {
    fn nbf(&self) -> Option<UnixTime> {
        self.not_before
    }

    fn exp(&self) -> Option<UnixTime> {
        self.expiration
    }

    fn aud(&self) -> &Audiences {
        &self.audience
    }

    fn iss(&self) -> Option<&IssuerRef> {
        self.issuer.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct EmptyClaims {}

impl CoreClaims for EmptyClaims {}

typed_string! {
    /// An audience
    pub struct Audience(String);

    /// Reference to `Audience`
    pub struct AudienceRef(str);
}

typed_string! {
    /// An issuer of JWTs
    pub struct Issuer(String);

    /// Reference to `Issuer`
    pub struct IssuerRef(str);
}

typed_string! {
    /// A token
    pub struct Jwt(String);

    /// A borrowed reference to a token
    pub struct JwtRef(str);
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "OneOrMany<Audience>", into = "OneOrMany<Audience>")]
#[repr(transparent)]
pub struct Audiences(Vec<Audience>);

impl Audiences {
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    pub fn single(aud: impl Into<Audience>) -> Self {
        let mut v = Vec::with_capacity(1);
        v.push(aud.into());
        Self(v)
    }

    pub const EMPTY_AUD: &'static Audiences = &Audiences::new();

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &AudienceRef> {
        self.0.iter().map(|i| i.as_ref())
    }
}

impl From<OneOrMany<Audience>> for Audiences {
    #[inline]
    fn from(vals: OneOrMany<Audience>) -> Self {
        match vals {
            OneOrMany::One(x) => Self(vec![x]),
            OneOrMany::Many(v) => Self(v),
        }
    }
}

impl From<Audiences> for OneOrMany<Audience> {
    #[inline]
    fn from(mut vec: Audiences) -> Self {
        if vec.0.len() == 1 {
            Self::One(vec.0.pop().unwrap())
        } else {
            Self::Many(vec.0)
        }
    }
}

impl From<Vec<Audience>> for Audiences {
    #[inline]
    fn from(vals: Vec<Audience>) -> Self {
        Self(vals)
    }
}

impl From<Audience> for Audiences {
    #[inline]
    fn from(aud: Audience) -> Self {
        Self::single(aud)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicValidation {
    approved_algorithms: Vec<jws::Algorithm>,
    leeway: Duration,
    validate_nbf: bool,
    validate_exp: bool,
    allowed_audiences: Vec<Audience>,
    issuer: Option<Issuer>,
}

impl Default for BasicValidation {
    #[inline]
    fn default() -> Self {
        Self {
            approved_algorithms: Vec::new(),
            leeway: Duration::default(),
            validate_exp: true,
            validate_nbf: false,
            allowed_audiences: Vec::new(),
            issuer: None,
        }
    }
}

impl BasicValidation {
    #[inline]
    pub fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    #[inline]
    pub fn check_expiration(mut self) -> Self {
        self.validate_exp = true;
        self
    }

    #[inline]
    pub fn check_not_before(mut self) -> Self {
        self.validate_nbf = true;
        self
    }

    #[inline]
    pub fn ignore_expiration(mut self) -> Self {
        self.validate_exp = false;
        self
    }

    #[inline]
    pub fn ignore_not_before(mut self) -> Self {
        self.validate_nbf = false;
        self
    }

    #[inline]
    pub fn add_allowed_audience(mut self, audience: Audience) -> Self {
        self.allowed_audiences.push(audience);
        self
    }

    #[inline]
    pub fn extend_allowed_audiences<I: IntoIterator<Item = Audience>>(mut self, alg: I) -> Self {
        self.allowed_audiences.extend(alg);
        self
    }

    #[inline]
    pub fn add_approved_algorithm(mut self, alg: jws::Algorithm) -> Self {
        self.approved_algorithms.push(alg);
        self
    }

    #[inline]
    pub fn extend_approved_algorithms<I: IntoIterator<Item = jws::Algorithm>>(
        mut self,
        alg: I,
    ) -> Self {
        self.approved_algorithms.extend(alg);
        self
    }

    #[inline]
    pub fn set_issuer(mut self, issuer: Issuer) -> Self {
        self.issuer = Some(issuer);
        self
    }

    #[inline]
    pub fn issuer(&self) -> Option<&IssuerRef> {
        self.issuer.as_deref()
    }

    pub(crate) fn validate<H: CoreHeaders, T: CoreClaims>(
        &self,
        header: &H,
        claims: &T,
    ) -> anyhow::Result<()> {
        self.validate_with_clock(header, claims, &System)
    }

    pub(crate) fn validate_with_clock<C: Clock, H: CoreHeaders, T: CoreClaims>(
        &self,
        header: &H,
        claims: &T,
        clock: &C,
    ) -> anyhow::Result<()> {
        let now = clock.now();

        let algorithm_matches =
            |&a: &jws::Algorithm| header.alg() != jws::Algorithm::Unknown && header.alg() == a;

        if !self.approved_algorithms.is_empty()
            && !self.approved_algorithms.iter().any(algorithm_matches)
        {
            return Err(anyhow!("token does not use an approved algorithm"));
        }

        if self.validate_exp {
            if let Some(exp) = claims.exp() {
                if exp.0 < now.0.saturating_sub(self.leeway.as_secs()) {
                    return Err(anyhow!("token has expired"));
                }
            } else {
                return Err(anyhow!("token is missing expected exp claim"));
            }
        }

        if self.validate_nbf {
            if let Some(nbf) = claims.nbf() {
                if nbf.0 > now.0.saturating_add(self.leeway.as_secs()) {
                    return Err(anyhow!("token is not yet good"));
                }
            } else {
                return Err(anyhow!("token is missing expected nbf claim"));
            }
        }

        if !self.allowed_audiences.is_empty() {
            if claims.aud().is_empty() {
                return Err(anyhow!("token is missing expected aud claim"));
            }

            let found = claims
                .aud()
                .iter()
                .any(|a| self.allowed_audiences.iter().any(|e| a == e));
            if !found {
                return Err(anyhow!("token does not match any allowed audience"));
            }
        }

        if let Some(allowed_iss) = &self.issuer {
            if let Some(iss) = claims.iss() {
                if iss != allowed_iss {
                    return Err(anyhow!("token issuer is not trusted"));
                }
            } else {
                return Err(anyhow!("token is missing expected iss claim"));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use aliri_core::clock::TestClock;

    use super::*;

    #[test]
    fn deserialize_basic_claims() -> anyhow::Result<()> {
        const DATA: &str = r#"{
                "nbf": 345,
                "iss": "me"
            }"#;

        let basic: BasicClaims = serde_json::from_str(DATA)?;
        dbg!(&basic);

        Ok(())
    }

    #[test]
    fn vdater() -> anyhow::Result<()> {
        let validation = BasicValidation::default()
            .with_leeway(Duration::from_secs(2))
            .check_not_before()
            .extend_allowed_audiences(vec![Audience::new("marcus"), Audience::new("other")])
            .set_issuer(Issuer::new("face"));

        let claims = BasicClaims {
            not_before: Some(UnixTime(9)),
            expiration: Some(UnixTime(5)),
            audience: Audiences::from(vec![Audience::new("marcus"), Audience::new("other")]),
            issuer: Some(Issuer::new("face")),
        };

        let mut clock = TestClock::default();
        clock.set(UnixTime(7));

        let header = BasicHeader {
            algorithm: jws::Algorithm::RS256,
            key_id: None,
        };

        validation.validate_with_clock(&header, &claims, &clock)
    }
}
