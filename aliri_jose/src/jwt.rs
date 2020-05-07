use std::time::Duration;

use aliri_core::{
    clock::{Clock, System, UnixTime},
    Base64Url, OneOrMany,
};
use aliri_macros::typed_string;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::{jwk, jws, Jwk};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenData<C = EmptyClaims, H = EmptyClaims> {
    pub header: H,
    pub claims: C,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decomposed<'a, H = EmptyClaims> {
    pub(crate) header: Headers<H>,
    pub(crate) message: &'a str,
    pub(crate) payload: &'a str,
    pub(crate) signature: Base64Url,
}

macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(anyhow::anyhow!("malformed JWT")),
        }
    }};
}

impl<'a, H> Decomposed<'a, H>
where
    H: for<'de> serde::Deserialize<'de>,
{
    pub fn verify<C>(self, key: &'_ Jwk, validator: &Validation) -> anyhow::Result<TokenData<C, H>>
    where
        C: for<'de> serde::Deserialize<'de>,
    {
        let data = key.verify_decomposed(self, validator)?;

        Ok(data)
    }
}

impl JwtRef {
    pub fn decompose<H>(&self) -> anyhow::Result<Decomposed<H>>
    where
        H: for<'de> Deserialize<'de>,
    {
        let (s_str, message) = expect_two!(self.as_str().rsplitn(2, '.'));
        let (payload, h_str) = expect_two!(message.rsplitn(2, '.'));
        let h_raw = Base64Url::from_encoded(h_str)?;
        let signature = Base64Url::from_encoded(s_str)?;
        let header: Headers<H> = serde_json::from_slice(h_raw.as_slice())?;
        Ok(Decomposed {
            header,
            message,
            payload,
            signature,
        })
    }

    pub fn verify<C, H>(&self, key: &'_ Jwk, validator: &Validation) -> anyhow::Result<TokenData<C, H>>
    where
        C: for<'de> serde::Deserialize<'de>,
        H: for<'de> serde::Deserialize<'de>,
    {
        let decomposed = self.decompose()?;
        
        let data = key.verify_decomposed(decomposed, validator)?;

        Ok(data)
    }
}

impl<'a, H> HasAlgorithm for Decomposed<'a, H> {
    fn alg(&self) -> jws::Algorithm {
        self.header.alg()
    }
}

impl<'a, H> CoreHeaders for Decomposed<'a, H> {
    fn kid(&self) -> Option<&jwk::KeyIdRef> {
        self.header.kid()
    }
}

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

pub trait HasAlgorithm {
    fn alg(&self) -> jws::Algorithm;
}

pub trait CoreHeaders: HasAlgorithm {
    fn kid(&self) -> Option<&jwk::KeyIdRef> {
        None
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
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
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn single(aud: impl Into<Audience>) -> Self {
        let mut v = Vec::with_capacity(1);
        v.push(aud.into());
        Self(v)
    }

    pub const EMPTY_AUD: &'static Audiences = &Audiences::empty();

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
pub struct Validation {
    approved_algorithms: Vec<jws::Algorithm>,
    leeway: Duration,
    validate_nbf: bool,
    validate_exp: bool,
    allowed_audiences: Vec<Audience>,
    issuer: Option<Issuer>,
}

impl Default for Validation {
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

impl Validation {
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

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Headers<H = EmptyClaims> {
    alg: jws::Algorithm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<jwk::KeyId>,
    #[serde(flatten)]
    headers: H,
}

impl<H> HasAlgorithm for Headers<H> {
    fn alg(&self) -> jws::Algorithm {
        self.alg
    }
}

impl<H> CoreHeaders for Headers<H> {
    fn kid(&self) -> Option<&jwk::KeyIdRef> {
        self.kid.as_deref()
    }
}

impl Headers {
    pub const fn new(alg: jws::Algorithm) -> Self {
        Self { alg, kid: None, headers: EmptyClaims{} }
    }
}

impl<H> Headers<H> {
    pub fn with_key_id(mut self, kid: impl Into<jwk::KeyId>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    pub fn with_headers<G>(self, headers: G) -> Headers<G> {
        Headers {
            alg: self.alg,
            kid: self.kid,
            headers,
        }
    }

    pub fn headers(&self) -> &H {
        &self.headers
    }

    pub fn take_headers(self) -> H {
        self.headers
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Claims<P = EmptyClaims> {
    #[serde(default, skip_serializing_if = "Audiences::is_empty")]
    aud: Audiences,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    iss: Option<Issuer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exp: Option<UnixTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nbf: Option<UnixTime>,
    #[serde(flatten)]
    payload: P,
}

impl Claims {
    pub const fn new() -> Self {
        Self {
            aud: Audiences::empty(),
            iss: None,
            exp: None,
            nbf: None,
            payload: EmptyClaims {},
        }
    }
}

impl<P> CoreClaims for Claims<P> {
    fn aud(&self) -> &Audiences {
        &self.aud
    }

    fn iss(&self) -> Option<&IssuerRef> {
        self.iss.as_deref()
    }

    fn exp(&self) -> Option<UnixTime> {
        self.exp
    }

    fn nbf(&self) -> Option<UnixTime> {
        self.exp
    }
}

impl<P> Claims<P> {
    pub fn with_audience(mut self, aud: impl Into<Audience>) -> Self {
        self.aud = Audiences::from(vec![aud.into()]);
        self
    }

    pub fn with_audiences(mut self, aud: impl Into<Audiences>) -> Self {
        self.aud = aud.into();
        self
    }

    pub fn with_issuer(mut self, iss: impl Into<Issuer>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    pub fn with_future_expiration(self, secs: u64) -> Self {
        self.with_future_expiration_from_clock(secs, &System)
    }

    pub fn with_future_expiration_from_clock<C: Clock>(mut self, secs: u64, clock: &C) -> Self {
        let n = clock.now();
        self.exp = Some(UnixTime(n.0 + secs));
        self
    }

    pub fn with_expiration(mut self, time: UnixTime) -> Self {
        self.exp = Some(time);
        self
    }

    pub fn with_not_before(mut self, time: UnixTime) -> Self {
        self.nbf = Some(time);
        self
    }

    pub fn with_payload<Q>(self, payload: Q) -> Claims<Q> {
        Claims {
            aud: self.aud,
            iss: self.iss,
            exp: self.exp,
            nbf: self.nbf,
            payload,
        }
    }

    pub fn payload(&self) -> &P {
        &self.payload
    }

    pub fn take_payload(self) -> P {
        self.payload
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

        let basic: Claims = serde_json::from_str(DATA)?;
        dbg!(&basic);

        Ok(())
    }

    #[test]
    fn vdater() -> anyhow::Result<()> {
        let validation = Validation::default()
            .with_leeway(Duration::from_secs(2))
            .check_not_before()
            .extend_allowed_audiences(vec![Audience::new("marcus"), Audience::new("other")])
            .set_issuer(Issuer::new("face"));

        let audiences = Audiences::from(vec![Audience::new("marcus"), Audience::new("other")]);

        let claims = Claims::new()
            .with_not_before(UnixTime(9))
            .with_expiration(UnixTime(5))
            .with_audiences(audiences)
            .with_issuer(Issuer::new("face"));

        let mut clock = TestClock::default();
        clock.set(UnixTime(7));

        let header = Headers::new(jws::Algorithm::RS256);

        validation.validate_with_clock(&header, &claims, &clock)
    }
}
