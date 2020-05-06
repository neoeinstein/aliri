use std::time::Duration;

use aliri_core::clock::{Clock, System, UnixTime};
use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::{jwa::Algorithm, Audience, Audiences, Issuer, IssuerRef};

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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct EmptyClaims {}

impl CoreClaims for EmptyClaims {}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicValidation {
    approved_algorithms: Vec<Algorithm>,
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
    pub fn add_approved_algorithm(mut self, alg: Algorithm) -> Self {
        self.approved_algorithms.push(alg);
        self
    }

    #[inline]
    pub fn extend_approved_algorithms<I: IntoIterator<Item = Algorithm>>(mut self, alg: I) -> Self {
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

    pub(crate) fn validate<T: CoreClaims>(
        &self,
        header: &jsonwebtoken::Header,
        claims: &T,
    ) -> anyhow::Result<()> {
        self.validate_with_clock(header, claims, &System)
    }

    pub(crate) fn validate_with_clock<C: Clock, T: CoreClaims>(
        &self,
        header: &jsonwebtoken::Header,
        claims: &T,
        clock: &C,
    ) -> anyhow::Result<()> {
        let now = clock.now();

        let algorithm_matches = |a: &Algorithm| {
            if let Some(alg) = a.to_jsonwebtoken() {
                alg == header.alg
            } else {
                false
            }
        };

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

        validation.validate_with_clock(&jsonwebtoken::Header::default(), &claims, &clock)
    }
}
