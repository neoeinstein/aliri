//! Implementations of the JSON Web Tokens (JWT) standard
//!
//! The specifications for this standard can be found in [RFC7519][].
//!
//! Unencrypted JWTs generally appear as a three-part base64-encoded string,
//! where each part is separated by a `.`.
//!
//! ```text
//! eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJBbGlyaSJ9.KUj-klFcT39uuSIrU91spdBFnMHsn8TDJMeJ99coucA
//! ```
//!
//! The first section is the header in JSON format, and provides basic
//! metadata about the token.
//! These values are generally used to elect the specific key to be used
//! for verifying the token's authenticity. Because of this, values in the
//! header should be evaluated against strict expectations before use.
//!
//! The second section is the payload in JSON format, and contains claims
//! regarding the authentication, including how long the token is valid,
//! who issued the token, who the token is intended for, and who the subject
//! is that has been authentication. Nothing in this section should be
//! trusted before the token's authenticity has been validated
//!
//! The third section is the binary signature, which must be verified against
//! some JSON Web Key, which, if valid, verifies that the headers and payload
//! were signed by the authority using this key.
//!
//! [RFC7519]: https://tools.ietf.org/html/rfc7519
//!
//! ```
//! use aliri_core::base64::Base64UrlRef;
//! use aliri_jose::{jwa, jwk, jws, jwt, Jwk, JwtRef};
//!
//! let token = JwtRef::from_str(concat!(
//!     "eyJhbGciOiJIUzI1NiJ9.",
//!     "eyJzdWIiOiJBbGlyaSIsImF1ZCI6Im15X2FwaSIsImlzcyI6ImF1dGhvcml0eSJ9.",
//!     "2N5yyY2UjqlUKSSCpFVWzfixfBRTWahiN2PrUuiuxbE"
//! ));
//!
//! let secret = Base64UrlRef::from_slice(b"test").to_owned();
//! let params = jwk::Parameters::Hmac(jwa::Hmac::new(secret));
//!
//! let key = Jwk {
//!     id: None,
//!     usage: Some(jwk::Usage::Signing),
//!     algorithm: Some(jws::Algorithm::HS256),
//!     params,
//! };
//!
//! let validator = jwt::Validation::default()
//!     .ignore_expiration()
//!     .add_approved_algorithm(jws::Algorithm::HS256)
//!     .add_allowed_audience(jwt::Audience::new("my_api"))
//!     .require_issuer(jwt::Issuer::new("authority"));
//!
//! let data: jwt::Validated<jwt::Claims> = token.verify(&key, &validator).unwrap();
//! # let _ = data;
//! ```

use std::time::Duration;

use aliri_core::{
    base64::Base64Url,
    clock::{Clock, System, UnixTime},
    OneOrMany,
};
use aliri_macros::typed_string;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::{jwk, jws, Jwk};

/// The validated headers and claims of a JWT
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validated<C = Empty, H = Empty> {
    headers: H,
    claims: C,
}

impl<C, H> Validated<C, H> {
    pub(crate) const fn new(headers: H, claims: C) -> Self {
        Self { headers, claims }
    }

    /// Extracts the header and claims from the token
    pub fn take(self) -> (H, C) {
        (self.headers, self.claims)
    }

    /// The validated token headers
    pub fn headers(&self) -> &H {
        &self.headers
    }

    /// The validated token claims
    pub fn claims(&self) -> &C {
        &self.claims
    }
}

/// A decomposed JWT header
///
/// This structure is suitable for inspection to determine which key
/// should be used to validate the JWT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decomposed<'a, H = Empty> {
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
    H: for<'de> Deserialize<'de>,
{
    /// Verifies the decomposed JWT against the given JWK and validation plan
    pub fn verify<C>(self, key: &'_ Jwk, validator: &Validation) -> anyhow::Result<Validated<C, H>>
    where
        C: for<'de> Deserialize<'de>,
    {
        let data = key.verify_decomposed(self, validator)?;

        Ok(data)
    }
}

impl JwtRef {
    /// Decomposes the JWT into its parts, preparing it for later processing.
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

    /// Verifies a token against a particular JWK and validation plan
    ///
    /// If you need to inspect the token first to determine how to verify
    /// the token, use `decompose()` to peek into the JWT.
    pub fn verify<C, H>(
        &self,
        key: &'_ Jwk,
        validator: &Validation,
    ) -> anyhow::Result<Validated<C, H>>
    where
        C: for<'de> Deserialize<'de>,
        H: for<'de> Deserialize<'de>,
    {
        let decomposed = self.decompose()?;

        let data = key.verify_decomposed(decomposed, validator)?;

        Ok(data)
    }
}

impl<'a, H> HasSigningAlgorithm for Decomposed<'a, H> {
    fn alg(&self) -> jws::Algorithm {
        self.header.alg()
    }
}

impl<'a, H> CoreHeaders for Decomposed<'a, H> {
    fn kid(&self) -> Option<&jwk::KeyIdRef> {
        self.header.kid()
    }
}

/// Core claims that most compliant and secure JWT tokens should have
pub trait CoreClaims {
    /// Not before
    ///
    /// A verifier MUST reject this token before the given time.
    fn nbf(&self) -> Option<UnixTime> {
        None
    }

    /// Expires
    ///
    /// A verifier MUST reject this token after the given time.
    fn exp(&self) -> Option<UnixTime> {
        None
    }

    /// Audience
    ///
    /// A verifier MUST reject this token none of the audiences specified
    /// is an approved.
    fn aud(&self) -> &Audiences {
        Audiences::EMPTY_AUD
    }

    /// Issuer
    ///
    /// A verifier MUST reject this token if it the issuer is not approved.
    fn iss(&self) -> Option<&IssuerRef> {
        None
    }
}

/// Indicates that the type specifies the signing algorithm
pub trait HasSigningAlgorithm {
    /// Signing algorithm
    ///
    /// The signing algorithm that was used to sign the token.
    /// A verifier MUST reject a token that specifies a signing
    /// algorithm that has not been approved or if the JWK to be used
    /// does not allow for the specified signing algorithm.
    fn alg(&self) -> jws::Algorithm;
}

/// Indicates that the type has values common to a JWT header
pub trait CoreHeaders: HasSigningAlgorithm {
    /// Key ID
    ///
    /// The ID of the JWK used to sign this token.
    /// A verifier MUST use the JWK with the specified ID to verify
    /// the token. A verifier MAY use a JWK without any ID to verify
    /// the token _if and only if_ there is no JWK with a matching ID.
    fn kid(&self) -> Option<&jwk::KeyIdRef> {
        None
    }
}

/// An empty structure
///
/// Useful for when a consumer has no custom claims to deserialize.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

impl CoreClaims for Empty {}

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
    /// A JSON Web Token
    pub struct Jwt(String);

    /// Reference to `Jwt`
    pub struct JwtRef(str);
}

/// A set of zero or more audiences
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "OneOrMany<Audience>", into = "OneOrMany<Audience>")]
#[repr(transparent)]
pub struct Audiences(Vec<Audience>);

impl Audiences {
    /// An empty audience set
    #[inline]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// An audience set with a single audience
    #[inline]
    pub fn single(aud: impl Into<Audience>) -> Self {
        let mut v = Vec::with_capacity(1);
        v.push(aud.into());
        Self(v)
    }

    /// An empty audience set
    pub const EMPTY_AUD: &'static Audiences = &Audiences::empty();

    /// Indicates whether the audience set is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates through references to the audiences in the set
    #[inline]
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

/// A standard validator for JWTs
///
/// The default validator will
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
    /// The default validator does not accept any algorithms and
    /// that the token is not expired (no grace period)
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
    /// Allows a grace period for token validation
    ///
    /// Applies on either side of the "not before" and "expires" claims.
    #[inline]
    pub fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// Enforces expiration checks
    #[inline]
    pub fn check_expiration(mut self) -> Self {
        self.validate_exp = true;
        self
    }

    /// Enforces "not valid before" checks
    #[inline]
    pub fn check_not_before(mut self) -> Self {
        self.validate_nbf = true;
        self
    }

    /// Skips expiration checks
    #[inline]
    pub fn ignore_expiration(mut self) -> Self {
        self.validate_exp = false;
        self
    }

    /// Skips "not valid before" checks
    #[inline]
    pub fn ignore_not_before(mut self) -> Self {
        self.validate_nbf = false;
        self
    }

    /// Adds a single audience to the set of allowed audiences
    #[inline]
    pub fn add_allowed_audience(mut self, audience: Audience) -> Self {
        self.allowed_audiences.push(audience);
        self
    }

    /// Adds mutliple audiences to the set of allowed audiences
    #[inline]
    pub fn extend_allowed_audiences<I: IntoIterator<Item = Audience>>(mut self, alg: I) -> Self {
        self.allowed_audiences.extend(alg);
        self
    }

    /// Approves a single algorithm
    #[inline]
    pub fn add_approved_algorithm(mut self, alg: jws::Algorithm) -> Self {
        self.approved_algorithms.push(alg);
        self
    }

    /// Approves multiple algorithms
    #[inline]
    pub fn extend_approved_algorithms<I: IntoIterator<Item = jws::Algorithm>>(
        mut self,
        alg: I,
    ) -> Self {
        self.approved_algorithms.extend(alg);
        self
    }

    /// Require that tokens specify a particular issuer
    #[inline]
    pub fn require_issuer(mut self, issuer: Issuer) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// The issuer required by this validator
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

/// Common headers used on JWTs
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Headers<H = Empty> {
    alg: jws::Algorithm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<jwk::KeyId>,
    #[serde(flatten)]
    headers: H,
}

impl<H> HasSigningAlgorithm for Headers<H> {
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
    /// Constructs JWT headers, to be signed by the specified algorithm
    pub const fn new(alg: jws::Algorithm) -> Self {
        Self {
            alg,
            kid: None,
            headers: Empty {},
        }
    }
}

impl<H> Headers<H> {
    /// Adds a key ID to the JWT header
    pub fn with_key_id(mut self, kid: impl Into<jwk::KeyId>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Adds custom headers to the JWT
    pub fn with_headers<G>(self, headers: G) -> Headers<G> {
        Headers {
            alg: self.alg,
            kid: self.kid,
            headers,
        }
    }

    /// A view of the custom headers
    pub fn headers(&self) -> &H {
        &self.headers
    }

    /// Moves the custom headers out
    pub fn take_headers(self) -> H {
        self.headers
    }
}

/// Common claims used in JWTs
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Claims<P = Empty> {
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
    /// Constructs a new, empty payload
    pub const fn new() -> Self {
        Self {
            aud: Audiences::empty(),
            iss: None,
            exp: None,
            nbf: None,
            payload: Empty {},
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
    /// Sets the `aud` claim for the JWT
    pub fn with_audience(mut self, aud: impl Into<Audience>) -> Self {
        self.aud = Audiences::from(vec![aud.into()]);
        self
    }

    /// Sets the `aud` claim for the JWT, where multiple audiences are allowed
    pub fn with_audiences(mut self, aud: impl Into<Audiences>) -> Self {
        self.aud = aud.into();
        self
    }

    /// Sets the `iss` claim for the JWT
    pub fn with_issuer(mut self, iss: impl Into<Issuer>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Sets the `exp` claim for the JWT using the system clock
    pub fn with_future_expiration(self, secs: u64) -> Self {
        self.with_future_expiration_from_clock(secs, &System)
    }

    /// Sets the `exp` claim for the JWT using the specified clock
    pub fn with_future_expiration_from_clock<C: Clock>(mut self, secs: u64, clock: &C) -> Self {
        let n = clock.now();
        self.exp = Some(UnixTime(n.0 + secs));
        self
    }

    /// Sets the `exp` claim for the JWT
    pub fn with_expiration(mut self, time: UnixTime) -> Self {
        self.exp = Some(time);
        self
    }

    /// Sets the `nbf` claim for the JWT
    pub fn with_not_before(mut self, time: UnixTime) -> Self {
        self.nbf = Some(time);
        self
    }

    /// Adds a custom payload of claims to the JWT
    pub fn with_payload<Q>(self, payload: Q) -> Claims<Q> {
        Claims {
            aud: self.aud,
            iss: self.iss,
            exp: self.exp,
            nbf: self.nbf,
            payload,
        }
    }

    /// Borrows the custom claims attached to the JWT
    pub fn payload(&self) -> &P {
        &self.payload
    }

    /// Moves the custom claims out
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
            .require_issuer(Issuer::new("face"));

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
