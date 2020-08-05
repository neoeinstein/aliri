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
//! use aliri_jose::{jwa, jws, jwt, Jwk, JwtRef};
//! use regex::Regex;
//!
//! let token = JwtRef::from_str(concat!(
//!     "eyJhbGciOiJIUzI1NiJ9.",
//!     "eyJzdWIiOiJBbGlyaSIsImF1ZCI6Im15X2FwaSIsImlzcyI6ImF1dGhvcml0eSJ9.",
//!     "2N5yyY2UjqlUKSSCpFVWzfixfBRTWahiN2PrUuiuxbE"
//! ));
//!
//! let secret = Base64UrlRef::from_slice(b"test").to_owned();
//! let key = Jwk::from(jwa::Hmac::new(secret))
//!     .with_algorithm(jwa::Algorithm::HS256);
//!
//! let validator = jwt::CoreValidator::default()
//!     .ignore_expiration()
//!     .add_approved_algorithm(jwa::Algorithm::HS256)
//!     .add_allowed_audience(jwt::Audience::new("my_api"))
//!     .require_issuer(jwt::Issuer::new("authority"))
//!     .check_subject(Regex::new("^Al.ri$").unwrap());
//!
//! let data: jwt::Validated = token.verify(&key, &validator).unwrap();
//! # let _ = data;
//! ```

use std::{convert::TryFrom, time::Duration};

use aliri_core::{
    base64::Base64Url,
    clock::{Clock, System, UnixTime},
    OneOrMany,
};
use aliri_macros::typed_string;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::jws::Signer;
use crate::{error, jwa, jwk, jws, Jwk};

#[cfg(feature = "unstable")]
mod validator;

#[cfg(feature = "unstable")]
use validator::{Validator, ValidatorExt};

#[inline(never)]
#[cfg(feature = "unstable")]
fn do_validate(
    b: impl Validator<(Headers, Claims), Error = error::ClaimsRejected>,
    header: crate::jwt::Headers,
    claims: crate::jwt::Claims,
) -> Result<(), error::ClaimsRejected> {
    b.validate(&(header, claims))
}

#[cfg(feature = "unstable")]
fn validate_it() {
    let issuer = IssuerRef::from_str("issuer");
    let audience = AudienceRef::from_str("audience");

    let validator = validator::All::<_, crate::error::ClaimsRejected>::new::<(Headers, Claims)>((
        crate::jwa::Algorithm::HS512,
        issuer,
        audience,
        validator::Timing {
            validate_exp: true,
            validate_nbf: true,
            leeway: 3,
            clock: System,
        },
    ));

    let header = crate::jwt::Headers::new(crate::jwa::Algorithm::HS512);
    let claims = crate::jwt::Claims::new()
        .with_issuer(issuer.to_owned())
        .with_audience(audience.to_owned())
        .with_future_expiration(60);

    let _ = do_validate(validator, header, claims);
}

/// The validated headers and claims of a JWT
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validated<C = Empty, H = Empty> {
    headers: Headers<H>,
    claims: Claims<C>,
}

impl<C, H> Validated<C, H> {
    /// Extracts the header and claims from the token
    pub fn take(self) -> (Headers<H>, Claims<C>) {
        (self.headers, self.claims)
    }

    /// The validated token headers
    pub fn headers(&self) -> &Headers<H> {
        &self.headers
    }

    /// The validated token claims
    pub fn claims(&self) -> &Claims<C> {
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
            (Some(first), Some(second), None) => Some((first, second)),
            _ => None,
        }
    }};
}

impl<'a, H> Decomposed<'a, H>
where
    H: for<'de> Deserialize<'de>,
{
    /// Verifies the decomposed JWT against the given JWK and validation plan
    pub fn verify<C, V>(
        self,
        key: &'_ V,
        validator: &CoreValidator,
    ) -> Result<Validated<C, H>, error::JwtVerifyError>
    where
        C: for<'de> Deserialize<'de>,
        V: jws::Verifier<Algorithm = jwa::Algorithm>,
        error::JwtVerifyError: From<V::Error>,
    {
        self.verify_with_custom(key, validator, NoopValidator)
    }

    /// Verifies the decomposed JWT against the given JWK and validation plan
    pub fn verify_with_custom<C, V, X>(
        self,
        key: &'_ V,
        validator: &CoreValidator,
        custom: X,
    ) -> Result<Validated<C, H>, error::JwtVerifyError>
    where
        C: for<'de> Deserialize<'de>,
        V: jws::Verifier<Algorithm = jwa::Algorithm>,
        error::JwtVerifyError: From<V::Error>,
        X: ClaimsValidator<C, H>,
    {
        key.verify(
            self.header.alg(),
            self.message.as_bytes(),
            self.signature.as_slice(),
        )?;

        let p_raw = Base64Url::from_encoded(self.payload).map_err(error::malformed_jwt_payload)?;

        let payload: Claims<C> =
            serde_json::from_slice(p_raw.as_slice()).map_err(error::malformed_jwt_payload)?;

        validator.validate(&self.header, &payload)?;

        custom.validate(self.header.headers(), payload.payload())?;

        Ok(Validated {
            headers: self.header,
            claims: payload,
        })
    }
}

impl JwtRef {
    /// Decomposes the JWT into its parts, preparing it for later processing.
    pub fn decompose<H>(&self) -> Result<Decomposed<H>, error::JwtVerifyError>
    where
        H: for<'de> Deserialize<'de>,
    {
        let (s_str, message) =
            expect_two!(self.as_str().rsplitn(2, '.')).ok_or_else(error::malformed_jwt)?;
        let (payload, h_str) =
            expect_two!(message.rsplitn(2, '.')).ok_or_else(error::malformed_jwt)?;
        let h_raw = Base64Url::from_encoded(h_str).map_err(error::malformed_jwt_header)?;
        let signature = Base64Url::from_encoded(s_str).map_err(error::malformed_jwt_signature)?;
        let header: Headers<H> =
            serde_json::from_slice(h_raw.as_slice()).map_err(error::malformed_jwt_header)?;
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
    pub fn verify<C, H, V>(
        &self,
        key: &'_ V,
        validator: &CoreValidator,
    ) -> Result<Validated<C, H>, error::JwtVerifyError>
    where
        C: for<'de> Deserialize<'de>,
        H: for<'de> Deserialize<'de>,
        V: jws::Verifier<Algorithm = jwa::Algorithm>,
        error::JwtVerifyError: From<V::Error>,
    {
        self.verify_with_custom(key, validator, NoopValidator)
    }

    /// Verifies a token against a particular JWK and validation plan
    ///
    /// If you need to inspect the token first to determine how to verify
    /// the token, use `decompose()` to peek into the JWT.
    pub fn verify_with_custom<C, H, V, X>(
        &self,
        key: &'_ V,
        validator: &CoreValidator,
        custom: X,
    ) -> Result<Validated<C, H>, error::JwtVerifyError>
    where
        C: for<'de> Deserialize<'de>,
        H: for<'de> Deserialize<'de>,
        V: jws::Verifier<Algorithm = jwa::Algorithm>,
        error::JwtVerifyError: From<V::Error>,
        X: ClaimsValidator<C, H>,
    {
        let decomposed = self.decompose()?;

        decomposed.verify_with_custom(key, validator, custom)
    }
}

impl<'a, H> HasAlgorithm for Decomposed<'a, H> {
    fn alg(&self) -> jwa::Algorithm {
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

    /// Subject
    ///
    /// A verifier SHOULD verify that the subject is acceptable.
    fn sub(&self) -> Option<&SubjectRef> {
        None
    }
}

/// Indicates that the type specifies the algorithm
pub trait HasAlgorithm {
    /// Algorithm
    ///
    /// The algorithm that was used to sign or encrypt the token.
    /// A verifier MUST reject a token that specifies the
    /// algorithm that has not been approved or if the JWK to be used
    /// does not allow for the specified algorithm.
    fn alg(&self) -> jwa::Algorithm;
}

/// Indicates that the type has values common to a JWT header
pub trait CoreHeaders: HasAlgorithm {
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

    /// Reference to an `Audience`
    pub struct AudienceRef(str);
}

typed_string! {
    /// An issuer of JWTs
    pub struct Issuer(String);

    /// Reference to an `Issuer`
    pub struct IssuerRef(str);
}

typed_string! {
    /// The subject of a JWT
    pub struct Subject(String);

    /// Reference to a `Subject`
    pub struct SubjectRef(str);
}

typed_string! {
    /// A JSON Web Token
    pub struct Jwt(String);

    /// Reference to a JSON Web Token
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

/// A claims validator
pub trait ClaimsValidator<C, H> {
    /// Validates the header and payload claims decoded from a JWT
    fn validate(&self, header: &H, claims: &C) -> Result<(), error::ClaimsRejected>;
}

impl<C, H, T> ClaimsValidator<C, H> for &'_ T
where
    T: ClaimsValidator<C, H>,
{
    #[inline]
    fn validate(&self, header: &H, claims: &C) -> Result<(), error::ClaimsRejected> {
        T::validate(&**self, header, claims)
    }
}

impl<C, H, T> ClaimsValidator<C, H> for Box<T>
where
    T: ClaimsValidator<C, H>,
{
    #[inline]
    fn validate(&self, header: &H, claims: &C) -> Result<(), error::ClaimsRejected> {
        T::validate(&**self, header, claims)
    }
}

/// A validator that makes no checks
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoopValidator;

impl<C, H> ClaimsValidator<C, H> for NoopValidator {
    #[inline]
    fn validate(&self, _header: &H, _claims: &C) -> Result<(), error::ClaimsRejected> {
        Ok(())
    }
}

/// A core validator for JWTs
///
/// A default validator configured with common expected validations.
#[derive(Clone, Debug)]
pub struct CoreValidator {
    approved_algorithms: Vec<jwa::Algorithm>,
    leeway: Duration,
    validate_nbf: bool,
    validate_exp: bool,
    allowed_audiences: Vec<Audience>,
    valid_subjects: Option<Regex>,
    issuer: Option<Issuer>,
}

impl Default for CoreValidator {
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
            valid_subjects: None,
            issuer: None,
        }
    }
}

impl CoreValidator {
    /// Allows a grace period for token validation
    ///
    /// Applies on either side of the "not before" and "expires" claims.
    #[inline]
    pub fn with_leeway(self, leeway: Duration) -> Self {
        Self { leeway, ..self }
    }

    /// Allows a grace period (in seconds) for token validation
    ///
    /// Applies on either side of the "not before" and "expires" claims.
    #[inline]
    pub fn with_leeway_secs(self, leeway: u64) -> Self {
        Self {
            leeway: Duration::from_secs(leeway),
            ..self
        }
    }

    /// Enforces expiration checks
    #[inline]
    pub fn check_expiration(self) -> Self {
        Self {
            validate_exp: true,
            ..self
        }
    }

    /// Enforces "not valid before" checks
    #[inline]
    pub fn check_not_before(self) -> Self {
        Self {
            validate_nbf: true,
            ..self
        }
    }

    /// Skips expiration checks
    #[inline]
    pub fn ignore_expiration(self) -> Self {
        Self {
            validate_exp: false,
            ..self
        }
    }

    /// Skips "not valid before" checks
    #[inline]
    pub fn ignore_not_before(self) -> Self {
        Self {
            validate_nbf: false,
            ..self
        }
    }

    /// Adds a single audience to the set of allowed audiences
    #[inline]
    pub fn add_allowed_audience(self, audience: Audience) -> Self {
        let mut slf = self;
        slf.allowed_audiences.push(audience);
        slf
    }

    /// Adds mutliple audiences to the set of allowed audiences
    #[inline]
    pub fn extend_allowed_audiences<I: IntoIterator<Item = Audience>>(self, alg: I) -> Self {
        let mut slf = self;
        slf.allowed_audiences.extend(alg);
        slf
    }

    /// Approves a single algorithm
    #[inline]
    pub fn add_approved_algorithm(self, alg: jwa::Algorithm) -> Self {
        let mut slf = self;
        slf.approved_algorithms.push(alg);
        slf
    }

    /// Approves multiple algorithms
    #[inline]
    pub fn extend_approved_algorithms<I: IntoIterator<Item = jwa::Algorithm>>(
        self,
        alg: I,
    ) -> Self {
        let mut slf = self;
        slf.approved_algorithms.extend(alg);
        slf
    }

    /// Require that tokens specify a particular issuer
    #[inline]
    pub fn require_issuer(self, issuer: Issuer) -> Self {
        Self {
            issuer: Some(issuer),
            ..self
        }
    }

    /// Require that the `sub` claim exists and matches a particular
    /// regular expression
    #[inline]
    pub fn check_subject(self, sub_regex: Regex) -> Self {
        Self {
            valid_subjects: Some(sub_regex),
            ..self
        }
    }

    pub(crate) fn validate<H: CoreHeaders, T: CoreClaims>(
        &self,
        header: &H,
        claims: &T,
    ) -> Result<(), error::ClaimsRejected> {
        self.validate_with_clock(header, claims, &System)
    }

    pub(crate) fn validate_with_clock<C: Clock, H: CoreHeaders, T: CoreClaims>(
        &self,
        header: &H,
        claims: &T,
        clock: &C,
    ) -> Result<(), error::ClaimsRejected> {
        let now = clock.now();

        let algorithm_matches = |&a: &jwa::Algorithm| header.alg() == a;

        if !self.approved_algorithms.is_empty()
            && !self.approved_algorithms.iter().any(algorithm_matches)
        {
            return Err(error::ClaimsRejected::InvalidAlgorithm);
        }

        if self.validate_exp {
            if let Some(exp) = claims.exp() {
                if exp.0 < now.0.saturating_sub(self.leeway.as_secs()) {
                    return Err(error::ClaimsRejected::TokenExpired);
                }
            } else {
                return Err(error::ClaimsRejected::MissingRequiredClaim("exp"));
            }
        }

        if self.validate_nbf {
            if let Some(nbf) = claims.nbf() {
                if nbf.0 > now.0.saturating_add(self.leeway.as_secs()) {
                    return Err(error::ClaimsRejected::TokenNotYetValid);
                }
            } else {
                return Err(error::ClaimsRejected::MissingRequiredClaim("nbf"));
            }
        }

        if !self.allowed_audiences.is_empty() {
            if claims.aud().is_empty() {
                return Err(error::ClaimsRejected::MissingRequiredClaim("aud"));
            }

            let found = claims
                .aud()
                .iter()
                .any(|a| self.allowed_audiences.iter().any(|e| a == e));
            if !found {
                return Err(error::ClaimsRejected::InvalidAudience);
            }
        }

        if let Some(allowed_iss) = &self.issuer {
            if let Some(iss) = claims.iss() {
                if iss != allowed_iss {
                    return Err(error::ClaimsRejected::InvalidIssuer);
                }
            } else {
                return Err(error::ClaimsRejected::MissingRequiredClaim("iss"));
            }
        }

        if let Some(valid_subs) = &self.valid_subjects {
            if let Some(sub) = claims.sub() {
                if !valid_subs.is_match(sub.as_str()) {
                    return Err(error::ClaimsRejected::InvalidSubject);
                }
            } else {
                return Err(error::ClaimsRejected::MissingRequiredClaim("sub"));
            }
        }

        Ok(())
    }
}

/// Common headers used on JWTs
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Headers<H = Empty> {
    alg: jwa::Algorithm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<jwk::KeyId>,
    #[serde(flatten)]
    headers: H,
}

impl<H> HasAlgorithm for Headers<H> {
    fn alg(&self) -> jwa::Algorithm {
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
    pub const fn new(alg: jwa::Algorithm) -> Self {
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
    sub: Option<Subject>,
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
            sub: None,
            exp: None,
            nbf: None,
            payload: Empty {},
        }
    }
}

impl<C: Serialize> Claims<C> {
    /// Produces a signed JWT with the given header and claims
    pub fn sign<H: Serialize + HasAlgorithm>(
        &self,
        jwk: &Jwk,
        headers: &H,
    ) -> Result<Jwt, error::JwtSigningError> {
        use std::fmt::Write;

        let alg = jws::Algorithm::try_from(headers.alg()).map_err(error::SigningError::from)?;

        let h_raw =
            Base64Url::from_raw(serde_json::to_vec(headers).map_err(error::malformed_jwt_header)?);
        let p_raw =
            Base64Url::from_raw(serde_json::to_vec(self).map_err(error::malformed_jwt_payload)?);

        let expected_len = h_raw.encoded_len()
            + p_raw.encoded_len()
            + Base64Url::calc_encoded_len(alg.signature_size())
            + 2;

        let mut message = String::with_capacity(expected_len);
        write!(message, "{}.{}", h_raw, p_raw).expect("writes to strings never fail");

        let s = Base64Url::from_raw(jwk.sign(headers.alg(), message.as_bytes())?);

        write!(message, ".{}", s).expect("writes to strings never fail");

        debug_assert_eq!(message.len(), expected_len);

        Ok(Jwt::new(message))
    }
}

impl<P> CoreClaims for Claims<P> {
    fn aud(&self) -> &Audiences {
        &self.aud
    }

    fn iss(&self) -> Option<&IssuerRef> {
        self.iss.as_deref()
    }

    fn sub(&self) -> Option<&SubjectRef> {
        self.sub.as_deref()
    }

    fn exp(&self) -> Option<UnixTime> {
        self.exp
    }

    fn nbf(&self) -> Option<UnixTime> {
        self.nbf
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

    /// Sets the `sub` claim for the JWT
    pub fn with_subject(mut self, sub: impl Into<Subject>) -> Self {
        self.sub = Some(sub.into());
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
            sub: self.sub,
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
    use color_eyre::Result;

    use aliri_core::clock::TestClock;

    use super::*;

    #[test]
    fn deserialize_basic_claims() -> Result<()> {
        const DATA: &str = r#"{
                "nbf": 345,
                "iss": "me"
            }"#;

        let basic: Claims = serde_json::from_str(DATA)?;
        dbg!(&basic);

        Ok(())
    }

    #[test]
    #[cfg(feature = "rsa")]
    fn vdater() -> Result<(), error::ClaimsRejected> {
        let validation = CoreValidator::default()
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

        let clock = TestClock::new(UnixTime(7));

        let header = Headers::new(jwa::Algorithm::RS256);

        validation.validate_with_clock(&header, &claims, &clock)
    }

    #[test]
    #[cfg(feature = "hmac")]
    fn round_trip_hs256() -> Result<()> {
        round_trip_hmac(jwa::hmac::SigningAlgorithm::HS256)
    }

    #[test]
    #[cfg(feature = "hmac")]
    fn round_trip_hs384() -> Result<()> {
        round_trip_hmac(jwa::hmac::SigningAlgorithm::HS384)
    }

    #[test]
    #[cfg(feature = "hmac")]
    fn round_trip_hs512() -> Result<()> {
        round_trip_hmac(jwa::hmac::SigningAlgorithm::HS512)
    }

    #[cfg(feature = "hmac")]
    fn round_trip_hmac(alg: jwa::hmac::SigningAlgorithm) -> Result<()> {
        let key = jwa::Hmac::generate(alg).unwrap();

        println!("Secret (b64url): {}", key.secret());

        round_trip(key.into(), alg.into())
    }

    #[test]
    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    fn round_trip_rs256() -> Result<()> {
        round_trip_rsa(jwa::rsa::SigningAlgorithm::RS256)
    }

    #[test]
    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    fn round_trip_rs384() -> Result<()> {
        round_trip_rsa(jwa::rsa::SigningAlgorithm::RS384)
    }

    #[test]
    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    fn round_trip_rs512() -> Result<()> {
        round_trip_rsa(jwa::rsa::SigningAlgorithm::RS512)
    }

    #[test]
    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    fn round_trip_ps256() -> Result<()> {
        round_trip_rsa(jwa::rsa::SigningAlgorithm::PS256)
    }

    #[test]
    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    fn round_trip_ps384() -> Result<()> {
        round_trip_rsa(jwa::rsa::SigningAlgorithm::PS384)
    }

    #[test]
    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    fn round_trip_ps512() -> Result<()> {
        round_trip_rsa(jwa::rsa::SigningAlgorithm::PS512)
    }

    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    fn round_trip_rsa(alg: jwa::rsa::SigningAlgorithm) -> Result<()> {
        let key = jwa::Rsa::generate().unwrap();

        println!("Private:\n{}", key.private_key().unwrap().to_pem());
        println!("Public:\n{}", key.public_key().to_pem().unwrap());

        round_trip(key.into(), alg.into())
    }

    #[test]
    #[cfg(all(feature = "ec", feature = "private-keys"))]
    fn round_trip_es256() -> Result<()> {
        round_trip_ec(jwa::ec::SigningAlgorithm::ES256)
    }

    #[test]
    #[cfg(all(feature = "ec", feature = "private-keys"))]
    fn round_trip_es384() -> Result<()> {
        round_trip_ec(jwa::ec::SigningAlgorithm::ES384)
    }

    #[test]
    #[cfg(all(feature = "ec", feature = "private-keys"))]
    #[ignore = "not implemented"]
    fn round_trip_es512() -> Result<()> {
        round_trip_ec(jwa::ec::SigningAlgorithm::ES512)
    }

    #[cfg(all(feature = "ec", feature = "private-keys"))]
    fn round_trip_ec(alg: jwa::ec::SigningAlgorithm) -> Result<()> {
        let key = jwa::EllipticCurve::generate(alg.into()).unwrap();

        println!("Private:\n{}", key.private_key().unwrap().to_pem().unwrap());
        println!("Public:\n{}", key.public_key().to_pem());

        round_trip(key.into(), alg.into())
    }

    fn round_trip(jwk: Jwk, alg: jwa::Algorithm) -> Result<()> {
        let claims = Claims::new()
            .with_expiration(UnixTime(100))
            .with_issuer("Marcus");

        let headers = Headers::new(alg);

        let token = claims.sign(&jwk, &headers)?;

        println!("Token: {}", token);

        let validator = CoreValidator::default().ignore_expiration();

        let verified: Validated = token.verify(&jwk, &validator)?;

        assert_eq!(verified.claims(), &claims);
        assert_eq!(verified.headers(), &headers);

        Ok(())
    }
}
