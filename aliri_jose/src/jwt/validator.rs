use std::{convert::Infallible, marker::PhantomData};

use regex::Regex;

pub trait Validator<T> {
    type Error;

    fn validate(&self, data: &T) -> Result<(), Self::Error>;
}

impl<T, A> ValidatorExt<T> for A where A: Validator<T> {}

pub trait ValidatorExt<T>: Validator<T> {
    #[inline]
    fn map_err<E, F>(self, f: F) -> MapErr<Self, F>
    where
        F: Fn(Self::Error) -> E,
        Self: Sized,
    {
        MapErr { inner: self, f }
    }

    #[inline]
    fn from_err<E>(self) -> FromErr<Self, E>
    where
        E: From<Self::Error>,
        Self: Sized,
    {
        FromErr {
            inner: self,
            _err: PhantomData,
        }
    }

    #[inline]
    fn and<V>(self, next: V) -> And<Self, V>
    where
        V: Validator<T>,
        Self: Sized,
    {
        And {
            first: self,
            second: next,
        }
    }

    #[inline]
    fn not<V>(self) -> Not<Self>
    where
        V: Validator<T>,
        Self: Sized,
    {
        Not { inner: self }
    }

    #[inline]
    fn unify_err<E>(self) -> UnifyErr<Self, E>
    where
        Self: Sized,
    {
        UnifyErr {
            inner: self,
            _err: PhantomData,
        }
    }

    #[inline]
    fn typed(self) -> TypedValidator<T, Self>
    where
        Self: Sized,
    {
        TypedValidator {
            inner: self,
            _t: PhantomData,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Either<A, B> {
    A(A),
    B(B),
}

pub struct All<V, Err> {
    inner: V,
    _err: PhantomData<*const Err>,
}

impl<V, Err> All<V, Err> {
    pub fn new<T>(validators: V) -> Self
    where
        All<V, Err>: Validator<T>,
    {
        All {
            inner: validators,
            _err: PhantomData,
        }
    }
}

pub struct UnifyErr<V, E> {
    inner: V,
    _err: PhantomData<*const E>,
}

impl<V, T, E, A, B> Validator<T> for UnifyErr<V, E>
where
    V: Validator<T, Error = Either<A, B>>,
    E: From<A> + From<B>,
{
    type Error = E;

    #[inline]
    fn validate(&self, data: &T) -> Result<(), Self::Error> {
        match self.inner.validate(data) {
            Ok(()) => Ok(()),
            Err(Either::A(err)) => Err(err.into()),
            Err(Either::B(err)) => Err(err.into()),
        }
    }
}

pub struct MapErr<V, F> {
    inner: V,
    f: F,
}

impl<V, T, E, F> Validator<T> for MapErr<V, F>
where
    V: Validator<T>,
    F: Fn(V::Error) -> E,
{
    type Error = E;

    #[inline]
    fn validate(&self, data: &T) -> Result<(), Self::Error> {
        match self.inner.validate(data) {
            Ok(()) => Ok(()),
            Err(err) => Err((&self.f)(err)),
        }
    }
}

pub struct FromErr<V, E> {
    inner: V,
    _err: PhantomData<*const E>,
}

impl<V, T, E> Validator<T> for FromErr<V, E>
where
    V: Validator<T>,
    E: From<V::Error>,
{
    type Error = E;

    #[inline]
    fn validate(&self, data: &T) -> Result<(), Self::Error> {
        match self.inner.validate(data) {
            Ok(()) => Ok(()),
            Err(err) => Err(E::from(err)),
        }
    }
}

struct NeverValid<T> {
    _t: PhantomData<*const T>,
}

#[derive(Debug, PartialEq)]
struct AlwaysFails;

impl<T> NeverValid<T> {
    #[inline]
    const fn new() -> Self {
        NeverValid { _t: PhantomData }
    }
}

impl<T> Validator<T> for NeverValid<T> {
    type Error = AlwaysFails;

    #[inline]
    fn validate(&self, _: &T) -> Result<(), Self::Error> {
        Err(AlwaysFails)
    }
}

struct AlwaysValid<T> {
    _t: PhantomData<*const T>,
}

impl<T> AlwaysValid<T> {
    #[inline]
    const fn new() -> Self {
        AlwaysValid { _t: PhantomData }
    }
}

impl<T> Validator<T> for AlwaysValid<T> {
    type Error = Infallible;

    #[inline]
    fn validate(&self, _: &T) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct And<A, B> {
    first: A,
    second: B,
}

impl<A, B, T> Validator<T> for And<A, B>
where
    A: Validator<T>,
    B: Validator<T>,
{
    type Error = Either<A::Error, B::Error>;

    #[inline]
    fn validate(&self, data: &T) -> Result<(), Self::Error> {
        self.first.validate(data).map_err(Either::A)?;
        self.second.validate(data).map_err(Either::B)?;
        Ok(())
    }
}

pub struct Not<V> {
    inner: V,
}

#[derive(Debug, PartialEq)]
pub struct NotError;

impl<V, T> Validator<T> for Not<V>
where
    V: Validator<T>,
{
    type Error = NotError;

    #[inline]
    fn validate(&self, data: &T) -> Result<(), Self::Error> {
        if let Ok(()) = self.inner.validate(data) {
            Err(NotError)
        } else {
            Ok(())
        }
    }
}

struct EqValidator<T> {
    value: T,
}

impl<T> EqValidator<T> {
    #[inline]
    const fn equals(value: T) -> Self {
        Self { value }
    }
}

#[derive(Debug, PartialEq)]
struct NotEqual;

impl<T, U> Validator<T> for EqValidator<U>
where
    T: PartialEq<U>,
{
    type Error = NotEqual;

    #[inline]
    fn validate(&self, data: &T) -> Result<(), Self::Error> {
        if data.eq(&self.value) {
            Ok(())
        } else {
            Err(NotEqual)
        }
    }
}

pub struct RegexValidator {
    regex: Regex,
}

impl RegexValidator {
    #[inline]
    const fn regex(regex: Regex) -> Self {
        Self { regex }
    }
}

#[derive(Debug, PartialEq)]
pub struct NoMatch;

impl<S> Validator<S> for RegexValidator
where
    S: AsRef<str>,
{
    type Error = NoMatch;

    #[inline]
    fn validate(&self, data: &S) -> Result<(), Self::Error> {
        if self.regex.is_match(data.as_ref()) {
            Ok(())
        } else {
            Err(NoMatch)
        }
    }
}

impl<H, P> Validator<(H, P)> for super::CoreValidator
where
    H: super::CoreHeaders,
    P: super::CoreClaims,
{
    type Error = crate::error::ClaimsRejected;

    #[inline]
    fn validate(&self, data: &(H, P)) -> Result<(), Self::Error> {
        self.validate(&data.0, &data.1)
    }
}

pub struct TypedValidator<T, V> {
    inner: V,
    _t: PhantomData<*const T>,
}

impl<T, V> Validator<T> for TypedValidator<T, V>
where
    V: Validator<T>,
{
    type Error = V::Error;

    #[inline]
    fn validate(&self, data: &T) -> Result<(), Self::Error> {
        self.inner.validate(data)
    }
}

impl<H, P> Validator<(H, P)> for crate::jwa::Algorithm
where
    H: super::HasAlgorithm,
{
    type Error = crate::error::ClaimsRejected;

    #[inline]
    fn validate(&self, data: &(H, P)) -> Result<(), Self::Error> {
        if *self == data.0.alg() {
            Ok(())
        } else {
            Err(crate::error::ClaimsRejected::InvalidAlgorithm)
        }
    }
}

pub trait HasAudience {
    fn aud(&self) -> &super::Audiences;
}

impl<C> HasAudience for super::Claims<C> {
    #[inline]
    fn aud(&self) -> &super::Audiences {
        &self.aud
    }
}

impl<H, C> Validator<(H, C)> for &'_ super::AudienceRef
where
    C: HasAudience,
{
    type Error = crate::error::ClaimsRejected;

    #[inline]
    fn validate(&self, data: &(H, C)) -> Result<(), Self::Error> {
        if data.1.aud().iter().any(|aud| aud == *self) {
            Ok(())
        } else {
            Err(crate::error::ClaimsRejected::InvalidAudience)
        }
    }
}

impl<H, C> Validator<(H, C)> for super::Audience
where
    C: HasAudience,
{
    type Error = crate::error::ClaimsRejected;

    #[inline]
    fn validate(&self, data: &(H, C)) -> Result<(), Self::Error> {
        self.as_ref().validate(data)
    }
}

pub trait HasIssuer {
    fn iss(&self) -> Option<&super::IssuerRef>;
}

impl<C> HasIssuer for super::Claims<C> {
    #[inline]
    fn iss(&self) -> Option<&super::IssuerRef> {
        self.iss.as_deref()
    }
}

impl<H, C> Validator<(H, C)> for &'_ super::IssuerRef
where
    C: HasIssuer,
{
    type Error = crate::error::ClaimsRejected;

    #[inline]
    fn validate(&self, data: &(H, C)) -> Result<(), Self::Error> {
        if let Some(iss) = data.1.iss() {
            if iss == *self {
                Ok(())
            } else {
                Err(crate::error::ClaimsRejected::InvalidIssuer)
            }
        } else {
            Err(crate::error::ClaimsRejected::MissingRequiredClaim("iss"))
        }
    }
}

impl<H, C> Validator<(H, C)> for super::Issuer
where
    C: HasIssuer,
{
    type Error = crate::error::ClaimsRejected;

    #[inline]
    fn validate(&self, data: &(H, C)) -> Result<(), Self::Error> {
        self.as_ref().validate(data)
    }
}

pub struct Timing<Clock = aliri_core::clock::System> {
    pub validate_exp: bool,
    pub validate_nbf: bool,
    pub leeway: u64,
    pub clock: Clock,
}

pub trait HasTiming {
    fn exp(&self) -> Option<aliri_core::clock::UnixTime>;
    fn iat(&self) -> Option<aliri_core::clock::UnixTime>;
    fn nbf(&self) -> Option<aliri_core::clock::UnixTime>;
}

impl<C> HasTiming for super::Claims<C> {
    #[inline]
    fn exp(&self) -> Option<aliri_core::clock::UnixTime> {
        self.exp
    }

    #[inline]
    fn iat(&self) -> Option<aliri_core::clock::UnixTime> {
        None
    }

    #[inline]
    fn nbf(&self) -> Option<aliri_core::clock::UnixTime> {
        self.nbf
    }
}

impl<H, C, Clock> Validator<(H, C)> for Timing<Clock>
where
    Clock: aliri_core::clock::Clock,
    C: HasTiming,
{
    type Error = crate::error::ClaimsRejected;

    #[inline]
    fn validate(&self, data: &(H, C)) -> Result<(), Self::Error> {
        let now = self.clock.now();

        if self.validate_exp {
            if let Some(exp) = data.1.exp() {
                if exp.0 < now.0.saturating_sub(self.leeway) {
                    return Err(crate::error::ClaimsRejected::TokenExpired);
                }
            } else {
                return Err(crate::error::ClaimsRejected::MissingRequiredClaim("exp"));
            }
        }

        if self.validate_nbf {
            if let Some(nbf) = data.1.nbf() {
                if nbf.0 > now.0.saturating_add(self.leeway) {
                    return Err(crate::error::ClaimsRejected::TokenNotYetValid);
                }
            } else {
                return Err(crate::error::ClaimsRejected::MissingRequiredClaim("nbf"));
            }
        }

        Ok(())
    }
}

struct DecomposedJwt<H, C> {
    headers: H,
    claims: C,
}

macro_rules! all_impl {
    ($($t:tt : $i:tt),*) => {
        impl<T, $($t,)* Err> Validator<T> for All<($($t,)*), Err>
        where
            $(
                $t: Validator<T>,
                Err: From<$t::Error>,
            )*
        {
            type Error = Err;

            #[inline]
            fn validate(&self, data: &T) -> Result<(), Self::Error> {
                $(
                    self.inner.$i.validate(data)?;
                )*
                Ok(())
            }
        }
    };
}

all_impl!(A: 0);
all_impl!(A: 0, B: 1);
all_impl!(A: 0, B: 1, C: 2);
all_impl!(A: 0, B: 1, C: 2, D: 3);
all_impl!(A: 0, B: 1, C: 2, D: 3, E: 4);
all_impl!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5);
all_impl!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6);
all_impl!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7);
all_impl!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8);
all_impl!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9);
all_impl!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7, I: 8, J: 9, K: 10);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_valid() {
        assert!(AlwaysValid::new().validate(&()).is_ok());
    }

    #[test]
    fn never_valid() {
        assert!(NeverValid::new().validate(&()).is_err());
    }

    #[test]
    fn map_err_invalid() {
        #[derive(Debug, PartialEq)]
        struct TestError;

        fn to_test_err(_: AlwaysFails) -> TestError {
            TestError
        }

        assert_eq!(
            Err(TestError),
            NeverValid::new().map_err(to_test_err).validate(&())
        );
    }

    #[test]
    fn from_err_invalid() {
        #[derive(Debug, PartialEq)]
        struct TestError;

        impl From<AlwaysFails> for TestError {
            fn from(_: AlwaysFails) -> Self {
                TestError
            }
        }

        assert_eq!(Err(TestError), NeverValid::new().from_err().validate(&()));
    }

    #[test]
    fn map_err_valid() {
        #[derive(Debug, PartialEq)]
        struct TestError;

        fn to_test_err<E>(_: E) -> TestError {
            TestError
        }

        assert_eq!(
            Ok(()),
            AlwaysValid::new().map_err(to_test_err).validate(&())
        );
    }

    #[test]
    fn from_err_valid() {
        #[derive(Debug, PartialEq)]
        struct TestError;

        impl From<Infallible> for TestError {
            fn from(_: Infallible) -> Self {
                TestError
            }
        }

        assert_eq!(
            Ok::<_, TestError>(()),
            AlwaysValid::new().from_err().validate(&())
        );
    }

    #[test]
    fn eq_match_neq() {
        let equals = EqValidator::equals("test");
        let to_test = String::from("TEST");

        assert_eq!(Err(NotEqual), equals.validate(&to_test));
    }

    #[test]
    fn core_validator() {
        let issuer = crate::jwt::Issuer::new("issuer");
        let audience = crate::jwt::Audience::new("audience");

        let header = crate::jwt::Headers::new(crate::jwa::Algorithm::HS512);
        let claims = crate::jwt::Claims::new()
            .with_issuer(issuer.clone())
            .with_audience(audience.clone())
            .with_future_expiration(60);

        let validator = crate::jwt::CoreValidator::default()
            .require_issuer(issuer)
            .add_allowed_audience(audience)
            .add_approved_algorithm(crate::jwa::Algorithm::HS512);

        assert_eq!(
            Ok(()),
            Validator::<_>::validate(&validator, &(header, claims))
        );
    }

    #[test]
    fn core_validator_fail() {
        let issuer = crate::jwt::Issuer::new("issuer");
        let audience = crate::jwt::Audience::new("audience");

        let header = crate::jwt::Headers::new(crate::jwa::Algorithm::HS512);
        let claims = crate::jwt::Claims::new()
            .with_issuer(issuer.clone())
            .with_audience(audience.clone())
            .with_expiration(aliri_core::clock::UnixTime(0));

        let validator = crate::jwt::CoreValidator::default()
            .require_issuer(issuer)
            .add_allowed_audience(audience)
            .add_approved_algorithm(crate::jwa::Algorithm::HS512);

        assert_eq!(
            Err(crate::error::ClaimsRejected::TokenExpired),
            Validator::<_>::validate(&validator, &(header, claims))
        );
    }

    #[test]
    fn core_validator_fail_2() {
        let issuer = crate::jwt::Issuer::new("issuer");
        let audience = crate::jwt::Audience::new("audience");

        let header = crate::jwt::Headers::new(crate::jwa::Algorithm::HS512);
        let claims = crate::jwt::Claims::new()
            .with_issuer(issuer.clone())
            .with_audience(audience.clone())
            .with_future_expiration(60);

        let validator = crate::jwt::CoreValidator::default()
            .add_approved_algorithm(crate::jwa::Algorithm::HS512)
            .typed()
            .and(issuer)
            .unify_err::<crate::error::ClaimsRejected>()
            .and(audience)
            .unify_err::<crate::error::ClaimsRejected>()
            .and(crate::jwa::Algorithm::HS256)
            .unify_err::<crate::error::ClaimsRejected>()
            .and(crate::jwa::Algorithm::HS384)
            .unify_err::<crate::error::ClaimsRejected>();

        assert_eq!(
            Err(crate::error::ClaimsRejected::InvalidAlgorithm),
            Validator::<_>::validate(&validator, &(header, claims))
        );
    }

    #[test]
    fn core_validator_fail_3() {
        let issuer = crate::jwt::Issuer::new("issuer");
        let audience = crate::jwt::Audience::new("audience");

        let header = crate::jwt::Headers::new(crate::jwa::Algorithm::HS512);
        let claims = crate::jwt::Claims::new()
            .with_issuer(issuer.clone())
            .with_audience(audience.clone())
            .with_future_expiration(60);

        let validator = All::<_, crate::error::ClaimsRejected>::new::<(
            crate::jwt::Headers,
            crate::jwt::Claims,
        )>((crate::jwa::Algorithm::HS512, issuer, audience));

        assert_eq!(
            Ok(()),
            Validator::<_>::validate(&validator, &(header, claims))
        );
    }
}
