use std::{future::Future, pin::Pin};

use aliri::{Authority, Policy};
use aliri_jose::{
    jwt::{self, CoreHeaders, HasAlgorithm},
    Jwks, JwtRef,
};
use serde::Deserialize;

use super::AuthorityError;
use crate::{HasScopes, ScopesPolicy};

/// An authority backed by a local JSON Web Key Set (JWKS)
#[derive(Debug, Clone)]
pub struct LocalAuthority {
    jwks: Jwks,
    validator: jwt::CoreValidator,
}

impl LocalAuthority {
    /// Constructs a new JWKS Authority
    pub fn new(jwks: Jwks, validator: jwt::CoreValidator) -> Self {
        Self { jwks, validator }
    }

    /// Explicitly sets the JWKS to be used for validation
    pub fn set_jwks(&mut self, jwks: Jwks) {
        self.jwks = jwks;
    }

    /// Authenticates the token and checks access according to the policy
    pub fn verify_token<'a, T, J, P>(
        &self,
        token: J,
        policy: P,
    ) -> Result<jwt::Claims<T>, AuthorityError>
    where
        T: for<'de> Deserialize<'de> + HasScopes,
        J: AsRef<JwtRef>,
        P: AsRef<ScopesPolicy>,
    {
        self.verify_impl(token.as_ref(), policy.as_ref())
    }

    fn verify_impl<T>(
        &self,
        token: &JwtRef,
        policy: &ScopesPolicy,
    ) -> Result<jwt::Claims<T>, AuthorityError>
    where
        T: for<'de> Deserialize<'de> + HasScopes,
    {
        let decomposed = token.decompose()?;

        let key = {
            let kid = decomposed.kid();
            let alg = decomposed.alg();

            self.jwks.get_key_by_opt(kid, alg).ok_or_else(|| {
                if let Some(kid) = kid {
                    tracing::debug!(%kid, %alg, "unable to find matching key")
                } else {
                    tracing::debug!(%alg, "unable to find matching key")
                }
                AuthorityError::UnknownKeyId
            })?
        };

        let data: jwt::Validated<T> = decomposed.verify(key, &self.validator)?;

        policy.evaluate(data.claims().payload().scopes())?;

        let (_, claims) = data.take();

        Ok(claims)
    }
}

impl<'a, T> Authority<'a, jwt::Claims<T>> for LocalAuthority
where
    T: for<'de> Deserialize<'de> + HasScopes + 'a,
{
    type Policy = &'a ScopesPolicy;
    type Token = &'a JwtRef;
    #[allow(clippy::type_complexity)]
    type VerifyFuture =
        Pin<Box<dyn Future<Output = Result<jwt::Claims<T>, Self::VerifyError>> + Send + Sync + 'a>>;
    type VerifyError = AuthorityError;

    fn verify(&'a self, token: Self::Token, dir: Self::Policy) -> Self::VerifyFuture {
        Box::pin(async move { self.verify_impl(token, dir) })
    }
}

#[cfg(test)]
#[cfg(never)]
mod tests {
    use std::time::Duration;

    use aliri_jose::{jwk, jws, jwt, Jwk};
    use color_eyre::Result;

    use super::*;
    use crate::Scopes;

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    async fn async_validate_rs256() -> Result<()> {
        async_validate(jws::Algorithm::RS256).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    async fn async_validate_rs384() -> Result<()> {
        async_validate(jws::Algorithm::RS384).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    async fn async_validate_rs512() -> Result<()> {
        async_validate(jws::Algorithm::RS512).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    async fn async_validate_ps256() -> Result<()> {
        async_validate(jws::Algorithm::PS256).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    async fn async_validate_ps384() -> Result<()> {
        async_validate(jws::Algorithm::PS384).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    async fn async_validate_ps512() -> Result<()> {
        async_validate(jws::Algorithm::PS512).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "hmac")]
    async fn async_validate_hs256() -> Result<()> {
        async_validate(jws::Algorithm::HS256).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "hmac")]
    async fn async_validate_hs384() -> Result<()> {
        async_validate(jws::Algorithm::HS384).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "hmac")]
    async fn async_validate_hs512() -> Result<()> {
        async_validate(jws::Algorithm::HS512).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "ec")]
    async fn async_validate_es256() -> Result<()> {
        async_validate(jws::Algorithm::ES256).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "ec")]
    async fn async_validate_es384() -> Result<()> {
        async_validate(jws::Algorithm::ES384).await
    }

    async fn async_validate(alg: jws::Algorithm) -> Result<()> {
        let jwk_params = jwk::Parameters::generate(alg)?;
        dbg!(&jwk_params);

        let test_kid = jwk::KeyId::new("test_key");
        let test_issuer = jwt::Issuer::new("test_issuer");
        let test_audience = jwt::Audience::new("test_audience");

        let jwk = Jwk {
            id: Some(test_kid.clone()),
            usage: Some(jwk::Usage::Signing),
            algorithm: Some(alg),
            params: jwk_params,
        };

        let header = jwt::Headers::new(alg.into()).with_key_id(test_kid);

        let claims = jwt::Claims::new()
            .with_audience(test_audience.clone())
            .with_issuer(test_issuer.clone())
            .with_future_expiration(60 * 5);

        let encoded = jwk.sign(&header, &claims)?;
        dbg!(&encoded);

        let mut jwks = Jwks::default();
        jwks.add_key(jwk);

        let validator = jwt::Validation::default()
            .add_approved_algorithm(alg.into())
            .require_issuer(test_issuer)
            .add_allowed_audience(test_audience)
            .with_leeway(Duration::from_secs(60));

        let auth = LocalAuthority::new(jwks, validator);

        let both = Scopes::from_scopes(vec!["testing", "other"]);

        let t = Scopes::single("testing");

        let mut policy = ScopesPolicy::deny_all();
        policy.allow(both);
        policy.allow(t);
        policy.allow(Scopes::empty());

        let c: jwt::Empty = auth.verify(&encoded, &policy).await?;

        dbg!(c);

        Ok(())
    }
}
