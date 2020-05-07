use std::future::Future;

use aliri_jose::{
    jwt::{self, CoreHeaders, HasAlgorithm},
    Jwks,
};

use super::Directive;
use crate::TokenRef;

#[derive(Debug, Clone)]
pub struct JwksAuthority {
    jwks: Jwks,
    jwks_url: String,
    validator: jwt::BasicValidation,
}

impl JwksAuthority {
    pub fn new(validator: jwt::BasicValidation) -> Self {
        let jwks_url = format!("{}.well-known/jwks.json", validator.issuer().unwrap());

        Self {
            jwks: Jwks::default(),
            jwks_url,
            validator,
        }
    }

    pub fn issuer(&self) -> &jwt::IssuerRef {
        self.validator.issuer().expect("always an issuer")
    }

    pub fn set_jwks(&mut self, jwks: Jwks) {
        self.jwks = jwks;
    }

    pub fn set_jwks_url(&mut self, url: String) {
        self.jwks_url = url;
    }

    #[cfg(feature = "reqwest")]
    async fn refresh_jwks_reqwest(&self) -> anyhow::Result<Jwks> {
        let jwks = reqwest::get(&self.jwks_url).await?.json::<Jwks>().await?;

        Ok(jwks)
    }

    #[cfg(any(feature = "reqwest"))]
    pub async fn refresh_jwks(&mut self) -> anyhow::Result<()> {
        let jwks = if cfg!(feature = "reqwest") {
            self.refresh_jwks_reqwest().await?
        } else {
            unreachable!()
        };

        self.jwks = jwks;

        Ok(())
    }

    pub async fn verify_token<
        T: for<'de> serde::Deserialize<'de> + jwt::CoreClaims + ScopeClaims,
    >(
        &mut self,
        token: &TokenRef,
        directives: &[Directive],
    ) -> anyhow::Result<T> {
        let decomposed: jwt::DecomposedJwt = jwt::DecomposedJwt::try_from_raw(token.as_str())?;

        let kid = decomposed.kid();
        let alg = decomposed.alg();

        let key = self.jwks.get_key_by_opt(kid, alg).next().ok_or_else(|| {
            if let Some(kid) = kid {
                anyhow::anyhow!("unable to find key with kid {} for alg {}", kid, alg)
            } else {
                anyhow::anyhow!("unable to find key for alg {}", alg)
            }
        })?;

        let data: jwt::TokenData<T> = key.verify_token(token.as_str(), &self.validator)?;
        let claims = data.claims;

        if directives.is_empty() {
            return Ok(claims);
        }

        let scopes = claims.scopes().iter().map(|r| r.as_ref()).collect();

        if directives.iter().any(|d| d.validate(&scopes)) {
            Ok(claims)
        } else {
            Err(anyhow::anyhow!("missing required scopes"))
        }
    }
}

lazy_static::lazy_static! {
    static ref SCOPES: Vec<super::Scope> = vec![
        // super::Scope::new("other"),
        // super::Scope::new("testing"),
    ];
}

pub trait ScopeClaims {
    fn scopes(&self) -> &[super::Scope] {
        &*SCOPES
    }
}

impl ScopeClaims for jwt::EmptyClaims {}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
struct Claims {
    aud: jwt::Audience,
    iss: jwt::Issuer,
    exp: u64,
}

impl<'a, T> crate::Authority<'a, T> for JwksAuthority
where
    T: for<'de> serde::Deserialize<'de> + jwt::CoreClaims + ScopeClaims + 'a,
{
    type Directive = &'a [super::Directive];
    type Verify = std::pin::Pin<Box<dyn Future<Output = Result<T, Self::VerifyError>> + 'a>>;
    type VerifyError = anyhow::Error;

    fn verify(&'a mut self, token: &'a TokenRef, dir: Self::Directive) -> Self::Verify {
        Box::pin(self.verify_token(token, dir))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aliri_jose::{jwk, jws, jwt, Jwk, Jwks};

    use crate::{oauth2::Directive, Authority};

    use super::*;

    #[tokio::test]
    #[cfg(feature = "rsa")]
    async fn async_validate_rs256() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::RS256).await
    }

    #[tokio::test]
    #[cfg(feature = "rsa")]
    async fn async_validate_rs384() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::RS384).await
    }

    #[tokio::test]
    #[cfg(feature = "rsa")]
    async fn async_validate_rs512() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::RS512).await
    }

    #[tokio::test]
    #[cfg(feature = "rsa")]
    async fn async_validate_ps256() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::PS256).await
    }

    #[tokio::test]
    #[cfg(feature = "rsa")]
    async fn async_validate_ps384() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::PS384).await
    }

    #[tokio::test]
    #[cfg(feature = "rsa")]
    async fn async_validate_ps512() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::PS512).await
    }

    #[tokio::test]
    #[cfg(feature = "hmac")]
    async fn async_validate_hs256() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::HS256).await
    }

    #[tokio::test]
    #[cfg(feature = "hmac")]
    async fn async_validate_hs384() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::HS384).await
    }

    #[tokio::test]
    #[cfg(feature = "hmac")]
    async fn async_validate_hs512() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::HS512).await
    }

    #[tokio::test]
    #[cfg(feature = "ec")]
    async fn async_validate_es256() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::ES256).await
    }

    #[tokio::test]
    #[cfg(feature = "ec")]
    async fn async_validate_es384() -> anyhow::Result<()> {
        async_validate(jws::Algorithm::ES384).await
    }

    async fn async_validate(alg: jws::Algorithm) -> anyhow::Result<()> {
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

        let header = aliri_jose::test::MinimalHeaders::new(alg).with_key_id(test_kid);

        let claims = aliri_jose::test::MinimalClaims::default()
            .with_audience(test_audience.clone())
            .with_issuer(test_issuer.clone())
            .with_future_expiration(60 * 5);

        let encoded = jwk.sign(&header, &claims)?;
        dbg!(&encoded);

        let mut jwks = Jwks::default();
        jwks.add_key(jwk);

        let validator = jwt::BasicValidation::default()
            .add_approved_algorithm(alg)
            .set_issuer(test_issuer)
            .add_allowed_audience(test_audience)
            .with_leeway(Duration::from_secs(60));

        let mut auth = JwksAuthority::new(validator);
        auth.set_jwks(jwks);

        let both = Directive::new(vec![
            super::super::Scope::new("testing"),
            super::super::Scope::new("other"),
        ]);

        let t = Directive::new(vec![super::super::Scope::new("testing")]);

        let directives = vec![Directive::default(), both, t];

        let c: jwt::EmptyClaims = auth
            .verify(&TokenRef::from_str(&encoded), &directives)
            .await?;

        dbg!(c);

        Ok(())
    }

    #[tokio::test]
    #[cfg(all(any(feature = "reqwest"), feature = "rsa"))]
    async fn request() -> anyhow::Result<()> {
        let validator = jwt::BasicValidation::default()
            .add_approved_algorithm(jws::Algorithm::RS256)
            .set_issuer(jwt::Issuer::new("https://demo.auth0.com/"))
            .add_allowed_audience(jwt::Audience::new("test"))
            .with_leeway(Duration::from_secs(0));

        let mut authority = JwksAuthority::new(validator);
        authority.refresh_jwks().await?;

        dbg!(authority);

        Ok(())
    }
}
