use std::{future::Future, time::Duration};

use aliri_jose::{jwa, Audience, BasicValidation, CoreClaims, Issuer, IssuerRef, Jwks, KeyIdRef};
use jsonwebtoken::Algorithm;

use super::Directive;
use crate::TokenRef;

#[derive(Debug, Clone)]
pub struct JwksAuthority {
    jwks: Jwks,
    jwks_url: String,
    validator: BasicValidation,
}

impl JwksAuthority {
    pub fn new(issuer: Issuer, audience: Audience, grace_period: Option<Duration>) -> Self {
        const JWT_ALG: jwa::Algorithm = jwa::Algorithm::RS256;

        let jwks_url = format!("{}.well-known/jwks.json", issuer);

        let validator = BasicValidation::default()
            .add_approved_algorithm(JWT_ALG)
            .set_issuer(issuer)
            .add_allowed_audience(audience)
            .with_leeway(grace_period.unwrap_or_default());

        Self {
            jwks: Jwks::default(),
            jwks_url,
            validator,
        }
    }

    pub fn issuer(&self) -> &IssuerRef {
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

    pub async fn verify_token<T: for<'de> serde::Deserialize<'de> + CoreClaims + ScopeClaims>(
        &mut self,
        token: &TokenRef,
        directives: &[Directive],
    ) -> anyhow::Result<T> {
        let dec_head = jsonwebtoken::decode_header(token.as_str())?;
        let kid = dec_head
            .kid
            .ok_or_else(|| anyhow::anyhow!("missing kid in header"))?;
        let header_alg = dec_head.alg;
        let alg = jwk_algo_from_jsonwebtoken(header_alg)
            .ok_or_else(|| anyhow::anyhow!("unsupported algorithm type {:?}", header_alg))?;

        let key = self
            .jwks
            .get_key_by_id(KeyIdRef::from_str(&kid), alg)
            .next()
            .ok_or_else(|| anyhow::anyhow!("unable to find key with matching kid {}", kid))?;

        let claims: T = key.verify_token(token.as_str(), &self.validator)?;

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

impl ScopeClaims for aliri_jose::EmptyClaims {}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
struct Claims {
    aud: Audience,
    iss: Issuer,
    exp: u64,
}

impl<'a, T> crate::Authority<'a, T> for JwksAuthority
where
    T: for<'de> serde::Deserialize<'de> + CoreClaims + ScopeClaims + 'a,
{
    type Directive = &'a [super::Directive];
    type Verify = std::pin::Pin<Box<dyn Future<Output = Result<T, Self::VerifyError>> + 'a>>;
    type VerifyError = anyhow::Error;

    fn verify(&'a mut self, token: &'a TokenRef, dir: Self::Directive) -> Self::Verify {
        Box::pin(self.verify_token(token, dir))
    }
}

fn jwk_algo_from_jsonwebtoken(alg: Algorithm) -> Option<jwa::Algorithm> {
    match alg {
        Algorithm::RS256 => Some(jwa::Algorithm::RS256),
        Algorithm::RS384 => Some(jwa::Algorithm::RS384),
        Algorithm::RS512 => Some(jwa::Algorithm::RS512),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use aliri_jose::{jwa, jwk, EmptyClaims, Jwk, Jwks, KeyId};

    use crate::{oauth2::Directive, Authority as _};

    use super::*;

    #[tokio::test]
    async fn async_validate() -> anyhow::Result<()> {
        const ALG: jwa::Algorithm = jwa::Algorithm::RS256;
        let jwk_params = jwk::Parameters::generate(ALG)?;
        dbg!(&jwk_params);

        let test_kid = KeyId::new("test_key");
        let jwk = Jwk {
            id: Some(test_kid.clone()),
            usage: Some(jwk::Usage::Signing),
            algorithm: Some(ALG),
            params: jwk_params,
        };

        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(String::from("test_key"));

        let dur = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        let exp = dur + std::time::Duration::from_secs(90);
        dur.as_secs();

        let claims = Claims {
            aud: Audience::new("test_audience"),
            iss: Issuer::new("test_issuer"),
            exp: exp.as_secs(),
        };

        let encoded = jwk.sign(&header, &claims)?;

        dbg!(&encoded);

        let dec_head = jsonwebtoken::decode_header(&encoded)?;

        dbg!(&dec_head);

        let mut jwks = Jwks::default();
        jwks.add_key(jwk);

        let mut auth = JwksAuthority::new(
            Issuer::new("test_issuer"),
            Audience::new("test_audience"),
            Some(Duration::from_secs(60)),
        );
        auth.set_jwks(jwks);

        let both = Directive::new(vec![
            super::super::Scope::new("testing"),
            super::super::Scope::new("other"),
        ]);

        let t = Directive::new(vec![super::super::Scope::new("testing")]);

        let directives = vec![Directive::default(), both, t];

        let c: EmptyClaims = auth
            .verify(&TokenRef::from_str(&encoded), &directives)
            .await?;

        dbg!(c);

        Ok(())
    }

    #[tokio::test]
    #[cfg(any(feature = "reqwest"))]
    async fn request() -> anyhow::Result<()> {
        let mut authority = JwksAuthority::new(
            Issuer::new("https://demo.auth0.com/"),
            Audience::new("test"),
            None,
        );
        authority.refresh_jwks().await?;

        dbg!(authority);

        Ok(())
    }
}
