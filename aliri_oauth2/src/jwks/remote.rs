use std::{future::Future, pin::Pin, sync::Arc};

use aliri::{Authority, Policy};
use aliri_jose::{
    jwt::{self, CoreHeaders, HasAlgorithm},
    Jwks, JwtRef,
};
use arc_swap::ArcSwap;
use reqwest::{
    header::{self, HeaderValue},
    Client, StatusCode,
};
use serde::Deserialize;

use crate::{HasScopes, ScopesPolicy};

#[derive(Debug, Clone)]
struct VolatileData {
    jwks: Jwks,
    etag: Option<HeaderValue>,
}

/// An authority backed by a potentially dynamic JSON Web Key Set (JWKS)
/// held by a remote source
#[derive(Debug, Clone)]
pub struct RemoteAuthority {
    data: ArcSwap<VolatileData>,
    jwks_url: String,
    client: Client,
    validator: jwt::CoreValidator,
}

impl RemoteAuthority {
    /// Constructs a new JWKS authority
    pub async fn new(jwks_url: String, validator: jwt::CoreValidator) -> anyhow::Result<Self> {
        let client = Client::builder()
            .user_agent(concat!("aliri_oauth2/", env!("CARGO_PKG_VERSION")))
            .build()?;

        let response = client.get(&jwks_url).send().await?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("remote JWKS authority returned an error"));
        }

        let etag = response.headers().get(header::ETAG).map(ToOwned::to_owned);
        let jwks = response.json::<Jwks>().await?;

        let data = VolatileData { etag, jwks };

        Ok(Self {
            data: ArcSwap::from_pointee(data),
            jwks_url,
            client,
            validator,
        })
    }

    /// Refreshes the JWKS from the remote URL
    ///
    /// No retries are attempted. If the attempt to refresh the JWKS from
    /// the remote URL fails, no change is made to the internal JWKS.
    pub async fn refresh(&self) -> anyhow::Result<()> {
        let mut request = self.client.get(&self.jwks_url);

        if let Some(etag) = &self.data.load().etag {
            request = request.header(header::IF_NONE_MATCH, etag)
        }

        let response = request.send().await?;

        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(());
        } else if !response.status().is_success() {
            return Err(anyhow::anyhow!("remote JWKS authority returned an error"));
        }

        let etag = response.headers().get("etag").map(ToOwned::to_owned);
        let jwks = response.json::<Jwks>().await?;

        let data = Arc::new(VolatileData { etag, jwks });

        self.data.store(data);

        Ok(())
    }

    /// Authenticates the token and checks access according to the policy
    pub fn verify_token<'a, T, J, P>(&self, token: J, policy: P) -> anyhow::Result<jwt::Claims<T>>
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
    ) -> anyhow::Result<jwt::Claims<T>>
    where
        T: for<'de> Deserialize<'de> + HasScopes,
    {
        let decomposed = token.decompose()?;

        let validated: jwt::Validated<T>;
        {
            let guard = self.data.load();

            let key = {
                let kid = decomposed.kid();
                let alg = decomposed.alg();

                guard.jwks.get_key_by_opt(kid, alg).ok_or_else(|| {
                    if let Some(kid) = kid {
                        anyhow::anyhow!("unable to find key with kid {} for alg {}", kid, alg)
                    } else {
                        anyhow::anyhow!("unable to find key for alg {}", alg)
                    }
                })?
            };

            validated = decomposed.verify(key, &self.validator)?;
        }

        policy.evaluate(validated.claims().payload().scopes())?;

        let (_, validated_claims) = validated.take();

        Ok(validated_claims)
    }
}

impl<'a, T> Authority<'a, jwt::Claims<T>> for RemoteAuthority
where
    T: for<'de> Deserialize<'de> + HasScopes + 'a,
{
    type Policy = &'a ScopesPolicy;
    type Token = &'a JwtRef;
    type VerifyFuture =
        Pin<Box<dyn Future<Output = Result<jwt::Claims<T>, Self::VerifyError>> + Send + Sync + 'a>>;
    type VerifyError = anyhow::Error;

    fn verify(&'a self, token: Self::Token, dir: Self::Policy) -> Self::VerifyFuture {
        Box::pin(async move { self.verify_impl(token, dir) })
    }
}
