use crate::{oauth2::HasScope, ScopePolicy};
use aliri::{
    jwt::{self, CoreHeaders, HasAlgorithm},
    Jwks, JwtRef,
};
use aliri_traits::Policy;
use arc_swap::ArcSwap;
#[cfg(feature = "reqwest")]
use reqwest::{
    header::{self, HeaderValue},
    Client, StatusCode,
};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use thiserror::Error;

/// Indicates the requester held insufficient scopes to be granted access
/// to a controlled resource
#[derive(Debug, Error)]
pub enum AuthorityError {
    /// Indicates that the authority cannot verify the JWT because it cannot
    /// find a key which matches the specifications in the token header
    #[error("no matching key found to validate JWT")]
    UnknownKeyId,
    /// Indicates that the JWT was malformed or otherwise defective
    #[error("invalid JWT")]
    JwtVerifyError(#[from] aliri::error::JwtVerifyError),
    /// Indicates that, while the JWT was acceptable, it does not grant the
    /// level of authorization requested.
    #[error("access denied by policy")]
    PolicyDenial(#[from] crate::InsufficientScope),
}

#[derive(Debug)]
struct VolatileData {
    jwks: Jwks,
    #[cfg(feature = "reqwest")]
    etag: Option<HeaderValue>,
    #[cfg(feature = "reqwest")]
    last_modified: Option<HeaderValue>,
}

impl VolatileData {
    fn new(jwks: Jwks) -> Self {
        Self {
            jwks,
            #[cfg(feature = "reqwest")]
            etag: None,
            #[cfg(feature = "reqwest")]
            last_modified: None,
        }
    }
}

#[derive(Debug)]
#[cfg(feature = "reqwest")]
struct RemoteOptions {
    jwks_url: String,
    client: Client,
}

#[derive(Debug)]
struct Inner {
    data: ArcSwap<VolatileData>,
    #[cfg(feature = "reqwest")]
    remote: Option<RemoteOptions>,
    validator: jwt::CoreValidator,
}

/// An authority backed by a potentially dynamic JSON Web Key Set (JWKS)
/// held by a remote source
#[derive(Debug, Clone)]
#[must_use]
pub struct Authority {
    inner: Arc<Inner>,
}

impl Authority {
    /// Constructs a new JWKS authority from an existing JWKS
    pub fn new(jwks: Jwks, validator: jwt::CoreValidator) -> Self {
        let data = VolatileData::new(jwks);

        Self {
            inner: Arc::new(Inner {
                data: ArcSwap::from_pointee(data),
                #[cfg(feature = "reqwest")]
                remote: None,
                validator,
            }),
        }
    }

    /// Constructs a new JWKS authority from a URL
    #[cfg(feature = "reqwest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
    pub async fn new_from_url(
        jwks_url: String,
        validator: jwt::CoreValidator,
    ) -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .user_agent(concat!("aliri_oauth2/", env!("CARGO_PKG_VERSION")))
            .build()?;

        let response = client.get(&jwks_url).send().await?;
        response.error_for_status_ref()?;

        let etag = response.headers().get(header::ETAG).map(ToOwned::to_owned);
        let last_modified = response
            .headers()
            .get(header::LAST_MODIFIED)
            .map(ToOwned::to_owned);
        let jwks = response.json::<Jwks>().await?;

        let data = VolatileData {
            jwks,
            etag,
            last_modified,
        };

        tracing::info!(jwks.url = %jwks_url, "JWKS refreshed");

        Ok(Self {
            inner: Arc::new(Inner {
                data: ArcSwap::from_pointee(data),
                remote: Some(RemoteOptions { jwks_url, client }),
                validator,
            }),
        })
    }

    /// A non-terminating future that will automatically refresh the JWKS
    /// using the configured interval
    #[cfg(feature = "tokio")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
    pub fn spawn_refresh(&self, interval: Duration) {
        let this = self.clone();

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.tick().await;

            loop {
                timer.tick().await;
                // Ignore any errors; we'll just try again next time
                let _ = this.refresh().await;
            }
        });
    }

    /// Refreshes the JWKS from the remote URL
    ///
    /// No retries are attempted. If the attempt to refresh the JWKS from
    /// the remote URL fails, no change is made to the internal JWKS.
    #[cfg(feature = "reqwest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
    #[tracing::instrument(skip(self), fields(jwks.url = tracing::field::Empty))]
    pub async fn refresh(&self) -> Result<(), reqwest::Error> {
        if let Some(remote) = &self.inner.remote {
            let span = tracing::Span::current();
            span.record("jwks.url", &remote.jwks_url);
            tracing::debug!("refreshing JWKS");
            let mut request = remote.client.get(&remote.jwks_url);

            {
                let data = self.inner.data.load();
                if let Some(etag) = &data.etag {
                    request = request.header(header::IF_NONE_MATCH, etag)
                } else if let Some(last_modified) = &data.last_modified {
                    request = request.header(header::IF_MODIFIED_SINCE, last_modified)
                }
            }

            let response = request.send().await?;

            if response.status() == StatusCode::NOT_MODIFIED {
                tracing::debug!("JWKS not modified");
                return Ok(());
            } else if let Err(err) = response.error_for_status_ref() {
                let error: &dyn std::error::Error = &err;
                tracing::warn!(
                    error,
                    http.status_code = response.status().as_u16(),
                    "JWKS refresh failed; unexpected response status",
                );
                return Err(err);
            }

            let etag = response.headers().get(header::ETAG).map(ToOwned::to_owned);
            let last_modified = response
                .headers()
                .get(header::LAST_MODIFIED)
                .map(ToOwned::to_owned);
            match response.json::<Jwks>().await {
                Ok(jwks) => {
                    let data = Arc::new(VolatileData {
                        jwks,
                        etag,
                        last_modified,
                    });

                    self.inner.data.store(data);
                    tracing::info!("JWKS refreshed");
                }
                Err(err) => {
                    let error: &dyn std::error::Error = &err;
                    tracing::warn!(error, "JWKS refresh failed; unexpected error");
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    /// Refreshes the JWKS from the remote URL
    ///
    /// No retries are attempted. If the attempt to refresh the JWKS from
    /// the remote URL fails, no change is made to the internal JWKS.
    #[cfg(not(feature = "reqwest"))]
    #[cfg_attr(docsrs, doc(cfg(not(feature = "reqwest"))))]
    #[tracing::instrument]
    pub async fn refresh(&self) -> Result<(), std::convert::Infallible> {
        Ok(())
    }

    /// Updates the JWKS associated with the internal state
    pub fn set_jwks(&self, jwks: Jwks) {
        let data = Arc::new(VolatileData::new(jwks));
        self.inner.data.store(data);
    }

    /// Authenticates the token and checks access according to the policy
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid or is not authorized by the policy
    pub fn verify_token<T>(&self, token: &JwtRef, policy: &ScopePolicy) -> Result<T, AuthorityError>
    where
        T: for<'de> Deserialize<'de> + HasScope + jwt::CoreClaims,
    {
        let decomposed = token.decompose()?;

        let validated: jwt::Validated<T>;
        {
            let guard = self.inner.data.load();

            let key = {
                let kid = decomposed.kid();
                let alg = decomposed.alg();

                guard.jwks.get_key_by_opt(kid, alg).ok_or_else(|| {
                    if let Some(kid) = kid {
                        tracing::debug!(%kid, %alg, "unable to find matching key");
                    } else {
                        tracing::debug!(%alg, "unable to find matching key");
                    }
                    AuthorityError::UnknownKeyId
                })?
            };

            validated = decomposed.verify(key, &self.inner.validator)?;
        }

        policy.evaluate(validated.claims().scope())?;

        let (_, validated_claims) = validated.extract();

        Ok(validated_claims)
    }
}

#[cfg(test)]
#[cfg(never)]
mod tests {
    use std::time::Duration;

    use aliri::{jwk, jws, jwt, Jwk};
    use color_eyre::Result;

    use super::*;
    use crate::Scopes;

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    fn validate_rs256() -> Result<()> {
        async_validate(jws::Algorithm::RS256).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    fn validate_rs384() -> Result<()> {
        async_validate(jws::Algorithm::RS384).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    fn validate_rs512() -> Result<()> {
        async_validate(jws::Algorithm::RS512).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    fn validate_ps256() -> Result<()> {
        async_validate(jws::Algorithm::PS256).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    fn validate_ps384() -> Result<()> {
        async_validate(jws::Algorithm::PS384).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "rsa")]
    fn validate_ps512() -> Result<()> {
        async_validate(jws::Algorithm::PS512).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "hmac")]
    fn validate_hs256() -> Result<()> {
        async_validate(jws::Algorithm::HS256).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "hmac")]
    fn validate_hs384() -> Result<()> {
        async_validate(jws::Algorithm::HS384).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "hmac")]
    fn validate_hs512() -> Result<()> {
        async_validate(jws::Algorithm::HS512).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "ec")]
    fn validate_es256() -> Result<()> {
        async_validate(jws::Algorithm::ES256).await
    }

    #[tokio::test]
    #[ignore = "disabled private key management"]
    #[cfg(feature = "ec")]
    fn validate_es384() -> Result<()> {
        async_validate(jws::Algorithm::ES384).await
    }

    fn validate(alg: jws::Algorithm) -> Result<()> {
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

        let header = jwt::BasicHeaders::with_key_id(alg.into(), test_kid);

        let claims = jwt::BsaicClaims::new()
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
