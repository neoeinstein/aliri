//! A token source that uses an OAuth2 server as an authority

use std::marker::PhantomData;

use aliri::jwt;
use aliri_clock::Clock;
use async_trait::async_trait;
use thiserror::Error;

use super::AsyncTokenSource;
use crate::{ClientIdRef, RefreshTokenRef, TokenLifetimeConfig, TokenWithLifetime};

pub mod dto;

/// A credentials source for an OAuth2 authority
pub trait CredentialsSource: serde::Serialize {
    /// The client ID of the client making the request
    fn client_id(&self) -> &ClientIdRef;
    /// The grant type or flow to be performed
    fn grant_type() -> &'static str;
    /// The optional audience of the request
    fn audience(&self) -> Option<&jwt::AudienceRef>;
    /// A handler to received updates to a refresh token if the refresh token rotates
    fn on_refresh_token(&mut self, refresh_token: Box<RefreshTokenRef>);
}

/// A credentials source for the client credentials flow
#[derive(Debug)]
pub struct ClientCredentialsTokenSource<C, T = JsonBody> {
    client: reqwest::Client,
    token_url: reqwest::Url,
    credentials: dto::ClientCredentialsWithAudience,
    lifetime_config: TokenLifetimeConfig<C>,
    content_type: PhantomData<fn() -> T>,
}

impl<C> ClientCredentialsTokenSource<C, JsonBody> {
    /// Constructs a new client credentials source
    pub fn new(
        client: reqwest::Client,
        token_url: reqwest::Url,
        credentials: dto::ClientCredentialsWithAudience,
        lifetime_config: TokenLifetimeConfig<C>,
    ) -> Self {
        Self {
            client,
            token_url,
            credentials,
            lifetime_config,
            content_type: PhantomData,
        }
    }

    /// Configures the token source to send credentials to
    /// the authority as form data
    pub fn using_form_data(self) -> ClientCredentialsTokenSource<C, FormBody> {
        ClientCredentialsTokenSource {
            client: self.client,
            token_url: self.token_url,
            credentials: self.credentials,
            lifetime_config: self.lifetime_config,
            content_type: PhantomData,
        }
    }
}

#[async_trait]
impl<C: Clock + Send + Sync, T: RequestType> AsyncTokenSource
    for ClientCredentialsTokenSource<C, T>
{
    type Error = TokenRequestError;

    async fn request_token(&mut self) -> Result<TokenWithLifetime, Self::Error> {
        request_token::<_, _, T>(
            &self.client,
            self.token_url.clone(),
            &mut self.credentials,
            &self.lifetime_config,
        )
        .await
    }
}

/// A credentials source that uses the refresh token flow
#[derive(Debug)]
pub struct RefreshTokenSource<C, T = JsonBody> {
    client: reqwest::Client,
    token_url: reqwest::Url,
    credentials: dto::RefreshTokenCredentialsSource,
    lifetime_config: TokenLifetimeConfig<C>,
    content_type: PhantomData<fn() -> T>,
}

impl<C> RefreshTokenSource<C, JsonBody> {
    /// Constructs a new refresh token source
    pub fn new(
        client: reqwest::Client,
        token_url: reqwest::Url,
        credentials: dto::RefreshTokenCredentialsSource,
        lifetime_config: TokenLifetimeConfig<C>,
    ) -> Self {
        Self {
            client,
            token_url,
            credentials,
            lifetime_config,
            content_type: PhantomData,
        }
    }

    /// Configures the token source to send credentials to
    /// the authority as form data
    pub fn using_form_data(self) -> RefreshTokenSource<C, FormBody> {
        RefreshTokenSource {
            client: self.client,
            token_url: self.token_url,
            credentials: self.credentials,
            lifetime_config: self.lifetime_config,
            content_type: PhantomData,
        }
    }
}

#[async_trait]
impl<C: Clock + Send + Sync, T: RequestType> AsyncTokenSource for RefreshTokenSource<C, T> {
    type Error = TokenRequestError;

    async fn request_token(&mut self) -> Result<TokenWithLifetime, Self::Error> {
        request_token::<_, _, T>(
            &self.client,
            self.token_url.clone(),
            &mut self.credentials,
            &self.lifetime_config,
        )
        .await
    }
}

/// An error while attempting to request a new token from the authority
#[derive(Debug, Error)]
pub enum TokenRequestError {
    /// An error from the authority with an error body
    #[error("error requesting token from authority: {body}")]
    ErrorWithBody {
        /// The underlying request error
        source: reqwest::Error,
        /// The body of the error
        body: String,
    },
    /// Unable to deserialize the token body
    #[error("error deserializing token body from authority")]
    TokenBodyError(#[from] serde_json::Error),
    /// Unable to read the response
    #[error("error reading response body")]
    BodyReadError(reqwest::Error),
    /// Unable to send a token request to the authority
    #[error("error sending request to authority")]
    RequestSend(reqwest::Error),
}

fn maybe_value<'a, T: tracing::Value + 'a>(v: &'a Option<T>) -> &'a dyn tracing::Value {
    if let Some(v) = v {
        v
    } else {
        &tracing::field::Empty
    }
}

/// Request content type
#[derive(Debug, PartialEq, Eq)]
pub enum ContentType {
    /// json content type
    Json,
    /// form content type
    Form,
}

#[tracing::instrument(
    err,
    skip(client, token_url, credentials),
    fields(
        token_url = %token_url,
        credentials.grant_type = R::grant_type(),
        credentials.client_id = %credentials.client_id(),
        credentials.audience = maybe_value(&credentials.audience().map(|a| a.as_str())),
    ),
)]
async fn request_token<R: CredentialsSource, C: Clock, T: RequestType>(
    client: &reqwest::Client,
    token_url: reqwest::Url,
    credentials: &mut R,
    lifetime_config: &TokenLifetimeConfig<C>,
) -> Result<TokenWithLifetime, TokenRequestError> {
    tracing::trace!("requesting token from authority");

    let req = T::attach_payload(client.post(token_url), credentials);
    let resp = req.send().await.map_err(TokenRequestError::RequestSend)?;

    tracing::debug!(
        response.status = resp.status().as_u16(),
        "received token response from issuing authority"
    );

    if let Err(error) = resp.error_for_status_ref() {
        let body = resp
            .text()
            .await
            .map_err(TokenRequestError::BodyReadError)?;
        return Err(TokenRequestError::ErrorWithBody {
            source: error,
            body,
        });
    }

    let body = resp
        .bytes()
        .await
        .map_err(TokenRequestError::BodyReadError)?;
    let resp: dto::TokenResponse = serde_json::from_slice(&body)?;

    let access_token = (*resp.access_token).to_owned();
    let id_token = resp.id_token.map(|x| (*x).to_owned());
    let lifetime = resp.expires_in;

    let token = lifetime_config.create_token(access_token, id_token, lifetime);

    tracing::info!(
        has_id_token = resp.id_token.is_some(),
        has_refresh_token = resp.refresh_token.is_some(),
        lifetime = token.lifetime().0,
        stale = token.stale().0,
        expiry = token.expiry().0,
        "received new tokens"
    );

    if let Some(rt) = resp.refresh_token {
        tracing::info!("received new refresh token");
        credentials.on_refresh_token((*rt).to_owned().into_boxed_ref())
    }

    Ok(token)
}

/// A manner of attaching a serializable payload to a request
pub trait RequestType {
    /// Attaches the serializable payload to the request body
    fn attach_payload<S: serde::Serialize>(
        request: reqwest::RequestBuilder,
        payload: &S,
    ) -> reqwest::RequestBuilder;
}

/// Attaches credentials to the request body as JSON
#[derive(Debug)]
pub struct JsonBody;

/// Attaches credentials to the request body as URL-encoded form data
#[derive(Debug)]
pub struct FormBody;

impl RequestType for JsonBody {
    fn attach_payload<S: serde::Serialize>(
        request: reqwest::RequestBuilder,
        payload: &S,
    ) -> reqwest::RequestBuilder {
        request.json(payload)
    }
}

impl RequestType for FormBody {
    fn attach_payload<S: serde::Serialize>(
        request: reqwest::RequestBuilder,
        payload: &S,
    ) -> reqwest::RequestBuilder {
        request.form(payload)
    }
}
