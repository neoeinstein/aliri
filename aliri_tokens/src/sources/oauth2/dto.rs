//! DTOs for interacting with OAuth2 token source servers

use aliri::jwt::{self};
use aliri_clock::DurationSecs;
use serde::{Deserialize, Serialize, Serializer};

use crate::{AccessTokenRef, ClientId, ClientIdRef, ClientSecret, IdTokenRef, RefreshTokenRef};

/// Client credentials
#[derive(Debug)]
pub struct ClientCredentials {
    /// The client ID
    pub client_id: ClientId,

    /// The client secret
    pub client_secret: ClientSecret,

    /// The target audience
    pub audience: Option<jwt::Audience>,
}

impl Serialize for ClientCredentials {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut ser = serializer.serialize_struct("ClientCredentials", 3)?;
        ser.serialize_field("grant_type", "client_credentials")?;
        ser.serialize_field("client_id", &self.client_id)?;
        ser.serialize_field("client_secret", &self.client_secret)?;
        if let Some(audience) = &self.audience {
            ser.serialize_field("audience", audience)?;
        }
        ser.end()
    }
}

impl super::CredentialsSource for ClientCredentials {
    fn client_id(&self) -> &ClientIdRef {
        &self.client_id
    }
    fn grant_type() -> &'static str {
        "client_credentials"
    }
    fn audience(&self) -> Option<&jwt::AudienceRef> {
        if let Some(audience) = &self.audience {
            Some(audience)
        } else {
            None
        }
    }
    fn on_refresh_token(&mut self, _: Box<RefreshTokenRef>) {}
}

/// Refresh token credentials
#[derive(Debug)]
pub struct RefreshTokenCredentialsSource {
    /// The client ID
    pub client_id: ClientId,

    /// The client secret, if required
    pub client_secret: Option<ClientSecret>,

    /// The refresh token
    pub refresh_token: Box<RefreshTokenRef>,
}

impl Serialize for RefreshTokenCredentialsSource {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut ser = serializer.serialize_struct("RefreshTokenCredentialsSource", 3)?;
        ser.serialize_field("grant_type", "refresh_token")?;
        ser.serialize_field("client_id", &self.client_id)?;
        if let Some(secret) = &self.client_secret {
            ser.serialize_field("client_secret", secret)?;
        } else {
            ser.skip_field("client_secret")?;
        }
        ser.serialize_field("refresh_token", &*self.refresh_token)?;
        ser.end()
    }
}

impl super::CredentialsSource for RefreshTokenCredentialsSource {
    fn client_id(&self) -> &ClientIdRef {
        &self.client_id
    }
    fn grant_type() -> &'static str {
        "refresh_token"
    }
    fn audience(&self) -> Option<&jwt::AudienceRef> {
        None
    }
    fn on_refresh_token(&mut self, refresh_token: Box<RefreshTokenRef>) {
        self.refresh_token = refresh_token;
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct TokenResponse<'a> {
    #[serde(borrow)]
    pub access_token: &'a AccessTokenRef,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    pub id_token: Option<&'a IdTokenRef>,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<&'a RefreshTokenRef>,
    pub expires_in: DurationSecs,
}
