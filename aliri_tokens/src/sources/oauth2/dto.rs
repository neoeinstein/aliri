//! DTOs for interacting with OAuth2 token source servers

use aliri::jwt::{self};
use aliri_clock::DurationSecs;
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    AccessTokenRef, ClientId, ClientIdRef, ClientSecret, IdTokenRef, RefreshTokenRef, Scope,
    ScopeRef,
};

/// Client credentials
#[derive(Debug)]
pub struct ClientCredentials {
    /// The client ID
    pub client_id: ClientId,

    /// The client secret
    pub client_secret: ClientSecret,

    /// The target audience
    pub audience: Option<jwt::Audience>,

    /// The scope being requested
    ///
    /// Authorities that gate their endpoints on scopes will happily issue a token
    /// without any scope and then refuse every call made with it, so a client that
    /// needs scopes must ask for them here. A scope the client is not permitted to
    /// request is generally rejected with an `invalid_scope` error.
    pub scope: Option<Scope>,
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
        if let Some(scope) = &self.scope {
            ser.serialize_field("scope", scope)?;
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
    fn scope(&self) -> Option<&ScopeRef> {
        self.scope.as_deref()
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

    /// The scope being requested, which may not exceed the scope originally granted
    pub scope: Option<Scope>,
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
        if let Some(scope) = &self.scope {
            ser.serialize_field("scope", scope)?;
        }
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
    fn scope(&self) -> Option<&ScopeRef> {
        self.scope.as_deref()
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
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<&'a ScopeRef>,
    pub expires_in: DurationSecs,
}

#[cfg(all(test, feature = "serde_json"))]
mod tests {
    use super::*;

    fn credentials(scope: Option<Scope>) -> ClientCredentials {
        ClientCredentials {
            client_id: ClientId::from_static("client"),
            client_secret: ClientSecret::from_static("secret"),
            audience: None,
            scope,
        }
    }

    #[test]
    fn client_credentials_serializes_requested_scope() {
        let json = serde_json::to_value(credentials(Scope::from_tokens([
            "resource:read",
            "resource:write",
        ])))
        .unwrap();

        assert_eq!(json["scope"], "resource:read resource:write");
    }

    #[test]
    fn client_credentials_omits_absent_scope() {
        let json = serde_json::to_value(credentials(None)).unwrap();

        assert!(json.get("scope").is_none());
    }

    #[test]
    fn empty_scope_request_is_omitted_entirely() {
        assert!(Scope::from_tokens(Vec::<String>::new()).is_none());
    }

    #[test]
    fn granted_scope_is_read_back_from_the_token_response() {
        let body = serde_json::json!({
            "access_token": "token",
            "expires_in": 3600,
            "scope": "resource:read",
        })
        .to_string();

        let resp: TokenResponse = serde_json::from_str(&body).unwrap();

        assert_eq!(
            resp.scope.unwrap().tokens().collect::<Vec<_>>(),
            vec!["resource:read"]
        );
    }
}
