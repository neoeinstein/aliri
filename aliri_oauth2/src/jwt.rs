//! Basic JWT payload that includes just basic claims with a scopes claim

use super::{HasScopes, Scopes};

use aliri::jwt;
use aliri_clock::UnixTime;
use serde::{Deserialize, Serialize};

/// A convenience structure for payloads where the user only cares about the scope
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicClaimsWithScope {
    /// The basic claims
    #[serde(flatten)]
    pub basic: jwt::BasicClaims,

    /// The `scope` claim
    pub scope: Scopes,
}

impl jwt::CoreClaims for BasicClaimsWithScope {
    #[inline]
    fn nbf(&self) -> Option<UnixTime> {
        self.basic.nbf()
    }

    #[inline]
    fn exp(&self) -> Option<UnixTime> {
        self.basic.exp()
    }

    #[inline]
    fn aud(&self) -> &jwt::Audiences {
        self.basic.aud()
    }

    #[inline]
    fn iss(&self) -> Option<&jwt::IssuerRef> {
        self.basic.iss()
    }

    #[inline]
    fn sub(&self) -> Option<&jwt::SubjectRef> {
        self.basic.sub()
    }
}

impl HasScopes for BasicClaimsWithScope {
    #[inline]
    fn scopes(&self) -> &Scopes {
        &self.scope
    }
}

impl HasScopes for Scopes {
    #[inline]
    fn scopes(&self) -> &Scopes {
        self
    }
}
