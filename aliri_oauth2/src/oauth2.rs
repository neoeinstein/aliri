//! OAuth2-specific

use std::{collections::hash_set, iter::FromIterator, str::FromStr};

use ahash::AHashSet;
use aliri::jwt;
use aliri_braid::braid;
use aliri_clock::UnixTime;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use thiserror::Error;

/// An invalid scope token
#[derive(Debug, Error)]
pub enum InvalidScopeToken {
    /// The scope token was the empty string
    #[error("scope token cannot be empty")]
    EmptyString,
    /// The scope token contained an invalid byte
    #[error("invalid scope token byte at position {position}: 0x{value:02x}")]
    InvalidByte {
        /// The index in the scope token where the invalid byte was found
        position: usize,
        /// The invalid byte value
        value: u8,
    },
}

/// An OAuth2 scope token as defined in [RFC 6749, Section 3.3][RFC6749 3.3]
///
/// A scope token must be composed of printable ASCII characters excluding
/// ` ` (space), `"` (double quote), and `\` (backslash).
///
///   [RFC6749 3.3]: (https://datatracker.ietf.org/doc/html/rfc6749#section-3.3)
#[braid(
    serde,
    validator,
    ref_doc = "A borrowed reference to an OAuth2 [`ScopeToken`]"
)]
pub struct ScopeToken;

impl aliri_braid::Validator for ScopeToken {
    type Error = InvalidScopeToken;

    /// Validates that the scope token is valid
    ///
    /// A valid scope token is non-empty and composed of printable
    /// ASCII characters except ` `, `"`, and `\`.
    fn validate(s: &str) -> Result<(), Self::Error> {
        if s.is_empty() {
            Err(InvalidScopeToken::EmptyString)
        } else if let Some((position, &value)) = s
            .as_bytes()
            .iter()
            .enumerate()
            .find(|(_, &b)| b <= 0x20 || b == 0x22 || b == 0x5C || 0x7F <= b)
        {
            Err(InvalidScopeToken::InvalidByte { position, value })
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum ScopeDto {
    String(String),
    Array(Vec<ScopeToken>),
}

impl TryFrom<Option<ScopeDto>> for Scope {
    type Error = InvalidScopeToken;

    fn try_from(dto: Option<ScopeDto>) -> Result<Self, Self::Error> {
        if let Some(dto) = dto {
            match dto {
                ScopeDto::String(s) => Self::try_from(s),
                ScopeDto::Array(arr) => Ok(arr.into_iter().collect()),
            }
        } else {
            Ok(Self::empty())
        }
    }
}

impl From<Scope> for ScopeDto {
    fn from(s: Scope) -> Self {
        let x: Vec<_> = s.0.into_iter().map(ScopeToken::into_string).collect();
        let y = x.join(" ");
        ScopeDto::String(y)
    }
}

/// An OAuth2 Scope defining a set of access permissions
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "Option<ScopeDto>", into = "ScopeDto")]
pub struct Scope(AHashSet<ScopeToken>);

lazy_static::lazy_static! {
    /// An empty, static scopes with no access permissions
    static ref EMPTY_SCOPE: Scope = Scope::empty();
}

impl Scope {
    /// Produces an empty scope
    #[inline]
    pub fn empty() -> Self {
        Self(AHashSet::new())
    }

    /// Constructs a new scope from a single scope token
    #[inline]
    pub fn single(scope_token: ScopeToken) -> Self {
        let mut s = Self::empty();
        s.insert(scope_token);
        s
    }

    /// Adds an additional scope token
    #[inline]
    pub fn and(self, scope_token: ScopeToken) -> Self {
        let mut s = self;
        s.insert(scope_token);
        s
    }

    /// Constructs a scope from an iterator of scope tokens
    #[inline]
    pub fn from_scope_tokens<I>(scope_tokens: I) -> Self
    where
        I: IntoIterator<Item = ScopeToken>,
    {
        Self::from_iter(scope_tokens)
    }

    /// Adds a scope token to the scope
    #[inline]
    pub fn insert(&mut self, scope_token: ScopeToken) {
        self.0.insert(scope_token);
    }

    /// Produces an iterator of the scope tokens in this set
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &ScopeTokenRef> {
        (&self).into_iter()
    }

    /// Checks to see whether this scope contains all of
    /// the scope tokens in `subset`.
    #[inline]
    pub fn contains_all(&self, subset: &Scope) -> bool {
        self.0.is_superset(&subset.0)
    }
}

impl IntoIterator for Scope {
    type Item = ScopeToken;
    type IntoIter = <AHashSet<ScopeToken> as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// An iterator over a set of borrowed scope tokens
#[derive(Clone, Debug)]
pub struct Iter<'a> {
    iter: hash_set::Iter<'a, ScopeToken>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a ScopeTokenRef;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|x| x.as_ref())
    }
}

impl<'a> IntoIterator for &'a Scope {
    type Item = &'a ScopeTokenRef;
    type IntoIter = Iter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            iter: self.0.iter(),
        }
    }
}

impl<S> Extend<S> for Scope
where
    S: Into<ScopeToken>,
{
    #[inline]
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = S>,
    {
        self.0.extend(iter.into_iter().map(Into::into))
    }
}

impl<S> FromIterator<S> for Scope
where
    S: Into<ScopeToken>,
{
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = S>,
    {
        let mut set = Self::empty();
        set.extend(iter);
        set
    }
}

impl TryFrom<&'_ str> for Scope {
    type Error = InvalidScopeToken;

    #[inline]
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.split_whitespace().map(ScopeToken::new).collect()
    }
}

impl TryFrom<String> for Scope {
    type Error = InvalidScopeToken;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl FromStr for Scope {
    type Err = InvalidScopeToken;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

/// A convenience structure for payloads where the user only cares about the
/// scope and other basic claims
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicClaimsWithScope {
    /// The basic claims
    #[serde(flatten)]
    pub basic: jwt::BasicClaims,

    /// The `scope` claim
    pub scope: Scope,
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

/// Indicates that the type has an OAuth2 scope claim
pub trait HasScope {
    /// OAuth2 scope
    ///
    /// Scope claimed by the underlying token, generally in the `scope`
    /// claim.
    fn scope(&self) -> &Scope;
}

impl HasScope for BasicClaimsWithScope {
    #[inline]
    fn scope(&self) -> &Scope {
        &self.scope
    }
}

impl HasScope for Scope {
    #[inline]
    fn scope(&self) -> &Scope {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_handles_valid() {
        let x = ScopeToken::new("https://crates.io/scopes/publish:crate").unwrap();
        assert_eq!(x.as_str(), "https://crates.io/scopes/publish:crate");
    }

    #[test]
    fn owned_rejects_empty() {
        let x = ScopeToken::new("");
        assert!(matches!(x, Err(InvalidScopeToken::EmptyString)));
    }

    #[test]
    fn owned_rejects_invalid_quote() {
        let x = ScopeToken::new("https://crates.io/scopes/\"publish:crate\"");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn owned_rejects_invalid_control() {
        let x = ScopeToken::new("https://crates.io/scopes/\tpublish:crate");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn owned_rejects_invalid_backslash() {
        let x = ScopeToken::new("https://crates.io/scopes/\\publish:crate");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn owned_rejects_invalid_delete() {
        let x = ScopeToken::new("https://crates.io/scopes/\x7Fpublish:crate");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn owned_rejects_invalid_non_ascii() {
        let x = ScopeToken::new("https://crates.io/scopes/¿publish:crate");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn owned_rejects_invalid_emoji() {
        let x = ScopeToken::new("https://crates.io/scopes/🪤publish:crate");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn ref_handles_valid() {
        let x = ScopeTokenRef::from_str("https://crates.io/scopes/publish:crate").unwrap();
        assert_eq!(x.as_str(), "https://crates.io/scopes/publish:crate");
    }

    #[test]
    fn ref_rejects_empty() {
        let x = ScopeTokenRef::from_str("");
        assert!(matches!(x, Err(InvalidScopeToken::EmptyString)));
    }

    #[test]
    fn ref_rejects_invalid_quote() {
        let x = ScopeTokenRef::from_str("https://crates.io/scopes/\"publish:crate\"");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn ref_rejects_invalid_control() {
        let x = ScopeTokenRef::from_str("https://crates.io/scopes/\tpublish:crate");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn ref_rejects_invalid_backslash() {
        let x = ScopeTokenRef::from_str("https://crates.io/scopes/\\publish:crate");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn ref_rejects_invalid_delete() {
        let x = ScopeTokenRef::from_str("https://crates.io/scopes/\x7Fpublish:crate");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn ref_rejects_invalid_non_ascii() {
        let x = ScopeTokenRef::from_str("https://crates.io/scopes/¿publish:crate");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }

    #[test]
    fn ref_rejects_invalid_emoji() {
        let x = ScopeTokenRef::from_str("https://crates.io/scopes/🪤publish:crate");
        assert!(matches!(x, Err(InvalidScopeToken::InvalidByte { .. })));
    }
}
