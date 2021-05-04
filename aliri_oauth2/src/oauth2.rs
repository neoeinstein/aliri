//! OAuth2-specific

use std::{collections::hash_set, iter::FromIterator, str::FromStr};

use ahash::AHashSet;
use aliri::jwt;
use aliri_clock::UnixTime;
use aliri_macros::typed_string;
use serde::{Deserialize, Serialize};

typed_string! {
    /// An OAuth2 scope
    pub struct Scope(String);

    /// Reference to a `Scope`
    pub struct ScopeRef(str);
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum ScopesDto {
    String(String),
    Array(Vec<Scope>),
}

impl From<Option<ScopesDto>> for Scopes {
    fn from(dto: Option<ScopesDto>) -> Self {
        if let Some(dto) = dto {
            match dto {
                ScopesDto::String(s) => Self::from(s),
                ScopesDto::Array(arr) => arr.into_iter().collect(),
            }
        } else {
            Self::empty()
        }
    }
}

impl From<Scopes> for ScopesDto {
    fn from(s: Scopes) -> Self {
        let x: Vec<_> = s.0.into_iter().map(Scope::into_inner).collect();
        let y = x.join(" ");
        ScopesDto::String(y)
    }
}

/// A set of scopes for defining access permissions
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(from = "Option<ScopesDto>", into = "ScopesDto")]
pub struct Scopes(AHashSet<Scope>);

lazy_static::lazy_static! {
    /// An empty, static set of scopes
    static ref EMPTY_SCOPES: Scopes = Scopes::empty();
}

impl Scopes {
    /// Produces an empty scope set
    #[inline]
    pub fn empty() -> Self {
        Self(AHashSet::new())
    }

    /// Constructs a new scope set from a single scope
    #[inline]
    pub fn single<S>(scope: S) -> Self
    where
        S: Into<Scope>,
    {
        let mut s = Self::empty();
        s.insert(scope.into());
        s
    }

    /// Adds an additional scope to the set
    #[inline]
    pub fn and<S>(self, scope: S) -> Self
    where
        S: Into<Scope>,
    {
        let mut s = self;
        s.insert(scope.into());
        s
    }

    /// Constructs a new scope set from a set of scopes
    #[inline]
    pub fn from_scopes<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Scope>,
    {
        Self::from_iter(scopes)
    }

    /// Adds a scope to the scope set
    #[inline]
    pub fn insert(&mut self, scope: Scope) {
        self.0.insert(scope);
    }

    /// Produces an iterator of the scopes in this set
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &ScopeRef> {
        (&self).into_iter()
    }

    /// Checks to see whether this set of scopes contains all of
    /// the scopes required.
    #[inline]
    pub fn contains_all(&self, subset: &Scopes) -> bool {
        self.0.is_superset(&subset.0)
    }
}

impl IntoIterator for Scopes {
    type Item = Scope;
    type IntoIter = <AHashSet<Scope> as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// An iterator over a set of borrowed scopes
#[derive(Clone, Debug)]
pub struct Iter<'a> {
    iter: hash_set::Iter<'a, Scope>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a ScopeRef;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|x| x.as_ref())
    }
}

impl<'a> IntoIterator for &'a Scopes {
    type Item = &'a ScopeRef;
    type IntoIter = Iter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            iter: self.0.iter(),
        }
    }
}

impl<S> Extend<S> for Scopes
where
    S: Into<Scope>,
{
    #[inline]
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = S>,
    {
        self.0.extend(iter.into_iter().map(Into::into))
    }
}

impl<S> FromIterator<S> for Scopes
where
    S: Into<Scope>,
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

impl From<&'_ str> for Scopes {
    #[inline]
    fn from(s: &str) -> Self {
        s.split_whitespace().map(Scope::new).collect()
    }
}

impl From<String> for Scopes {
    #[inline]
    fn from(s: String) -> Self {
        Self::from(s.as_str())
    }
}

impl FromStr for Scopes {
    type Err = std::convert::Infallible;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
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

/// Indicates that the type has OAuth2 scopes
pub trait HasScopes {
    /// Scopes
    ///
    /// Scopes claimed by the underlying token, generally in the `scope`
    /// claim.
    fn scopes(&self) -> &Scopes;
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
