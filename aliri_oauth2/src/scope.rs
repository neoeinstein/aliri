use std::collections::hash_set;

use ahash::AHashSet;
use aliri_jose::jwt;
use aliri_macros::typed_string;
use serde::{Deserialize, Serialize};

typed_string! {
    /// An OAuth2 scope
    pub struct Scope(String);

    /// Reference to a `Scope`
    pub struct ScopeRef(str);
}

/// Indicates that the type has OAuth2 scopes
pub trait HasScopes {
    /// Scopes
    ///
    /// Scopes claimed by the underlying token, generally in the `scope`
    /// claim.
    fn scopes(&self) -> &Scopes {
        &*EMPTY_SCOPES
    }
}

impl HasScopes for jwt::Empty {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum ScopesDto {
    String(String),
    Array(Vec<Scope>),
}

impl From<Option<ScopesDto>> for Scopes {
    fn from(dto: Option<ScopesDto>) -> Self {
        let scopes = if let Some(dto) = dto {
            match dto {
                ScopesDto::String(s) => s.split_whitespace().map(|s| Scope::new(s)).collect(),
                ScopesDto::Array(arr) => {
                    let mut set = AHashSet::new();
                    set.extend(arr);
                    set
                }
            }
        } else {
            AHashSet::new()
        };

        Self(scopes)
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
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(from = "Option<ScopesDto>", into = "ScopesDto")]
pub struct Scopes(AHashSet<Scope>);

lazy_static::lazy_static! {
    /// An empty, static set of scopes
    static ref EMPTY_SCOPES: Scopes = Scopes::new();
}

impl Scopes {
    /// Produces an empty scope set
    #[inline]
    pub fn new() -> Self {
        Self(AHashSet::new())
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
    pub fn contains_all<I, T>(&self, required_scopes: I) -> bool
    where
        I: IntoIterator<Item = T>,
        T: AsRef<ScopeRef>,
    {
        required_scopes
            .into_iter()
            .all(|v| self.0.contains(v.as_ref()))
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

impl Extend<Scope> for Scopes {
    #[inline]
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Scope>,
    {
        self.0.extend(iter)
    }
}

impl HasScopes for Scopes {
    #[inline]
    fn scopes(&self) -> &Scopes {
        self
    }
}
