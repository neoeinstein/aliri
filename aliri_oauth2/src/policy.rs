use std::iter::FromIterator;

use thiserror::Error;

use super::Scopes;

/// Indicates the requestor held insufficient scopes to be granted access
/// to a controlled resource
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Error)]
#[error("insufficient scopes")]
pub struct InsufficientScopes;

/// An access policy based on OAuth2 scopes
///
/// This access policy takes the form of alternatives around required scopes.
/// This policy will allow access if any of the alternatives would allow
/// access. If the policy contains no alternatives, the default effect is to
/// deny access.
///
/// ## Examples
///
/// ### Deny all requests
/// ```
/// use aliri_traits::Policy;
/// use aliri_oauth2::{Scopes, ScopesPolicy};
///
/// let policy = ScopesPolicy::deny_all();
///
/// let request = Scopes::single("admin");
/// assert!(policy.evaluate(&request).is_err());
/// ```
///
/// ### Allow all requests
/// ```
/// use aliri_traits::Policy;
/// use aliri_oauth2::{Scopes, ScopesPolicy};
///
/// let policy = ScopesPolicy::allow_all();
///
/// let request = Scopes::empty();
/// assert!(policy.evaluate(&request).is_ok());
/// ```
///
/// ### Allow requests with a single scope
/// ```
/// use aliri_traits::Policy;
/// use aliri_oauth2::{Scopes, ScopesPolicy};
///
/// let policy = ScopesPolicy::allow_one(
///     Scopes::single("admin")
/// );
///
/// let request = Scopes::from_scopes(vec![
///     "admin",
///     "user",
/// ]);
/// assert!(policy.evaluate(&request).is_ok());
///
/// let user_request = Scopes::from_scopes(vec![
///     "user",
/// ]);
/// assert!(policy.evaluate(&user_request).is_err());
/// ```
///
/// ### Allow requests with multiple potential sets of scopes
/// ```
/// use aliri_traits::Policy;
/// use aliri_oauth2::{Scopes, ScopesPolicy};
///
/// let mut policy = ScopesPolicy::deny_all();
/// policy.allow(Scopes::single("admin"));
/// policy.allow(Scopes::from_scopes(vec![
///     "special",
///     "user",
/// ]));
///
/// let admin_request = Scopes::from_scopes(vec![
///     "admin",
/// ]);
/// assert!(policy.evaluate(&admin_request).is_ok());
///
/// let user_request = Scopes::from_scopes(vec![
///     "user",
/// ]);
/// assert!(policy.evaluate(&user_request).is_err());
///
/// let special_user_request = Scopes::from_scopes(vec![
///     "special",
///     "user",
/// ]);
/// assert!(policy.evaluate(&special_user_request).is_ok());
/// ```
///
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopesPolicy {
    alternatives: Vec<Scopes>,
}

impl ScopesPolicy {
    /// Constructs a policy that has no permissible alternatives
    ///
    /// By default, this policy will deny all requests
    #[inline]
    pub fn deny_all() -> Self {
        Self {
            alternatives: Vec::new(),
        }
    }

    /// Constructs a policy that does not require any scopes (allow)
    #[inline]
    pub fn allow_all() -> Self {
        Self {
            alternatives: vec![Scopes::empty()],
        }
    }

    /// Constructs a policy that requires this set of scopes
    #[inline]
    pub fn allow_one(scopes: Scopes) -> Self {
        Self {
            alternatives: vec![scopes],
        }
    }

    /// Add an alternate set of reqired scopes
    #[inline]
    pub fn or_allow(self, scopes: Scopes) -> Self {
        let mut s = self;
        s.alternatives.push(scopes);
        s
    }

    /// Add an alternative set of required scopes
    #[inline]
    pub fn allow(&mut self, scopes: Scopes) {
        self.alternatives.push(scopes);
    }
}

impl aliri_traits::Policy for ScopesPolicy {
    type Request = Scopes;
    type Denial = InsufficientScopes;

    fn evaluate(&self, held: &Self::Request) -> Result<(), Self::Denial> {
        let allowed = self.alternatives.iter().any(|req| held.contains_all(req));

        if allowed {
            Ok(())
        } else {
            Err(InsufficientScopes)
        }
    }
}

impl IntoIterator for ScopesPolicy {
    type Item = Scopes;
    type IntoIter = <Vec<Scopes> as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.alternatives.into_iter()
    }
}

/// An iterator over a set of borrowed scopes
#[derive(Clone, Debug)]
pub struct Iter<'a> {
    iter: std::slice::Iter<'a, Scopes>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Scopes;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<'a> IntoIterator for &'a ScopesPolicy {
    type Item = &'a Scopes;
    type IntoIter = Iter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            iter: self.alternatives.iter(),
        }
    }
}

impl Extend<Scopes> for ScopesPolicy {
    #[inline]
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Scopes>,
    {
        self.alternatives.extend(iter)
    }
}

impl FromIterator<Scopes> for ScopesPolicy {
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Scopes>,
    {
        let mut set = Self::deny_all();
        set.extend(iter);
        set
    }
}
