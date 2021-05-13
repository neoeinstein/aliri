use std::iter::FromIterator;

use thiserror::Error;

use crate::Scope;

/// Indicates the requestor held insufficient scope to be granted access
/// to a controlled resource
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Error)]
#[error("insufficient scope")]
pub struct InsufficientScope;

/// An access policy based on OAuth2 scopes
///
/// This access policy takes the form of alternatives around required scopes.
/// This policy will allow access if any of the alternatives would allow
/// access. If the policy contains no alternatives, the default effect is to
/// deny access.
///
/// # Examples
///
/// ## Deny all requests
/// ```
/// use aliri_traits::Policy;
/// use aliri_oauth2::{Scope, ScopePolicy};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let policy = ScopePolicy::deny_all();
///
/// let request = Scope::single("admin".parse()?);
/// assert!(policy.evaluate(&request).is_err());
/// # Ok(())
/// # }
/// ```
///
/// ## Allow all requests
/// ```
/// use aliri_traits::Policy;
/// use aliri_oauth2::{Scope, ScopePolicy};
///
/// let policy = ScopePolicy::allow_all();
///
/// let request = Scope::empty();
/// assert!(policy.evaluate(&request).is_ok());
/// ```
///
/// ## Allow requests with a single scope
/// ```
/// use aliri_traits::Policy;
/// use aliri_oauth2::{Scope, ScopePolicy};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let policy = ScopePolicy::allow_one(
///     Scope::single("admin".parse()?)
/// );
///
/// let request = Scope::from_scope_tokens(vec![
///     "admin".parse()?,
///     "user".parse()?,
/// ]);
/// assert!(policy.evaluate(&request).is_ok());
///
/// let user_request = Scope::from_scope_tokens(vec![
///     "user".parse()?,
/// ]);
/// assert!(policy.evaluate(&user_request).is_err());
/// # Ok(())
/// # }
/// ```
///
/// ## Allow requests with multiple potential sets of scopes
/// ```
/// use aliri_traits::Policy;
/// use aliri_oauth2::{Scope, ScopePolicy};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut policy = ScopePolicy::deny_all();
/// policy.allow(Scope::single("admin".parse()?));
/// policy.allow(Scope::from_scope_tokens(vec![
///     "special".parse()?,
///     "user".parse()?,
/// ]));
///
/// let admin_request = Scope::from_scope_tokens(vec![
///     "admin".parse()?,
/// ]);
/// assert!(policy.evaluate(&admin_request).is_ok());
///
/// let user_request = Scope::from_scope_tokens(vec![
///     "user".parse()?,
/// ]);
/// assert!(policy.evaluate(&user_request).is_err());
///
/// let special_user_request = Scope::from_scope_tokens(vec![
///     "special".parse()?,
///     "user".parse()?,
/// ]);
/// assert!(policy.evaluate(&special_user_request).is_ok());
/// # Ok(())
/// # }
/// ```
///
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopePolicy {
    alternatives: Vec<Scope>,
}

impl ScopePolicy {
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
            alternatives: vec![Scope::empty()],
        }
    }

    /// Constructs a policy that requires this set of scopes
    #[inline]
    pub fn allow_one(scopes: Scope) -> Self {
        Self {
            alternatives: vec![scopes],
        }
    }

    /// Add an alternate set of required scopes
    #[inline]
    pub fn or_allow(self, scopes: Scope) -> Self {
        let mut s = self;
        s.alternatives.push(scopes);
        s
    }

    /// Add an alternative set of required scopes
    #[inline]
    pub fn allow(&mut self, scopes: Scope) {
        self.alternatives.push(scopes);
    }
}

impl aliri_traits::Policy for ScopePolicy {
    type Request = Scope;
    type Denial = InsufficientScope;

    fn evaluate(&self, held: &Self::Request) -> Result<(), Self::Denial> {
        let allowed = self.alternatives.iter().any(|req| held.contains_all(req));

        if allowed {
            Ok(())
        } else {
            Err(InsufficientScope)
        }
    }
}

impl IntoIterator for ScopePolicy {
    type Item = Scope;
    type IntoIter = <Vec<Scope> as IntoIterator>::IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.alternatives.into_iter()
    }
}

/// An iterator over a set of borrowed scopes
#[derive(Clone, Debug)]
pub struct Iter<'a> {
    iter: std::slice::Iter<'a, Scope>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Scope;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<'a> IntoIterator for &'a ScopePolicy {
    type Item = &'a Scope;
    type IntoIter = Iter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            iter: self.alternatives.iter(),
        }
    }
}

impl Extend<Scope> for ScopePolicy {
    #[inline]
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Scope>,
    {
        self.alternatives.extend(iter)
    }
}

impl FromIterator<Scope> for ScopePolicy {
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        let mut set = Self::deny_all();
        set.extend(iter);
        set
    }
}
