use std::{iter, slice, vec};

use thiserror::Error;

use crate::Scope;

/// Indicates the requester held insufficient scope to be granted access
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
/// ## Allow any request
/// ```
/// use aliri_traits::Policy;
/// use aliri_oauth2::{Scope, ScopePolicy};
///
/// let policy = ScopePolicy::allow_any();
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
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ScopePolicy {
    inner: ScopePolicyInner,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ScopePolicyInner {
    DenyAll,
    AllowAny,
    AllowOne(Scope),
    AllowMany(Vec<Scope>),
}

impl Default for ScopePolicy {
    #[inline]
    fn default() -> Self {
        Self::deny_all()
    }
}

impl ScopePolicy {
    /// Constructs a policy that has no permissible alternatives
    ///
    /// By default, this policy will deny all requests
    #[inline]
    pub const fn deny_all() -> Self {
        Self {
            inner: ScopePolicyInner::DenyAll,
        }
    }

    /// Constructs a policy that does not require any scopes (allow)
    #[inline]
    pub const fn allow_any() -> Self {
        Self {
            inner: ScopePolicyInner::AllowAny,
        }
    }

    /// Constructs a policy that requires this set of scopes
    #[inline]
    pub const fn allow_one(scope: Scope) -> Self {
        Self {
            inner: ScopePolicyInner::AllowOne(scope),
        }
    }

    /// Add an alternate allowable scope
    #[inline]
    pub fn or_allow(self, scope: Scope) -> Self {
        if scope.is_empty() {
            let mut this = self;
            this.inner = ScopePolicyInner::AllowAny;
            this
        } else {
            match self.inner {
                ScopePolicyInner::AllowAny => Self::allow_any(),
                ScopePolicyInner::DenyAll => Self::allow_one(scope),
                ScopePolicyInner::AllowOne(existing) => Self {
                    inner: ScopePolicyInner::AllowMany(vec![existing, scope]),
                },
                ScopePolicyInner::AllowMany(mut scopes) => {
                    scopes.push(scope);
                    Self {
                        inner: ScopePolicyInner::AllowMany(scopes),
                    }
                }
            }
        }
    }

    /// Add an alternate allowable scope
    pub fn allow(&mut self, scope: Scope) {
        let this = std::mem::take(self);
        *self = this.or_allow(scope);
    }

    /// Constructs a policy that requires this set of scopes from a string
    ///
    /// # Panics
    ///
    /// This function will panic if the provided string is not a valid [`Scope`].
    pub fn allow_one_from_static(scope: &'static str) -> Self {
        match scope.parse::<Scope>() {
            Ok(scope) => Self::allow_one(scope),
            Err(err) => panic!("{}: scope = {}", err, scope),
        }
    }

    /// Add an alternate allowable scope from a string
    ///
    /// # Panics
    ///
    /// This function will panic if the provided string is not a valid [`Scope`].
    pub fn or_allow_from_static(self, scope: &'static str) -> Self {
        match scope.parse::<Scope>() {
            Ok(scope) => self.or_allow(scope),
            Err(err) => panic!("{}: scope = {}", err, scope),
        }
    }

    /// Add an alternate allowable scope from a string
    ///
    /// # Panics
    ///
    /// This function will panic if the provided string is not a valid [`Scope`].
    pub fn allow_from_static(&mut self, scope: &'static str) {
        match scope.parse::<Scope>() {
            Ok(scope) => self.allow(scope),
            Err(err) => panic!("{}: scope = {}", err, scope),
        }
    }

    const fn is_allow_all(&self) -> bool {
        matches!(self.inner, ScopePolicyInner::AllowAny)
    }
}

impl aliri_traits::Policy for ScopePolicy {
    type Request = Scope;
    type Denial = InsufficientScope;

    fn evaluate(&self, held: &Self::Request) -> Result<(), Self::Denial> {
        let allowed = self.into_iter().any(|req| held.contains_all(req));

        if allowed {
            Ok(())
        } else {
            Err(InsufficientScope)
        }
    }
}

impl IntoIterator for ScopePolicy {
    type Item = Scope;
    type IntoIter = IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        let inner = match self.inner {
            ScopePolicyInner::DenyAll => IntoIterInner::Empty,
            ScopePolicyInner::AllowAny => IntoIterInner::One(iter::once(Scope::empty())),
            ScopePolicyInner::AllowOne(scope) => IntoIterInner::One(iter::once(scope)),
            ScopePolicyInner::AllowMany(scopes) => IntoIterInner::Many(scopes.into_iter()),
        };
        IntoIter { inner }
    }
}

/// An iterator over the scopes in a [`ScopePolicy`]
#[derive(Debug)]
pub struct IntoIter {
    inner: IntoIterInner,
}

#[derive(Debug)]
enum IntoIterInner {
    Empty,
    One(iter::Once<Scope>),
    Many(vec::IntoIter<Scope>),
}

impl Iterator for IntoIter {
    type Item = Scope;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            IntoIterInner::Empty => None,
            IntoIterInner::One(iter) => iter.next(),
            IntoIterInner::Many(iter) => iter.next(),
        }
    }
}

/// An iterator over a set of borrowed scopes
#[derive(Clone, Debug)]
pub struct Iter<'a> {
    inner: IterInner<'a>,
}

#[derive(Clone, Debug)]
enum IterInner<'a> {
    Empty,
    One(iter::Once<&'a Scope>),
    Many(slice::Iter<'a, Scope>),
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Scope;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            IterInner::Empty => None,
            IterInner::One(iter) => iter.next(),
            IterInner::Many(iter) => iter.next(),
        }
    }
}

impl<'a> IntoIterator for &'a ScopePolicy {
    type Item = &'a Scope;
    type IntoIter = Iter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        const EMPTY_SCOPE: &Scope = &Scope::empty();
        Iter {
            inner: match &self.inner {
                ScopePolicyInner::DenyAll => IterInner::Empty,
                ScopePolicyInner::AllowAny => IterInner::One(iter::once(EMPTY_SCOPE)),
                ScopePolicyInner::AllowOne(scope) => IterInner::One(iter::once(scope)),
                ScopePolicyInner::AllowMany(scopes) => IterInner::Many(scopes.iter()),
            },
        }
    }
}

impl Extend<Scope> for ScopePolicy {
    #[inline]
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Scope>,
    {
        for scope in iter {
            self.allow(scope);

            if self.is_allow_all() {
                break;
            }
        }
    }
}

impl iter::FromIterator<Scope> for ScopePolicy {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        let mut set = Self::deny_all();
        set.extend(iter);
        set
    }
}

impl From<Scope> for ScopePolicy {
    #[inline]
    fn from(scope: Scope) -> Self {
        Self::allow_one(scope)
    }
}

/// Construct a policy from a list of scope alternatives.
///
/// For more information about how the alternatives are evaluated, see [`ScopePolicy`].
///
/// ```
/// use aliri_oauth2::{scope, policy};
///
/// let policy = policy![
///     scope!["admin"],
///     scope!["special", "user"],
/// ];
/// ```
///
/// This is equivalent to the following:
///
/// ```
/// use aliri_oauth2::{ScopePolicy, scope};
///
/// let policy = ScopePolicy::deny_all()
///     .or_allow(scope!["admin"])
///     .or_allow(scope!["special", "user"]);
/// ```
#[macro_export]
macro_rules! policy {
    ($($scope:expr),* $(,)?) => {
        $crate::ScopePolicy::deny_all()
        $(
            .or_allow($scope)
        )*
    };
}
