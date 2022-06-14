use crate::Scope;
use std::iter::FromIterator;
use thiserror::Error;

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
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            alternatives: Vec::new(),
        }
    }

    /// Constructs a policy that does not require any scopes (allow)
    #[inline]
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            alternatives: vec![Scope::empty()],
        }
    }

    /// Constructs a policy that requires this set of scopes
    #[inline]
    #[must_use]
    pub fn allow_one(scope: Scope) -> Self {
        Self {
            alternatives: vec![scope],
        }
    }

    /// Add an alternate allowable scope
    #[inline]
    #[must_use]
    pub fn or_allow(self, scope: Scope) -> Self {
        let mut s = self;
        s.allow(scope);
        s
    }

    /// Add an alternate allowable scope
    #[inline]
    pub fn allow(&mut self, scope: Scope) {
        if !self.is_allow_all() {
            if scope.is_empty() {
                self.alternatives.clear();
            }
            self.alternatives.push(scope);
        }
    }

    /// Constructs a policy that requires this set of scopes from a string
    ///
    /// # Panics
    ///
    /// This function will panic if the provided string is not a valid [`Scope`].
    #[must_use]
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
    #[must_use]
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

    fn is_allow_all(&self) -> bool {
        self.alternatives.first().map_or(false, Scope::is_empty)
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
        self.alternatives.extend(iter);
        if self.alternatives.iter().any(Scope::is_empty) {
            self.alternatives.clear();
            self.alternatives.push(Scope::empty());
        }
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
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use aliri_oauth2::{scope, policy};
///
/// let policy = policy![
///     scope!["admin"]?,
///     scope!["special", "user"]?,
/// ];
/// # Ok(()) }
/// ```
///
/// This is equivalent to the following:
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use aliri_oauth2::{ScopePolicy, scope};
///
/// let policy = ScopePolicy::deny_all()
///     .or_allow(scope!["admin"]?)
///     .or_allow(scope!["special", "user"]?);
/// # Ok(()) }
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
