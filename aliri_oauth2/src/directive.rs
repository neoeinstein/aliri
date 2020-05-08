use super::{HasScopes, Scope};

/// A directive requiring a token to have been granted all of the specified
/// scopes
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Directive {
    required_scopes: Vec<Scope>,
}

impl Directive {
    /// Constructs a new directive from a set of scopes
    ///
    /// The resulting directive will require that a token has all of the
    /// identified scopes to be authorized.
    pub fn new(scopes: impl IntoIterator<Item = Scope>) -> Self {
        Self {
            required_scopes: scopes.into_iter().collect(),
        }
    }

    /// Check whether sufficient scopes are held
    ///
    /// Checks to see whether the scopes required by this directive
    /// are completely satisfied by the provided set of held scopes.
    #[inline]
    pub fn check_scopes<S: HasScopes>(&self, held_scopes: &S) -> bool {
        held_scopes.scopes().contains_all(&self.required_scopes)
    }
}
