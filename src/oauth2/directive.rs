use ahash::AHashSet;

use super::{Scope, ScopeRef};

/// A directive requiring a token to have been granted all of the specified
/// scopes
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Directive {
    required_scopes: AHashSet<Scope>,
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

    pub(super) fn validate(&self, held_scopes: &AHashSet<&ScopeRef>) -> bool {
        self.required_scopes
            .iter()
            .all(|v| held_scopes.contains(v.as_ref()))
    }
}
