use ahash::AHashSet;

use super::{Scope, ScopeRef};

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Directive {
    required_scopes: AHashSet<Scope>,
}

impl Directive {
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
