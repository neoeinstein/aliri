use aliri_jose::jwt;
use aliri_macros::typed_string;

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
    fn scopes(&self) -> &[Scope] {
        &[]
    }
}

impl HasScopes for jwt::Empty {}
