mod authority;
mod directive;

pub use authority::JwksAuthority;
pub use directive::Directive;

use aliri_macros::typed_string;

typed_string! {
    /// A scope
    pub struct Scope(String);

    /// A borrowed reference to a scope
    pub struct ScopeRef(str);
}
