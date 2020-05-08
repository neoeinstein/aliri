//! Authorization based on OAuth2 scopes

mod authority;
mod directive;
mod scope;

pub use authority::JwksAuthority;
pub use directive::Directive;
pub use scope::{HasScopes, Scope, ScopeRef};
