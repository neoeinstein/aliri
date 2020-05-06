#![deny(unsafe_code)]

mod authority;
pub mod oauth2;

pub use authority::Authority;

use aliri_macros::typed_string;

typed_string! {
    /// A token
    pub struct Token(String);

    /// A borrowed reference to a token
    pub struct TokenRef(str);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
