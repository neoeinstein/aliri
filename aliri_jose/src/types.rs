use aliri_core::OneOrMany;
use aliri_macros::typed_string;
use serde::{Deserialize, Serialize};

typed_string! {
    /// An audience
    pub struct Audience(String);

    /// Reference to `Audience`
    pub struct AudienceRef(str);
}

typed_string! {
    /// An issuer of JWTs
    pub struct Issuer(String);

    /// Reference to `Issuer`
    pub struct IssuerRef(str);
}

typed_string! {
    /// An identifier for a JWK
    pub struct KeyId(String);

    /// Reference to `KeyId`
    pub struct KeyIdRef(str);
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "OneOrMany<Audience>", into = "OneOrMany<Audience>")]
#[repr(transparent)]
pub struct Audiences(Vec<Audience>);

impl Audiences {
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    pub const EMPTY_AUD: &'static Audiences = &Audiences::new();

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &AudienceRef> {
        self.0.iter().map(|i| i.as_ref())
    }
}

impl From<OneOrMany<Audience>> for Audiences {
    fn from(vals: OneOrMany<Audience>) -> Self {
        match vals {
            OneOrMany::One(x) => Self(vec![x]),
            OneOrMany::Many(v) => Self(v),
        }
    }
}

impl From<Vec<Audience>> for Audiences {
    fn from(vals: Vec<Audience>) -> Self {
        Self(vals)
    }
}

impl From<Audiences> for OneOrMany<Audience> {
    fn from(mut vec: Audiences) -> Self {
        if vec.0.len() == 1 {
            Self::One(vec.0.pop().unwrap())
        } else {
            Self::Many(vec.0)
        }
    }
}
