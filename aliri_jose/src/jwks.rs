use std::borrow::Borrow;

use crate::{
    jwk::{self, Jwk},
    jws,
};

use serde::{Deserialize, Serialize};

/// A JSON Web Key set
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

impl Jwks {
    pub fn add_key(&mut self, key: Jwk) {
        self.keys.push(key);
    }

    fn keys_with_good_algorithms(&self) -> impl Iterator<Item = &Jwk> {
        self.keys
            .iter()
            .filter(|k| k.algorithm != Some(jws::Algorithm::Unknown))
    }

    fn find_exact_matches<'a, 'b: 'a>(
        &'a self,
        kid: &'b jwk::KeyIdRef,
        alg: jws::Algorithm,
    ) -> impl Iterator<Item = &'a Jwk> {
        self.keys_with_good_algorithms()
            .filter(move |k| k.id.as_deref() == Some(kid) && k.algorithm == Some(alg))
    }

    fn find_kid_only_matches<'a, 'b: 'a>(
        &'a self,
        kid: &'b jwk::KeyIdRef,
    ) -> impl Iterator<Item = &'a Jwk> {
        self.keys_with_good_algorithms()
            .filter(move |k| k.id.as_deref() == Some(kid) && k.algorithm == None)
    }

    fn find_anon_alg_matches(&self, alg: jws::Algorithm) -> impl Iterator<Item = &Jwk> {
        self.keys_with_good_algorithms().filter(move |k| {
            alg != jws::Algorithm::Unknown && k.id == None && k.algorithm == Some(alg)
        })
    }

    fn find_anon_no_alg_matches(&self) -> impl Iterator<Item = &Jwk> {
        self.keys_with_good_algorithms()
            .filter(move |k| k.id == None && k.algorithm == None)
    }

    fn find_any_alg_matches(&self, alg: jws::Algorithm) -> impl Iterator<Item = &Jwk> {
        self.keys_with_good_algorithms().filter(move |k| {
            alg != jws::Algorithm::Unknown && k.id == None && k.algorithm == Some(alg)
        })
    }

    fn find_any_no_alg_matches(&self) -> impl Iterator<Item = &Jwk> {
        self.keys_with_good_algorithms()
            .filter(move |k| k.algorithm == None)
    }

    /// Gets the identified key for the given algorithm.
    pub fn get_key_by_id<'a, 'b: 'a, K: Borrow<jwk::KeyIdRef> + ?Sized + 'b>(
        &'a self,
        kid: &'b K,
        alg: jws::Algorithm,
    ) -> impl Iterator<Item = &'a Jwk> + 'a {
        let borrowed_kid = kid.borrow();
        self.find_exact_matches(borrowed_kid, alg)
            .chain(self.find_kid_only_matches(borrowed_kid))
            .chain(self.find_anon_alg_matches(alg))
            .chain(self.find_anon_no_alg_matches())
    }

    /// Gets the any key for the given algorithm.
    pub fn get_key(&self, alg: jws::Algorithm) -> impl Iterator<Item = &Jwk> {
        self.find_any_alg_matches(alg)
            .chain(self.find_any_no_alg_matches())
    }

    pub fn get_key_by_opt<'a, 'b: 'a, K: Borrow<jwk::KeyIdRef> + ?Sized + 'b>(
        &'a self,
        kid: Option<&'b K>,
        alg: jws::Algorithm,
    ) -> impl Iterator<Item = &'a Jwk> + 'a {
        if let Some(kid) = kid {
            Either::A(self.get_key_by_id(kid, alg))
        } else {
            Either::B(self.get_key(alg))
        }
    }
}

enum Either<A, B> {
    A(A),
    B(B),
}

impl<A, B> Iterator for Either<A, B>
where
    A: Iterator,
    B: Iterator<Item = A::Item>,
{
    type Item = A::Item;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::A(a) => a.next(),
            Self::B(b) => b.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    use crate::{
        jwa,
        jwk::{KeyId, Parameters, Usage},
    };

    #[cfg(feature = "rsa")]
    use crate::test;

    #[cfg(feature = "rsa")]
    use super::*;

    #[test]
    #[cfg(feature = "rsa")]
    fn decodes_jwks() -> anyhow::Result<()> {
        let jwks: Jwks = serde_json::from_str(test::rsa::JWKS)?;
        dbg!(&jwks);
        Ok(())
    }

    #[test]
    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    fn serializable_roundtrip() -> anyhow::Result<()> {
        let rsa = Jwk {
            id: Some(KeyId::new("rsa")),
            usage: Some(Usage::Signing),
            algorithm: Some(jws::Algorithm::RS256),
            params: Parameters::Rsa(jwa::Rsa::generate()?),
        };

        let mut jwks = Jwks::default();
        jwks.add_key(rsa);
        let serialized = serde_json::to_string(&jwks)?;
        dbg!(&serialized);

        let roundtrip: Jwks = serde_json::from_str(&serialized)?;
        dbg!(&roundtrip);

        assert_eq!(roundtrip, jwks);
        Ok(())
    }
}
