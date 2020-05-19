use crate::{jwa, jwk, Jwk};

use serde::{Deserialize, Serialize};

/// A JSON Web Key Set (JWKS)
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

impl Jwks {
    /// Adds a key to the set
    pub fn add_key(&mut self, key: Jwk) {
        self.keys.push(key);
    }

    /// A view of the keys in this set
    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// Gets the best key based on the algorithm requested
    pub fn get_key<A: Into<jwa::Algorithm>>(&self, alg: A) -> Option<&Jwk> {
        get_key_impl(self.keys(), alg.into())
    }

    /// Gets the best key based on the key id and algorithm requested
    pub fn get_key_by_id<A: Into<jwa::Algorithm>>(
        &self,
        kid: &'_ jwk::KeyIdRef,
        alg: A,
    ) -> Option<&Jwk> {
        get_key_by_id_impl(self.keys(), kid, alg.into())
    }

    /// Gets the best key based on the key id (if provided) and algorithm requested
    pub fn get_key_by_opt<A: Into<jwa::Algorithm>>(
        &self,
        kid: Option<&'_ jwk::KeyIdRef>,
        alg: A,
    ) -> Option<&Jwk> {
        match kid {
            Some(kid) => get_key_by_id_impl(self.keys(), kid, alg.into()),
            None => get_key_impl(self.keys(), alg.into()),
        }
    }
}

fn get_key_impl(keys: &[Jwk], alg: jwa::Algorithm) -> Option<&Jwk> {
    let alg_usage = alg.to_usage();

    let best = keys.iter().fold(None, move |best, k| {
        let mut score = 0;

        dbg!(k);

        if !k.is_compatible(alg) {
            return best;
        }

        if let Some(algorithm) = k.algorithm() {
            if algorithm == alg {
                score += 2;
            } else {
                return best;
            }
        }

        if let Some(key_usage) = k.usage() {
            if key_usage == alg_usage {
                score += 1;
            } else {
                return best;
            }
        }

        match best {
            Some((_, best_score)) if best_score < score => Some((k, score)),
            None => Some((k, score)),
            _ => best,
        }
    });

    best.map(|(b, _)| b)
}

fn get_key_by_id_impl<'a>(
    keys: &'a [Jwk],
    kid: &'_ jwk::KeyIdRef,
    alg: jwa::Algorithm,
) -> Option<&'a Jwk> {
    let alg_usage = alg.to_usage();

    let best = keys.iter().fold(None, move |best, k| {
        let mut score = 0;

        dbg!(k);

        if !k.is_compatible(alg) {
            return best;
        }

        dbg!(score);

        if let Some(key_id) = k.key_id() {
            if key_id == kid {
                score += 4;
            } else {
                return best;
            }
        }

        dbg!(score);

        if let Some(algorithm) = k.algorithm() {
            if algorithm == alg {
                score += 2;
            } else {
                return best;
            }
        }

        dbg!(score);

        if let Some(key_usage) = k.usage() {
            if key_usage == alg_usage {
                score += 1;
            } else {
                return best;
            }
        }

        dbg!(score);

        match best {
            Some((_, best_score)) if best_score < score => Some((k, score)),
            None => Some((k, score)),
            _ => best,
        }
    });

    best.map(|(b, _)| b)
}

#[cfg(test)]
#[cfg(feature = "rsa")]
mod tests {
    use crate::test::rsa::*;

    use super::*;

    #[test]
    fn decodes_jwks() -> anyhow::Result<()> {
        let jwks: Jwks = serde_json::from_str(JWKS)?;
        dbg!(&jwks);
        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     #[cfg(all(feature = "rsa", feature = "private-keys"))]
//     use crate::{
//         jwa,
//         jwk::{KeyId, Parameters, Usage},
//     };

//     #[cfg(feature = "rsa")]
//     use crate::test;

//     #[cfg(feature = "rsa")]
//     use super::*;

//     #[test]
//     #[cfg(feature = "rsa")]
//     fn decodes_jwks() -> anyhow::Result<()> {
//         let jwks: Jwks = serde_json::from_str(test::rsa::JWKS)?;
//         dbg!(&jwks);
//         Ok(())
//     }

//     #[test]
//     #[cfg(all(feature = "rsa", feature = "private-keys"))]
//     fn serializable_roundtrip() -> anyhow::Result<()> {
//         let rsa = Jwk {
//             id: Some(KeyId::new("rsa")),
//             usage: Some(Usage::Signing),
//             algorithm: Some(jws::Algorithm::RS256),
//             params: Parameters::Rsa(jwa::Rsa::generate()?),
//         };

//         let mut jwks = Jwks::default();
//         jwks.add_key(rsa);
//         let serialized = serde_json::to_string(&jwks)?;
//         dbg!(&serialized);

//         let roundtrip: Jwks = serde_json::from_str(&serialized)?;
//         dbg!(&roundtrip);

//         assert_eq!(roundtrip, jwks);
//         Ok(())
//     }
// }
