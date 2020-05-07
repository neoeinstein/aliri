//! Implementations of the JSON Web Keys (JWK) standard
//!
//! The specifications for JSON Web Keys can be found in [RFC7517][].
//!
//! [RFC7517]: https://tools.ietf.org/html/rfc7517

use aliri_core::base64::Base64Url;
use aliri_macros::typed_string;
use serde::{Deserialize, Serialize};

use crate::{
    jwa,
    jws::{self, Signer, Verifier},
    jwt::{self, HasSigningAlgorithm},
    Jwt,
};

typed_string! {
    /// An identifier for a JWK
    pub struct KeyId(String);

    /// Reference to `KeyId`
    pub struct KeyIdRef(str);
}

/// The type of JWK
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// RSA key
    #[cfg(feature = "rsa")]
    #[serde(rename = "RSA")]
    Rsa,

    /// Elliptic curve cryptography key
    #[cfg(feature = "ec")]
    #[serde(rename = "EC")]
    EllipticCurve,

    /// HMAC shared secret
    #[cfg(feature = "hmac")]
    #[serde(rename = "oct")]
    Hmac,
}

impl KeyType {
    fn is_compatible_with_alg(self, alg: jws::Algorithm) -> bool {
        match (self, alg) {
            #[cfg(feature = "rsa")]
            (Self::Rsa, jws::Algorithm::RS256)
            | (Self::Rsa, jws::Algorithm::RS384)
            | (Self::Rsa, jws::Algorithm::RS512)
            | (Self::Rsa, jws::Algorithm::PS256)
            | (Self::Rsa, jws::Algorithm::PS384)
            | (Self::Rsa, jws::Algorithm::PS512) => true,

            #[cfg(feature = "hmac")]
            (Self::Hmac, jws::Algorithm::HS256)
            | (Self::Hmac, jws::Algorithm::HS384)
            | (Self::Hmac, jws::Algorithm::HS512) => true,

            #[cfg(feature = "ec")]
            (Self::EllipticCurve, jws::Algorithm::ES256)
            | (Self::EllipticCurve, jws::Algorithm::ES384) => true,

            _ => false,
        }
    }
}

/// An identified JSON Web Key
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// The key ID
    #[serde(rename = "kid")]
    pub id: Option<KeyId>,

    /// The intended usage of the key
    #[serde(rename = "use")]
    pub usage: Option<Usage>,

    /// The algorithm to be used with this JWK
    #[serde(rename = "alg")]
    pub algorithm: Option<jws::Algorithm>,

    /// JWK parameters
    #[serde(flatten)]
    pub params: Parameters,
}

impl Jwk {
    pub(crate) fn verify_decomposed<C, H>(
        &self,
        jwt: jwt::Decomposed<H>,
        validation: &jwt::Validation,
    ) -> anyhow::Result<jwt::Validated<C, H>>
    where
        C: for<'de> Deserialize<'de>,
        H: for<'de> Deserialize<'de>,
    {
        if let Some(u) = self.usage {
            if u != Usage::Signing {
                return Err(anyhow::anyhow!("JWK cannot be used for verification"));
            }
        }

        if let Some(a) = self.algorithm {
            if a != jwt.header.alg() {
                return Err(anyhow::anyhow!(
                    "token algorithm does not match JWK algorithm"
                ));
            }
        }

        if self
            .params
            .to_key_type()
            .is_compatible_with_alg(jwt.header.alg())
        {
            match (&self.params, jwt.header.alg()) {
                #[cfg(feature = "hmac")]
                (Parameters::Hmac(p), jws::Algorithm::Hmac(sa)) => {
                    p.verify(sa, jwt.message.as_bytes(), jwt.signature.as_slice())?
                }

                #[cfg(feature = "rsa")]
                (Parameters::Rsa(p), jws::Algorithm::Rsa(sa)) => {
                    p.verify(sa, jwt.message.as_bytes(), jwt.signature.as_slice())?
                }

                #[cfg(feature = "ec")]
                (Parameters::EllipticCurve(p), jws::Algorithm::EllipticCurve(sa)) => {
                    p.verify(sa, jwt.message.as_bytes(), jwt.signature.as_slice())?
                }

                _ => unreachable!(),
            }

            let p_raw = Base64Url::from_encoded(jwt.payload)?;

            let payload: jwt::Claims<C> = serde_json::from_slice(p_raw.as_slice())?;

            validation.validate(&jwt.header, &payload)?;

            Ok(jwt::Validated::new(
                jwt.header.take_headers(),
                payload.take_payload(),
            ))
        } else {
            Err(anyhow::anyhow!(
                "JWK is not compatible with token algorithm"
            ))
        }
    }

    /// Produces a signed JWT with the given header and claims
    #[cfg(feature = "private-keys")]
    pub fn sign<H: Serialize + HasSigningAlgorithm, C: Serialize>(
        &self,
        header: &H,
        claims: &C,
    ) -> Result<Jwt, anyhow::Error> {
        use std::fmt::Write;

        if let Some(u) = self.usage {
            if u != Usage::Signing {
                return Err(anyhow::anyhow!("JWK cannot be used for signing"));
            }
        }

        if let Some(a) = self.algorithm {
            if a != header.alg() {
                return Err(anyhow::anyhow!(
                    "token algorithm does not match JWK algorithm"
                ));
            }
        }

        let h_raw = Base64Url::from_raw(serde_json::to_vec(header)?);
        let p_raw = Base64Url::from_raw(serde_json::to_vec(claims)?);

        let expected_len = h_raw.encoded_len()
            + p_raw.encoded_len()
            + Base64Url::calc_encoded_len(header.alg().signature_size())
            + 2;

        let mut message = String::with_capacity(expected_len);
        write!(message, "{}.{}", h_raw, p_raw).expect("writes to strings never fail");

        if self
            .params
            .to_key_type()
            .is_compatible_with_alg(header.alg())
        {
            let s = Base64Url::from_raw(match (&self.params, header.alg()) {
                #[cfg(feature = "hmac")]
                (Parameters::Hmac(p), jws::Algorithm::Hmac(sa)) => {
                    p.sign(sa, message.as_bytes())?
                }

                #[cfg(feature = "rsa")]
                (Parameters::Rsa(p), jws::Algorithm::Rsa(sa)) => p.sign(sa, message.as_bytes())?,

                #[cfg(feature = "ec")]
                (Parameters::EllipticCurve(p), jws::Algorithm::EllipticCurve(sa)) => {
                    p.sign(sa, message.as_bytes())?
                }

                _ => unreachable!(),
            });

            write!(message, ".{}", s).expect("writes to strings never fail");

            debug_assert_eq!(message.len(), expected_len);

            Ok(Jwt::new(message))
        } else {
            Err(anyhow::anyhow!(
                "JWK is not compatible with token algorithm"
            ))
        }
    }
}

/// The intended use for a JWK
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Usage {
    /// The JWK is intended signing and verification
    #[serde(rename = "sig")]
    Signing,

    /// The JWK is intended for encryption
    #[serde(rename = "enc")]
    Encryption,
}

/// A JSON Web Key
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Parameters {
    /// RSA
    #[cfg(feature = "rsa")]
    #[serde(rename = "RSA")]
    Rsa(jwa::Rsa),

    /// Elliptic curve cryptography
    #[cfg(feature = "ec")]
    #[serde(rename = "EC")]
    EllipticCurve(jwa::EllipticCurve),

    /// HMAC symmetric
    #[cfg(feature = "hmac")]
    #[serde(rename = "oct")]
    Hmac(jwa::Hmac),
}

impl Parameters {
    /// Generates new JWK parameters based on the algorithm specified
    #[cfg(feature = "private-keys")]
    pub fn generate(alg: jws::Algorithm) -> anyhow::Result<Self> {
        match alg {
            #[cfg(feature = "hmac")]
            jws::Algorithm::Hmac(a) => Self::generate_hmac(a),

            #[cfg(feature = "rsa")]
            jws::Algorithm::RS256
            | jws::Algorithm::RS384
            | jws::Algorithm::RS512
            | jws::Algorithm::PS256
            | jws::Algorithm::PS384
            | jws::Algorithm::PS512 => Self::generate_rsa(),

            #[cfg(feature = "ec")]
            jws::Algorithm::ES256 => Self::generate_ec(jwa::ec::Curve::P256),
            #[cfg(feature = "ec")]
            jws::Algorithm::ES384 => Self::generate_ec(jwa::ec::Curve::P384),

            jws::Algorithm::Unknown => Err(anyhow::anyhow!("unknown algorithm")),
        }
    }

    /// Generates a JWK using a newly minted RSA key pair
    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    pub fn generate_rsa() -> anyhow::Result<Self> {
        Ok(Parameters::Rsa(jwa::Rsa::generate()?))
    }

    /// Generates a JWK using a newly minted ECC key pair
    #[cfg(all(feature = "ec", feature = "private-keys"))]
    pub fn generate_ec(curve: jwa::ec::Curve) -> anyhow::Result<Self> {
        Ok(Parameters::EllipticCurve(jwa::EllipticCurve::generate(
            curve,
        )?))
    }

    /// Generates a JWK using a newly minted HMAC secret
    #[cfg(all(feature = "hmac", feature = "private-keys"))]
    pub fn generate_hmac(alg: jwa::hmac::SigningAlgorithm) -> anyhow::Result<Self> {
        Ok(Parameters::Hmac(jwa::Hmac::generate(alg)?))
    }

    /// Returns the algorithm family used by the key.
    fn to_key_type(&self) -> KeyType {
        match self {
            #[cfg(feature = "rsa")]
            Self::Rsa(_) => KeyType::Rsa,

            #[cfg(feature = "ec")]
            Self::EllipticCurve(_) => KeyType::EllipticCurve,

            #[cfg(feature = "hmac")]
            Self::Hmac(_) => KeyType::Hmac,
        }
    }
}

#[cfg(test)]
#[cfg(any(feature = "ec", feature = "rsa", feature = "hmac"))]
mod tests {
    use super::*;

    mod serialization {
        use crate::test;

        use super::*;

        #[cfg(feature = "ec")]
        mod ec {
            use super::*;

            mod public {
                use super::*;

                #[test]
                fn deserialize() -> anyhow::Result<()> {
                    let key: Jwk = serde_json::from_str(test::ec::JWK)?;
                    assert_eq!(key.algorithm, Some(jws::Algorithm::ES256));
                    Ok(())
                }

                #[test]
                fn deserialize_minimal() -> anyhow::Result<()> {
                    let key: Jwk = serde_json::from_str(test::ec::JWK_MINIMAL)?;
                    assert_eq!(key.algorithm, None);
                    Ok(())
                }
            }

            #[cfg(feature = "private-keys")]
            mod private {
                use super::*;

                #[test]
                fn deserialize_with_private_key() -> anyhow::Result<()> {
                    let key: Jwk = serde_json::from_str(test::ec::JWK_WITH_PRIVATE_KEY)?;
                    assert_eq!(key.algorithm, Some(jws::Algorithm::ES256));
                    Ok(())
                }

                #[test]
                fn deserialize_minimal_with_private_key() -> anyhow::Result<()> {
                    let key: Jwk = serde_json::from_str(test::ec::JWK_WITH_MINIMAL_PRIVATE_KEY)?;
                    assert_eq!(key.algorithm, None);
                    Ok(())
                }
            }
        }

        #[cfg(feature = "hmac")]
        mod hmac {
            use super::*;

            #[test]
            fn deserialize() -> anyhow::Result<()> {
                let key: Jwk = serde_json::from_str(test::hmac::JWK)?;
                assert_eq!(key.algorithm, Some(jws::Algorithm::HS256));
                Ok(())
            }

            #[test]
            fn deserialize_minimal() -> anyhow::Result<()> {
                let key: Jwk = serde_json::from_str(test::hmac::JWK_MINIMAL)?;
                assert_eq!(key.algorithm, None);
                Ok(())
            }
        }

        #[cfg(feature = "rsa")]
        mod rsa {
            use super::*;

            mod public {
                use super::*;

                #[test]
                fn deserialize_with_private_key() -> anyhow::Result<()> {
                    let key: Jwk = serde_json::from_str(test::rsa::JWK_WITH_PRIVATE_KEY)?;
                    assert_eq!(key.algorithm, Some(jws::Algorithm::RS256));
                    Ok(())
                }

                #[test]
                fn deserialize_minimal_with_private_key() -> anyhow::Result<()> {
                    let key: Jwk = serde_json::from_str(test::rsa::JWK_WITH_MINIMAL_PRIVATE_KEY)?;
                    assert_eq!(key.algorithm, None);
                    Ok(())
                }
            }

            #[cfg(feature = "private-keys")]
            mod private {
                use super::*;

                #[test]
                fn deserialize_with_private_key() -> anyhow::Result<()> {
                    let key: Jwk = serde_json::from_str(test::rsa::JWK_WITH_PRIVATE_KEY)?;
                    assert_eq!(key.algorithm, Some(jws::Algorithm::RS256));
                    Ok(())
                }

                #[test]
                fn deserialize_minimal_with_private_key() -> anyhow::Result<()> {
                    let key: Jwk = serde_json::from_str(test::rsa::JWK_WITH_MINIMAL_PRIVATE_KEY)?;
                    assert_eq!(key.algorithm, None);
                    Ok(())
                }
            }
        }
    }

    #[cfg(feature = "private-keys")]
    mod key_generation {
        use crate::test;

        use super::*;

        #[cfg(feature = "ec")]
        mod ec {
            use super::*;

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_ES256() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::ES256)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_ES384() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::ES384)
            }
        }

        #[cfg(feature = "hmac")]
        mod hmac {
            use super::*;

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_HS256() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::HS256)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_HS384() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::HS384)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_HS512() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::HS512)
            }
        }

        #[cfg(feature = "rsa")]
        mod rsa {
            use super::*;

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_RS256() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::RS256)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_RS384() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::RS384)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_RS512() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::RS512)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_PS256() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::PS256)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_PS384() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::PS384)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_PS512() -> anyhow::Result<()> {
                gen_and_rt(jws::Algorithm::PS512)
            }
        }

        fn gen_and_rt(alg: jws::Algorithm) -> anyhow::Result<()> {
            let jwk_params = Parameters::generate(alg)?;
            dbg!(&jwk_params);

            let jwk = Jwk {
                id: None,
                usage: Some(Usage::Signing),
                algorithm: Some(alg),
                params: jwk_params,
            };

            let header = jwt::Headers::new(alg);

            let claims = jwt::Claims::new()
                .with_audience(*test::TEST_AUD)
                .with_future_expiration(60 * 5);

            let encoded = jwk.sign(&header, &claims)?;

            dbg!(&encoded);

            let validator = jwt::Validation::default()
                .add_approved_algorithm(alg)
                .add_allowed_audience(test::TEST_AUD.to_owned());

            let data: jwt::Validated<jwt::Claims> = encoded.verify(&jwk, &validator)?;
            dbg!(data.claims());

            Ok(())
        }
    }
}
