use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

#[cfg(feature = "ec")]
pub mod ec;
#[cfg(feature = "hmac")]
pub mod hmac;
#[cfg(feature = "rsa")]
pub mod rsa;

use crate::{jwa, verify::PayloadWithBasicClaims, BasicValidation, CoreClaims, KeyId};

/// An identified JSON Web Key
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(rename = "kid")]
    pub id: Option<KeyId>,

    #[serde(rename = "use")]
    pub usage: Option<Usage>,

    #[serde(rename = "alg")]
    pub algorithm: Option<jwa::Algorithm>,

    #[serde(flatten)]
    pub params: Parameters,
}

lazy_static! {
    static ref HMAC_BLANK_CHECK: jsonwebtoken::Validation = jsonwebtoken::Validation {
        validate_exp: false,
        algorithms: vec![
            jsonwebtoken::Algorithm::HS256,
            jsonwebtoken::Algorithm::HS384,
            jsonwebtoken::Algorithm::HS512,
        ],
        ..Default::default()
    };
    static ref RSA_BLANK_CHECK: jsonwebtoken::Validation = jsonwebtoken::Validation {
        validate_exp: false,
        algorithms: vec![
            jsonwebtoken::Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512,
            jsonwebtoken::Algorithm::PS256,
            jsonwebtoken::Algorithm::PS384,
            jsonwebtoken::Algorithm::PS512,
        ],
        ..Default::default()
    };
    static ref EC_BLANK_CHECK: jsonwebtoken::Validation = jsonwebtoken::Validation {
        validate_exp: false,
        algorithms: vec![
            jsonwebtoken::Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384,
        ],
        ..Default::default()
    };
    static ref RSA_ALGOS: &'static [jsonwebtoken::Algorithm] = &[];
    static ref EC_ALGOS: &'static [jsonwebtoken::Algorithm] = &[
        jsonwebtoken::Algorithm::ES256,
        jsonwebtoken::Algorithm::ES384,
    ];
}

impl Jwk {
    #[doc(hidden)]
    pub fn verify_token<C: for<'de> serde::Deserialize<'de> + CoreClaims>(
        &self,
        token: &str,
        validation: &BasicValidation,
    ) -> anyhow::Result<C> {
        let decoder = self.params.verify_key();

        let blank = match self.params.to_family() {
            jwa::KeyType::Hmac => &*HMAC_BLANK_CHECK,
            jwa::KeyType::Rsa => &*RSA_BLANK_CHECK,
            jwa::KeyType::EllipticCurve => &*EC_BLANK_CHECK,
        };

        let token_data: jsonwebtoken::TokenData<PayloadWithBasicClaims<C>> =
            jsonwebtoken::decode(token, &decoder, &blank)?;

        validation.validate(&token_data.header, &token_data.claims)?;

        Ok(token_data.claims.payload)
    }

    #[doc(hidden)]
    #[cfg(feature = "private-keys")]
    pub fn sign<C: serde::Serialize>(
        &self,
        header: &jsonwebtoken::Header,
        claims: &C,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let encoder = self.params.signing_key().unwrap();
        Ok(jsonwebtoken::encode(header, claims, &encoder)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Usage {
    #[serde(rename = "sig")]
    Signing,
    #[serde(rename = "enc")]
    Encryption,
}

/// A JSON Web Key
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Parameters {
    #[cfg(feature = "rsa")]
    #[serde(rename = "RSA")]
    Rsa(rsa::Parameters),

    #[cfg(feature = "ec")]
    #[serde(rename = "EC")]
    EllipticCurve(ec::Parameters),

    #[cfg(feature = "hmac")]
    #[serde(rename = "oct")]
    Hmac(hmac::Parameters),
}

impl Parameters {
    /// Generates new JWK parameters based on the algorithm specified
    #[cfg(feature = "private-keys")]
    pub fn generate(alg: jwa::Algorithm) -> anyhow::Result<Self> {
        match alg {
            #[cfg(feature = "hmac")]
            jwa::Algorithm::HS256 => Self::generate_hmac(256),
            #[cfg(feature = "hmac")]
            jwa::Algorithm::HS384 => Self::generate_hmac(384),
            #[cfg(feature = "hmac")]
            jwa::Algorithm::HS512 => Self::generate_hmac(512),

            #[cfg(feature = "rsa")]
            jwa::Algorithm::RS256
            | jwa::Algorithm::RS384
            | jwa::Algorithm::RS512
            | jwa::Algorithm::PS256
            | jwa::Algorithm::PS384
            | jwa::Algorithm::PS512 => Self::generate_rsa(),

            #[cfg(feature = "ec")]
            jwa::Algorithm::ES256 => Self::generate_ec(ec::Curve::P256),
            #[cfg(feature = "ec")]
            jwa::Algorithm::ES384 => Self::generate_ec(ec::Curve::P384),

            jwa::Algorithm::Unknown => Err(anyhow::anyhow!("unknown algorithm")),
        }
    }

    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    pub fn generate_rsa() -> anyhow::Result<Self> {
        Ok(Parameters::Rsa(rsa::Parameters::generate()?))
    }

    #[cfg(all(feature = "ec", feature = "private-keys"))]
    pub fn generate_ec(curve: ec::Curve) -> anyhow::Result<Self> {
        Ok(Parameters::EllipticCurve(ec::Parameters::generate(curve)?))
    }

    #[cfg(all(feature = "hmac", feature = "private-keys"))]
    pub fn generate_hmac(bits: usize) -> anyhow::Result<Self> {
        Ok(Parameters::Hmac(hmac::Parameters::generate(bits)?))
    }

    fn verify_key(&self) -> jsonwebtoken::DecodingKey {
        match self {
            #[cfg(feature = "rsa")]
            Self::Rsa(p) => p.verify_key(),

            #[cfg(feature = "ec")]
            Self::EllipticCurve(p) => p.verify_key(),

            #[cfg(feature = "hmac")]
            Self::Hmac(p) => p.verify_key(),
        }
    }

    #[cfg(feature = "private-keys")]
    fn signing_key(&self) -> Option<jsonwebtoken::EncodingKey> {
        match self {
            #[cfg(feature = "rsa")]
            Self::Rsa(p) => p.signing_key(),

            #[cfg(feature = "ec")]
            Self::EllipticCurve(p) => p.signing_key(),

            #[cfg(feature = "hmac")]
            Self::Hmac(p) => Some(p.signing_key()),
        }
    }

    /// Returns the algorithm family used by the key.
    pub fn to_family(&self) -> jwa::KeyType {
        match self {
            #[cfg(feature = "rsa")]
            Self::Rsa(_) => jwa::KeyType::Rsa,

            #[cfg(feature = "ec")]
            Self::EllipticCurve(_) => jwa::KeyType::EllipticCurve,

            #[cfg(feature = "hmac")]
            Self::Hmac(_) => jwa::KeyType::Hmac,
        }
    }

    /// Returns the RSA parameters for the public key, if the key is an RSA key.
    #[cfg(feature = "rsa")]
    pub fn as_rsa_params(&self) -> Option<&rsa::Parameters> {
        match self {
            Self::Rsa(p) => Some(&p),

            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Returns the elliptic curve parameters for the public key, if the key is an RSA key.
    #[cfg(feature = "ec")]
    pub fn as_ec_params(&self) -> Option<&ec::Parameters> {
        match self {
            Self::EllipticCurve(p) => Some(&p),

            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    #[cfg(feature = "hmac")]
    pub fn as_sym_params(&self) -> Option<&hmac::Parameters> {
        match self {
            Self::Hmac(p) => Some(&p),

            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

#[cfg(test)]
#[cfg(any(feature = "ec", feature = "rsa", feature = "hmac"))]
mod tests {
    use super::*;

    mod serialization {
        use crate::test_util;

        use super::*;

        #[cfg(feature = "ec")]
        mod ec {
            use super::*;

            mod public {
                use super::*;

                #[test]
                fn deserialize() -> anyhow::Result<()> {
                    let _key: Parameters = serde_json::from_str(test_util::ec::JWK_MINIMAL)?;
                    Ok(())
                }
            }

            #[cfg(feature = "private-keys")]
            mod private {
                use super::*;

                #[test]
                fn deserialize_with_private_key() -> anyhow::Result<()> {
                    let _key: Parameters =
                        serde_json::from_str(test_util::ec::JWK_WITH_MINIMAL_PRIVATE_KEY)?;
                    Ok(())
                }
            }
        }

        #[cfg(feature = "hmac")]
        mod hmac {
            use super::*;

            #[test]
            fn deserialize() -> anyhow::Result<()> {
                let _key: Parameters = serde_json::from_str(test_util::hmac::JWK_MINIMAL)?;
                Ok(())
            }
        }

        #[cfg(feature = "rsa")]
        mod rsa {
            use super::*;

            mod public {
                use super::*;

                #[test]
                fn deserialize() -> anyhow::Result<()> {
                    let _key: Parameters = serde_json::from_str(test_util::rsa::JWK_MINIMAL)?;
                    Ok(())
                }
            }

            #[cfg(feature = "private-keys")]
            mod private {
                use super::*;

                #[test]
                fn deserialize_with_private_key() -> anyhow::Result<()> {
                    let _key: Parameters =
                        serde_json::from_str(test_util::rsa::JWK_WITH_MINIMAL_PRIVATE_KEY)?;
                    Ok(())
                }
            }
        }
    }

    #[cfg(feature = "private-keys")]
    mod key_generation {
        use crate::{jwa::Algorithm, test_util};

        use super::*;

        #[cfg(feature = "ec")]
        mod ec {
            use super::*;

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_ES256() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::ES256)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_ES384() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::ES384)
            }
        }

        #[cfg(feature = "hmac")]
        mod hmac {
            use super::*;

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_HS256() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::HS256)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_HS384() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::HS384)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_HS512() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::HS512)
            }
        }

        #[cfg(feature = "rsa")]
        mod rsa {
            use super::*;

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_RS256() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::RS256)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_RS384() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::RS384)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_RS512() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::RS512)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_PS256() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::PS256)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_PS384() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::PS384)
            }

            #[test]
            #[allow(non_snake_case)]
            fn get_and_rt_PS512() -> anyhow::Result<()> {
                gen_and_rt(Algorithm::PS512)
            }
        }

        fn gen_and_rt(alg: Algorithm) -> anyhow::Result<()> {
            let jwk_params = Parameters::generate(alg)?;
            dbg!(&jwk_params);

            let jwk = Jwk {
                id: None,
                usage: Some(Usage::Signing),
                algorithm: Some(alg),
                params: jwk_params,
            };

            let header = jsonwebtoken::Header::new(alg.to_jsonwebtoken().unwrap());

            let claims = test_util::MinimalClaims::default()
                .with_audience(*test_util::TEST_AUD)
                .with_future_expiration(60 * 5);

            let encoded = jwk.sign(&header, &claims)?;

            dbg!(&encoded);

            let dec_head = jsonwebtoken::decode_header(&encoded)?;

            dbg!(&dec_head);

            let validator = BasicValidation::default()
                .add_approved_algorithm(alg)
                .add_allowed_audience(test_util::TEST_AUD.to_owned());

            let claims: test_util::MinimalClaims = jwk.verify_token(&encoded, &validator)?;
            dbg!(claims);

            Ok(())
        }
    }
}
