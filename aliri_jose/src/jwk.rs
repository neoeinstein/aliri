use aliri_macros::typed_string;
use serde::{Deserialize, Serialize};

use crate::{
    jwa, jws,
    jwt::{BasicValidation, CoreClaims, PayloadWithBasicClaims},
};

typed_string! {
    /// An identifier for a JWK
    pub struct KeyId(String);

    /// Reference to `KeyId`
    pub struct KeyIdRef(str);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    #[cfg(feature = "rsa")]
    #[serde(rename = "RSA")]
    Rsa,

    #[cfg(feature = "ec")]
    #[serde(rename = "EC")]
    EllipticCurve,

    #[cfg(feature = "hmac")]
    #[serde(rename = "oct")]
    Hmac,
}

/// An identified JSON Web Key
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(rename = "kid")]
    pub id: Option<KeyId>,

    #[serde(rename = "use")]
    pub usage: Option<Usage>,

    #[serde(rename = "alg")]
    pub algorithm: Option<jws::Algorithm>,

    #[serde(flatten)]
    pub params: Parameters,
}

#[cfg(feature = "hmac")]
lazy_static::lazy_static! {
    static ref HMAC_BLANK_CHECK: jsonwebtoken::Validation = jsonwebtoken::Validation {
        validate_exp: false,
        algorithms: vec![
            jsonwebtoken::Algorithm::HS256,
            jsonwebtoken::Algorithm::HS384,
            jsonwebtoken::Algorithm::HS512,
        ],
        ..Default::default()
    };
}

#[cfg(feature = "rsa")]
lazy_static::lazy_static! {
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
}

#[cfg(feature = "ec")]
lazy_static::lazy_static! {
    static ref EC_BLANK_CHECK: jsonwebtoken::Validation = jsonwebtoken::Validation {
        validate_exp: false,
        algorithms: vec![
            jsonwebtoken::Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384,
        ],
        ..Default::default()
    };
}

fn get_blank_check(kty: KeyType) -> &'static jsonwebtoken::Validation {
    match kty {
        #[cfg(feature = "hmac")]
        KeyType::Hmac => &*HMAC_BLANK_CHECK,

        #[cfg(feature = "rsa")]
        KeyType::Rsa => &*RSA_BLANK_CHECK,

        #[cfg(feature = "ec")]
        KeyType::EllipticCurve => &*EC_BLANK_CHECK,
    }
}

impl Jwk {
    #[doc(hidden)]
    pub fn verify_token<C: for<'de> serde::Deserialize<'de> + CoreClaims>(
        &self,
        token: &str,
        validation: &BasicValidation,
    ) -> anyhow::Result<C> {
        let decoder = self.params.verify_key();

        let blank = get_blank_check(self.params.to_key_type());

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
    Rsa(jwa::Rsa),

    #[cfg(feature = "ec")]
    #[serde(rename = "EC")]
    EllipticCurve(jwa::EllipticCurve),

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
            jws::Algorithm::HS256 => Self::generate_hmac(256),
            #[cfg(feature = "hmac")]
            jws::Algorithm::HS384 => Self::generate_hmac(384),
            #[cfg(feature = "hmac")]
            jws::Algorithm::HS512 => Self::generate_hmac(512),

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

    #[cfg(all(feature = "rsa", feature = "private-keys"))]
    pub fn generate_rsa() -> anyhow::Result<Self> {
        Ok(Parameters::Rsa(jwa::Rsa::generate()?))
    }

    #[cfg(all(feature = "ec", feature = "private-keys"))]
    pub fn generate_ec(curve: jwa::ec::Curve) -> anyhow::Result<Self> {
        Ok(Parameters::EllipticCurve(jwa::EllipticCurve::generate(
            curve,
        )?))
    }

    #[cfg(all(feature = "hmac", feature = "private-keys"))]
    pub fn generate_hmac(bits: usize) -> anyhow::Result<Self> {
        Ok(Parameters::Hmac(jwa::Hmac::generate(bits)?))
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
    pub fn to_key_type(&self) -> KeyType {
        match self {
            #[cfg(feature = "rsa")]
            Self::Rsa(_) => KeyType::Rsa,

            #[cfg(feature = "ec")]
            Self::EllipticCurve(_) => KeyType::EllipticCurve,

            #[cfg(feature = "hmac")]
            Self::Hmac(_) => KeyType::Hmac,
        }
    }

    /// Returns the RSA parameters for the public key, if the key is an RSA key.
    #[cfg(feature = "rsa")]
    pub fn as_rsa_params(&self) -> Option<&jwa::Rsa> {
        match self {
            Self::Rsa(p) => Some(&p),

            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Returns the elliptic curve parameters for the public key, if the key is an RSA key.
    #[cfg(feature = "ec")]
    pub fn as_ec_params(&self) -> Option<&jwa::EllipticCurve> {
        match self {
            Self::EllipticCurve(p) => Some(&p),

            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    #[cfg(feature = "hmac")]
    pub fn as_sym_params(&self) -> Option<&jwa::Hmac> {
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
        use crate::test;

        use super::*;

        #[cfg(feature = "ec")]
        mod ec {
            use super::*;

            mod public {
                use super::*;

                #[test]
                fn deserialize() -> anyhow::Result<()> {
                    let _key: Parameters = serde_json::from_str(test::ec::JWK_MINIMAL)?;
                    Ok(())
                }
            }

            #[cfg(feature = "private-keys")]
            mod private {
                use super::*;

                #[test]
                fn deserialize_with_private_key() -> anyhow::Result<()> {
                    let _key: Parameters =
                        serde_json::from_str(test::ec::JWK_WITH_MINIMAL_PRIVATE_KEY)?;
                    Ok(())
                }
            }
        }

        #[cfg(feature = "hmac")]
        mod hmac {
            use super::*;

            #[test]
            fn deserialize() -> anyhow::Result<()> {
                let _key: Parameters = serde_json::from_str(test::hmac::JWK_MINIMAL)?;
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
                    let _key: Parameters = serde_json::from_str(test::rsa::JWK_MINIMAL)?;
                    Ok(())
                }
            }

            #[cfg(feature = "private-keys")]
            mod private {
                use super::*;

                #[test]
                fn deserialize_with_private_key() -> anyhow::Result<()> {
                    let _key: Parameters =
                        serde_json::from_str(test::rsa::JWK_WITH_MINIMAL_PRIVATE_KEY)?;
                    Ok(())
                }
            }
        }
    }

    #[cfg(feature = "private-keys")]
    mod key_generation {
        use crate::{jws::Algorithm, test};

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

            let claims = test::MinimalClaims::default()
                .with_audience(*test::TEST_AUD)
                .with_future_expiration(60 * 5);

            let encoded = jwk.sign(&header, &claims)?;

            dbg!(&encoded);

            let dec_head = jsonwebtoken::decode_header(&encoded)?;

            dbg!(&dec_head);

            let validator = BasicValidation::default()
                .add_approved_algorithm(alg)
                .add_allowed_audience(test::TEST_AUD.to_owned());

            let claims: test::MinimalClaims = jwk.verify_token(&encoded, &validator)?;
            dbg!(claims);

            Ok(())
        }
    }
}
