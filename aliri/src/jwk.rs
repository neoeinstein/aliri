//! Implementations of the JSON Web Keys (JWK) standard
//!
//! The specifications for JSON Web Keys can be found in [RFC7517][].
//!
//! [RFC7517]: https://tools.ietf.org/html/rfc7517

use std::convert::{TryFrom, TryInto};

use aliri_braid::braid;
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    error, jwa,
    jws::{self, Signer, Verifier},
};

/// An identifier for a JWK
#[braid(serde, ref_doc = "A borrowed reference to JWK identifier ([`KeyId`])")]
pub struct KeyId;

/// An identified JSON Web Key
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "JwkDto")]
#[must_use]
pub struct Jwk {
    key_id: Option<KeyId>,
    usage: Option<jwa::Usage>,
    algorithm: Option<jwa::Algorithm>,
    key: Key,
}

impl Jwk {
    /// The key ID
    #[must_use]
    pub fn key_id(&self) -> Option<&KeyIdRef> {
        self.key_id.as_deref()
    }

    /// The intended usage of the key
    #[must_use]
    pub fn usage(&self) -> Option<jwa::Usage> {
        self.usage
    }

    /// The algorithm to be used with this JWK
    #[must_use]
    pub fn algorithm(&self) -> Option<jwa::Algorithm> {
        self.algorithm
    }

    /// Whether the key is compatible with the given algorithm
    #[must_use]
    pub fn is_compatible(&self, alg: jwa::Algorithm) -> bool {
        self.key.is_compatible(alg)
    }

    /// Sets the key ID
    pub fn with_key_id(self, kid: KeyId) -> Self {
        Self {
            key_id: Some(kid),
            ..self
        }
    }

    /// Sets the key's usage
    pub fn with_usage(self, usage: jwa::Usage) -> Self {
        Self {
            usage: Some(usage),
            ..self
        }
    }

    /// Sets the algorithm and usage consistent with that algorithm
    pub fn with_algorithm(self, alg: impl Into<jwa::Algorithm>) -> Self {
        let alg = alg.into();
        Self {
            algorithm: Some(alg),
            usage: Some(alg.to_usage()),
            ..self
        }
    }

    /// Strips any private key components
    pub fn public_only(self) -> Self {
        Self {
            key: self.key.public_only(),
            ..self
        }
    }
}

#[cfg(feature = "hmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "hmac")))]
impl From<jwa::Hmac> for Jwk {
    fn from(key: jwa::Hmac) -> Self {
        Self {
            key_id: None,
            usage: None,
            algorithm: None,
            key: Key::from(key),
        }
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl From<jwa::Rsa> for Jwk {
    fn from(key: jwa::Rsa) -> Self {
        Self {
            key_id: None,
            usage: None,
            algorithm: None,
            key: Key::from(key),
        }
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl From<jwa::rsa::PublicKey> for Jwk {
    fn from(key: jwa::rsa::PublicKey) -> Self {
        Self {
            key_id: None,
            usage: None,
            algorithm: None,
            key: Key::from(key),
        }
    }
}

#[cfg(all(feature = "rsa", feature = "private-keys"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "hmac", feature = "private-keys"))))]
impl From<jwa::rsa::PrivateKey> for Jwk {
    fn from(key: jwa::rsa::PrivateKey) -> Self {
        Self {
            key_id: None,
            usage: None,
            algorithm: None,
            key: Key::from(key),
        }
    }
}

#[cfg(feature = "ec")]
#[cfg_attr(docsrs, doc(cfg(feature = "ec")))]
impl From<jwa::EllipticCurve> for Jwk {
    fn from(key: jwa::EllipticCurve) -> Self {
        Self {
            key_id: None,
            usage: None,
            algorithm: None,
            key: Key::from(key),
        }
    }
}

#[cfg(feature = "ec")]
#[cfg_attr(docsrs, doc(cfg(feature = "ec")))]
impl From<jwa::ec::PublicKey> for Jwk {
    fn from(key: jwa::ec::PublicKey) -> Self {
        Self {
            key_id: None,
            usage: None,
            algorithm: None,
            key: Key::from(key),
        }
    }
}

#[cfg(all(feature = "ec", feature = "private-keys"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "hmac", feature = "private-keys"))))]
impl From<jwa::ec::PrivateKey> for Jwk {
    fn from(key: jwa::ec::PrivateKey) -> Self {
        Self {
            key_id: None,
            usage: None,
            algorithm: None,
            key: Key::from(key),
        }
    }
}

impl Verifier for Jwk {
    type Algorithm = jwa::Algorithm;
    type Error = error::JwkVerifyError;

    fn can_verify(&self, alg: Self::Algorithm) -> bool {
        if let Ok(alg) = jws::Algorithm::try_from(alg) {
            self.key.can_verify(alg)
        } else {
            false
        }
    }

    fn verify(
        &self,
        alg: Self::Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        if alg.to_usage() != jwa::Usage::Signing {
            return Err(error::jwk_usage_mismatch().into());
        }

        if let Some(u) = self.usage {
            if u != jwa::Usage::Signing {
                return Err(error::jwk_usage_mismatch().into());
            }
        }

        match self.algorithm {
            Some(key_alg) if key_alg == alg => {}
            Some(_) => {
                return Err(error::incompatible_algorithm(alg).into());
            }
            None => {}
        }

        let alg = jws::Algorithm::try_from(alg)?;
        self.key.verify(alg, data, signature)?;

        Ok(())
    }
}

impl Signer for Jwk {
    type Algorithm = jwa::Algorithm;
    type Error = error::SigningError;

    fn can_sign(&self, alg: Self::Algorithm) -> bool {
        if let Ok(alg) = jws::Algorithm::try_from(alg) {
            self.key.can_sign(alg)
        } else {
            false
        }
    }

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        if alg.to_usage() != jwa::Usage::Signing {
            return Err(error::jwk_usage_mismatch().into());
        }

        if let Some(u) = self.usage {
            if u != jwa::Usage::Signing {
                return Err(error::jwk_usage_mismatch().into());
            }
        }

        match self.algorithm {
            Some(key_alg) if key_alg == alg => {}
            Some(_) => {
                return Err(error::incompatible_algorithm(alg).into());
            }
            None => {}
        }

        let alg = jws::Algorithm::try_from(alg)?;

        self.key.sign(alg, data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JwkDto {
    #[serde(rename = "kid", default, skip_serializing_if = "Option::is_none")]
    key_id: Option<KeyId>,

    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    usage: Option<jwa::Usage>,

    #[serde(rename = "alg", default, skip_serializing_if = "Option::is_none")]
    algorithm: Option<jwa::Algorithm>,

    #[serde(flatten)]
    key: Key,
}

impl TryFrom<JwkDto> for Jwk {
    type Error = error::IncompatibleAlgorithm;

    fn try_from(dto: JwkDto) -> Result<Self, Self::Error> {
        if let Some(alg) = &dto.algorithm {
            if !dto.key.is_compatible(*alg) {
                return Err(error::incompatible_algorithm(*alg));
            }
        }

        Ok(Self {
            key_id: dto.key_id,
            usage: dto.usage,
            algorithm: dto.algorithm,
            key: dto.key,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct JwkDtoRef<'a> {
    #[serde(rename = "kid")]
    key_id: Option<&'a KeyIdRef>,

    #[serde(rename = "use")]
    usage: Option<jwa::Usage>,

    #[serde(rename = "alg")]
    algorithm: Option<jwa::Algorithm>,

    #[serde(flatten)]
    key: &'a Key,
}

impl Serialize for Jwk {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let dto = JwkDtoRef {
            key_id: self.key_id(),
            usage: self.usage(),
            algorithm: self.algorithm(),
            key: &self.key,
        };

        dto.serialize(serializer)
    }
}

/// A JSON Web Key
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kty")]
enum Key {
    /// RSA
    #[cfg(feature = "rsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
    #[serde(rename = "RSA")]
    Rsa(jwa::rsa::Rsa),

    /// Elliptic curve cryptography
    #[cfg(feature = "ec")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ec")))]
    #[serde(rename = "EC")]
    EllipticCurve(jwa::ec::EllipticCurve),

    /// HMAC symmetric
    #[cfg(feature = "hmac")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hmac")))]
    #[serde(rename = "oct")]
    Hmac(jwa::Hmac),
}

impl Key {
    fn is_compatible(&self, alg: jwa::Algorithm) -> bool {
        match alg {
            jwa::Algorithm::Signing(alg) => self.can_verify(alg),
        }
    }

    fn public_only(self) -> Self {
        match self {
            #[cfg(feature = "rsa")]
            Self::Rsa(k) => Self::Rsa(k.public_only()),

            #[cfg(feature = "ec")]
            Self::EllipticCurve(k) => Self::EllipticCurve(k.public_only()),

            #[cfg(feature = "hmac")]
            Self::Hmac(_) => self,
        }
    }
}

#[cfg(feature = "hmac")]
#[cfg_attr(docsrs, doc(cfg(feature = "hmac")))]
impl From<jwa::Hmac> for Key {
    fn from(key: jwa::Hmac) -> Self {
        Self::Hmac(key)
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl From<jwa::Rsa> for Key {
    fn from(key: jwa::Rsa) -> Self {
        Self::Rsa(key)
    }
}

#[cfg(feature = "rsa")]
#[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
impl From<jwa::rsa::PublicKey> for Key {
    fn from(key: jwa::rsa::PublicKey) -> Self {
        Self::Rsa(key.into())
    }
}

#[cfg(all(feature = "rsa", feature = "private-keys"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "rsa", feature = "private-keys"))))]
impl From<jwa::rsa::PrivateKey> for Key {
    fn from(key: jwa::rsa::PrivateKey) -> Self {
        Self::Rsa(key.into())
    }
}

#[cfg(feature = "ec")]
#[cfg_attr(docsrs, doc(cfg(feature = "ec")))]
impl From<jwa::EllipticCurve> for Key {
    fn from(key: jwa::EllipticCurve) -> Self {
        Self::EllipticCurve(key)
    }
}

#[cfg(feature = "ec")]
#[cfg_attr(docsrs, doc(cfg(feature = "ec")))]
impl From<jwa::ec::PublicKey> for Key {
    fn from(key: jwa::ec::PublicKey) -> Self {
        Self::EllipticCurve(key.into())
    }
}

#[cfg(all(feature = "ec", feature = "private-keys"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "ec", feature = "private-keys"))))]
impl From<jwa::ec::PrivateKey> for Key {
    fn from(key: jwa::ec::PrivateKey) -> Self {
        Self::EllipticCurve(key.into())
    }
}

impl Verifier for Key {
    type Algorithm = jws::Algorithm;
    type Error = error::JwkVerifyError;

    fn can_verify(&self, alg: Self::Algorithm) -> bool {
        match self {
            #[cfg(feature = "rsa")]
            Self::Rsa(p) => {
                if let Ok(alg) = alg.try_into() {
                    p.can_verify(alg)
                } else {
                    false
                }
            }
            #[cfg(feature = "hmac")]
            Self::Hmac(p) => {
                if let Ok(alg) = alg.try_into() {
                    p.can_verify(alg)
                } else {
                    false
                }
            }
            #[cfg(feature = "ec")]
            Self::EllipticCurve(p) => {
                if let Ok(alg) = alg.try_into() {
                    p.can_verify(alg)
                } else {
                    false
                }
            }

            #[cfg(not(any(feature = "hmac", feature = "rsa", feature = "ec")))]
            _ => unreachable!(),
        }
    }

    fn verify(
        &self,
        alg: Self::Algorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        match self {
            #[cfg(feature = "hmac")]
            Self::Hmac(p) => p.verify(alg.try_into()?, data, signature)?,

            #[cfg(feature = "rsa")]
            Self::Rsa(p) => p.verify(alg.try_into()?, data, signature)?,

            #[cfg(feature = "ec")]
            Self::EllipticCurve(p) => p.verify(alg.try_into()?, data, signature)?,

            #[cfg(not(any(feature = "hmac", feature = "rsa", feature = "ec")))]
            _ => unreachable!(),
        }

        Ok(())
    }
}

impl Signer for Key {
    type Algorithm = jws::Algorithm;
    type Error = error::SigningError;

    fn can_sign(&self, alg: Self::Algorithm) -> bool {
        match self {
            #[cfg(feature = "rsa")]
            Self::Rsa(p) => {
                if let Ok(alg) = alg.try_into() {
                    p.can_sign(alg)
                } else {
                    false
                }
            }
            #[cfg(feature = "hmac")]
            Self::Hmac(p) => {
                if let Ok(alg) = alg.try_into() {
                    p.can_sign(alg)
                } else {
                    false
                }
            }
            #[cfg(feature = "ec")]
            Self::EllipticCurve(p) => {
                if let Ok(alg) = alg.try_into() {
                    p.can_sign(alg)
                } else {
                    false
                }
            }

            #[cfg(not(any(feature = "hmac", feature = "rsa", feature = "ec")))]
            _ => unreachable!(),
        }
    }

    fn sign(&self, alg: Self::Algorithm, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signature = match self {
            #[cfg(feature = "hmac")]
            Self::Hmac(p) => p.sign(alg.try_into()?, data)?,

            #[cfg(feature = "rsa")]
            Self::Rsa(p) => p.sign(alg.try_into()?, data)?,

            #[cfg(feature = "ec")]
            Self::EllipticCurve(p) => p.sign(alg.try_into()?, data)?,

            #[cfg(not(any(feature = "hmac", feature = "rsa", feature = "ec")))]
            _ => unreachable!(),
        };

        Ok(signature)
    }
}

#[cfg(test)]
#[cfg(any(feature = "ec", feature = "rsa", feature = "hmac"))]
mod tests {
    use aliri_base64::Base64Url;
    use color_eyre::Result;

    use super::*;

    mod serialization {
        use super::*;

        #[cfg(feature = "ec")]
        mod ec {
            use super::*;
            use crate::test::ec::*;

            #[test]
            fn deserialize_p256() -> Result<()> {
                let key: Jwk = serde_json::from_str(JWK_P256)?;
                assert_eq!(key.algorithm, Some(jwa::Algorithm::ES256));
                Ok(())
            }

            #[test]
            fn deserialize_p256_minimal() -> Result<()> {
                let key: Jwk = serde_json::from_str(JWK_P256_MINIMAL)?;
                assert_eq!(key.algorithm, None);
                Ok(())
            }

            #[test]
            fn deserialize_p384() -> Result<()> {
                let key: Jwk = serde_json::from_str(JWK_P384)?;
                assert_eq!(key.algorithm, Some(jwa::Algorithm::ES384));
                Ok(())
            }

            #[test]
            fn deserialize_p384_minimal() -> Result<()> {
                let key: Jwk = serde_json::from_str(JWK_P384_MINIMAL)?;
                assert_eq!(key.algorithm, None);
                Ok(())
            }
            #[test]
            fn deserialize_p521() -> Result<()> {
                let key: Jwk = serde_json::from_str(JWK_P521)?;
                assert_eq!(key.algorithm, Some(jwa::Algorithm::ES512));
                Ok(())
            }

            #[test]
            fn deserialize_p521_minimal() -> Result<()> {
                let key: Jwk = serde_json::from_str(JWK_P521_MINIMAL)?;
                assert_eq!(key.algorithm, None);
                Ok(())
            }
        }

        #[cfg(feature = "hmac")]
        mod hmac {
            use super::*;
            use crate::test::hmac::*;

            #[test]
            fn deserialize() -> Result<()> {
                let key: Jwk = serde_json::from_str(JWK)?;
                assert_eq!(key.algorithm, Some(jwa::Algorithm::HS256));
                Ok(())
            }

            #[test]
            fn deserialize_minimal() -> Result<()> {
                let key: Jwk = serde_json::from_str(JWK_MINIMAL)?;
                assert_eq!(key.algorithm, None);
                Ok(())
            }
        }

        #[cfg(feature = "rsa")]
        mod rsa {
            use super::*;
            use crate::test::rsa::*;

            #[test]
            fn deserialize() -> Result<()> {
                let key: Jwk = serde_json::from_str(JWK)?;
                assert_eq!(key.algorithm, Some(jwa::Algorithm::RS256));
                Ok(())
            }

            #[test]
            fn deserialize_minimal() -> Result<()> {
                let key: Jwk = serde_json::from_str(JWK_MINIMAL)?;
                assert_eq!(key.algorithm, None);
                Ok(())
            }
        }
    }

    mod verification {
        use super::*;

        fn verify(
            jwk_str: &str,
            alg: jwa::Algorithm,
            message: &str,
            signature: &str,
        ) -> Result<(), error::JwkVerifyError> {
            let key: Jwk = serde_json::from_str(jwk_str).unwrap();
            key.verify(
                alg,
                message.as_bytes(),
                Base64Url::from_encoded(signature).unwrap().as_slice(),
            )?;
            Ok(())
        }

        #[cfg(feature = "ec")]
        mod ec {
            use super::*;
            use crate::test::ec::*;

            #[test]
            #[cfg(feature = "rsa")]
            fn error_verifying_rsa_alg() {
                let err =
                    dbg!(verify(JWK_P256_MINIMAL, jwa::Algorithm::RS512, "", "")).unwrap_err();
                assert!(err.is_incompatible_alg());
            }

            #[test]
            #[cfg(feature = "hmac")]
            fn error_verifying_hmac_alg() {
                let err =
                    dbg!(verify(JWK_P256_MINIMAL, jwa::Algorithm::HS512, "", "")).unwrap_err();
                assert!(err.is_incompatible_alg());
            }

            #[test]
            fn error_using_encryption_key_for_signing() {
                let key = Jwk {
                    key_id: None,
                    usage: Some(jwa::Usage::Encryption),
                    algorithm: None,
                    key: Key::from(jwa::ec::PublicKey::from_public_point(
                        jwa::ec::Curve::P256,
                        Base64Url::from_raw(Vec::new()),
                    )),
                };

                let err = dbg!(key.verify(jwa::Algorithm::ES256, &[], &[])).unwrap_err();

                assert!(err.is_usage_mismatch());
            }

            #[test]
            fn error_using_wrong_alg_for_curve() {
                let key = Jwk {
                    key_id: None,
                    usage: Some(jwa::Usage::Signing),
                    algorithm: None,
                    key: Key::from(jwa::ec::PublicKey::from_public_point(
                        jwa::ec::Curve::P256,
                        Base64Url::from_raw(Vec::new()),
                    )),
                };

                let err = dbg!(key.verify(jwa::Algorithm::ES384, &[], &[])).unwrap_err();

                assert!(err.is_signature_mismatch());
            }

            #[test]
            fn verify_es256() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "Ik88qxDAOSKFCzoYQH1lTZc3c1bDowlF8sNS6YvrEu2scqrm_srfevlb92sMLGVrDwoVZ1XdSfhpX7aHwV5IZQ";
                verify(JWK_P256_MINIMAL, jwa::Algorithm::ES256, MESSAGE, SIGNATURE)
            }

            #[test]
            fn verify_es384() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "BJHIEUxnFekY6Ejtpb8nWjiz5uEv-9jC6n38tPGYAtZDAbVA22W9tU7oBySY5xwWTTVAGA68TRaS2zCf5BDSyQiTEx27VkzZgi1R_u8WbcS3wZTdQt0dI25-yQIs29FJ";
                verify(JWK_P384_MINIMAL, jwa::Algorithm::ES384, MESSAGE, SIGNATURE)
            }

            #[test]
            #[ignore = "ring does not yet support EC curve P-521"]
            fn verify_es512() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "ACjYr8OBDyVY3ddet_08iTcQo-QQCn8FVyp5zcRvgfO2w76zka80ud77P9f4SO8VFe-LAoNhY2EmiRWzQKCcjmVGAXSsZeI8U27rqznidDeWI8KSs1y3tb2JQc8eS41PKSb1_qdfhmLhe8NIliWNdkN9nRhA9zSsunBUjEaEnKrVgKt1";
                verify(JWK_P521_MINIMAL, jwa::Algorithm::ES512, MESSAGE, SIGNATURE)
            }
        }

        #[cfg(feature = "rsa")]
        mod rsa {
            use super::*;
            use crate::test::rsa::*;

            #[test]
            #[cfg(feature = "ec")]
            fn error_verifying_ec_alg() {
                let err = dbg!(verify(JWK_MINIMAL, jwa::Algorithm::ES512, "", "")).unwrap_err();
                assert!(err.is_incompatible_alg());
            }

            #[test]
            #[cfg(feature = "hmac")]
            fn error_verifying_hmac_alg() {
                let err = dbg!(verify(JWK_MINIMAL, jwa::Algorithm::HS512, "", "")).unwrap_err();
                assert!(err.is_incompatible_alg());
            }

            #[test]
            fn error_using_encryption_key_for_signing() {
                let key = Jwk {
                    key_id: None,
                    usage: Some(jwa::Usage::Encryption),
                    algorithm: None,
                    key: Key::Rsa(
                        jwa::Rsa::from_public_components(
                            Base64Url::from_raw(vec![0; 256]),
                            Base64Url::from_raw(Vec::new()),
                        )
                        .unwrap(),
                    ),
                };

                let err = dbg!(key.verify(jwa::Algorithm::RS256, &[], &[])).unwrap_err();

                assert!(err.is_usage_mismatch());
            }

            #[test]
            fn verify_rs256() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "ZP_JL_YAsEAuPZnBiySGjuCR5PyCOrzk7FtzE5RPSB_0FSQxzWYDdJDRmOH0saoK3wAYDLe2IxI-FOpBr5Rc3NWEpy7NFeKx51uBT1IG75KJIvNDQKd9U9Y6qmSu5fb_YrC_83GPrIeRotbtSWArMcPGGOFSDj8tSbaNtlab1SMzKnBW6OWIR6PgLXHAh_8jTmWryjY8_CVlOjJX7q6tx45Mg3nar4WsK-PluhNCgaOYeiHq7rzgOXoK2WCBSDDvLV2CGUxXzZHFXExQojX76fF3uHRiTtEWfex38iqKulozlUTRPnWbArNEUiUmo95y9nOBqmJl-ww1rnG0lnI4TQ";
                verify(JWK_MINIMAL, jwa::Algorithm::RS256, MESSAGE, SIGNATURE)
            }

            #[test]
            fn verify_rs384() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "AUbGb16c5_3AqvB_EHcIh7Uf03BFw8INwMMvdclqbiRPwt36fWabogrjfXDqX2BaJ8xH37-Cuc3mFP_1jztToivl-bXSXo_EoT4Zca5eIpLC4hvV2LMt51FOOo6HQrvsQL9-KOqrMWWvWmF9NxhIVHWTmOuH8ssIOB2zyiBeovVvssB-4nURzAHdkLa8_NnqRlgmae17yQaXNIboC0DpTf6ohy3sp7hX9qNleGbYsm3XpP0KPVCUUlFzQJLIMfgsux54QkYK4KQjZc9vvYUCRG3SNHxackYGJPzHEXgfNPxDWZK-B6_7CBD83w9_aKNtil91zyfFgVz3epLK2kiJTg";
                verify(JWK_MINIMAL, jwa::Algorithm::RS384, MESSAGE, SIGNATURE)
            }

            #[test]
            fn verify_rs512() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "vRKqN1VIdmwncziJ-kY1Mbq0-nSpQRFeQBtxm4U3RodZgaWmB_jqT6g5sdHnpVOq9KPnC180fqYIl-7ubHs3v0tzz1EWe9AmmDEUsAnQhY5-F0-Fk9NBTni8YWPNbjx9xLxYetWox8OMj0ySUiTwjIXlIlgD9FhW8wScYXGdvsFL9dCZXb448hEuUPmS9JgWG2JZayy48Xjk_AtVeFF68Y8HYGplLY3oT1KStmQm3PwpXTuVRFE9KMlwljRELP-CJFCGzy1Y_OgQbWMYMRwjnDFwtGgfpb9-Ie2qPo713SP8E-Y5CYN8ds0sXZXyoDk07n9DdLM_z143d8U6e2dRHA";
                verify(JWK_MINIMAL, jwa::Algorithm::RS512, MESSAGE, SIGNATURE)
            }

            #[test]
            fn verify_ps256() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "w3-lODLNVy6KJfuqlw62pDbHa7-Bfa7mulH0HDsJ02l3Zhbfo1sbxGugPRh_f1Qy3JVxsyEq6ymifOuHYh_rLzHDeph2SrdnPLJX2gyv38B-Igb8ugZN4zL9GleO3qAMdGvyobgUq40CVyMuQN5dYFUC3Ezl1WoS2HaDBfZghBLgyV0RSwEnxmWe46COAbjVr_E00Isg5oS-YcjrNJHvYsuOcy40dRGZ6yeP5rrdWtBU-sWgAC8ISfmY74XPUjBJEai0QmJ9AZ1zTdGvZezPtZ9poy65buuQEpWFGlQEYKojuClZGfLXFfbyWI4tagU5JBjMJFxFQFw3iCsEsISv2w";
                verify(JWK_MINIMAL, jwa::Algorithm::PS256, MESSAGE, SIGNATURE)
            }

            #[test]
            fn verify_ps384() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "HJnbeOXlNAC5nsjQKXyDNkwy9tj_-MUv_fc1zwNluxepsB0OLqf-_SKRpKZD2Z2QAZwnz8jxtnrZh0-jsY5rmIGLDrDcoGN5pDo8_1TEpoRAK8Km4YhtDjmKx36nxLMRGwl2IMvO6_aWQb3iYpsN14MqK6aIt6suCLFiHstan-YCPjceOM70isIuHN26IVwiZFmtY4B31ODfzYGh20WVeEfPNJD10kiP-TEe4F0dPhaJ_c_W2wW3cUeEF4CTMMy16e35As6b2zgZb8bUKPh7XR7JXQO4FDA-YZBLdfgI7lHM4_s_PkkgWB3EmxAXXEsqKEP8M_XxlvyoAgjx891UPA";
                verify(JWK_MINIMAL, jwa::Algorithm::PS384, MESSAGE, SIGNATURE)
            }

            #[test]
            fn verify_ps512() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "wS1Z3BuwU8ZjnRY4yH9V7RBR8QAqG5o9WYjL68SFROkfyQGDICLsops6_Kl6oHrsxKStYYIU2RxOnjBJOTykJDXbzCNMgD3oT9s6mDMuWhkA-1BwDdgHJXplxFJSqpDdypxNcH0zCe_-8Xgz2sV7RW_Vz3fWacWinucegTRkMWds8_oMIBz2Y85lF8ZRvLSIbKYIfJX5aZjlWEayKKrOLEoXCBcHo4sA9h2oqw_vuwW3aV8S_8p0BcxBw_bFmiMek4yWgYy1BX-iAIKq5GiweDG-42JxANj79KJxuC9kajmxewlOMmHyND_gahKBc7AxwMZBjjS-rCyEf3EpPqGyCQ";
                verify(JWK_MINIMAL, jwa::Algorithm::PS512, MESSAGE, SIGNATURE)
            }
        }

        #[cfg(feature = "hmac")]
        mod hmac {
            use super::*;
            use crate::test::hmac::*;

            #[test]
            #[cfg(feature = "ec")]
            fn error_verifying_ec_alg() {
                let err = dbg!(verify(JWK_MINIMAL, jwa::Algorithm::ES512, "", "")).unwrap_err();
                assert!(err.is_incompatible_alg());
            }

            #[test]
            #[cfg(feature = "rsa")]
            fn error_verifying_rsa_alg() {
                let err = dbg!(verify(JWK_MINIMAL, jwa::Algorithm::RS512, "", "")).unwrap_err();
                assert!(err.is_incompatible_alg());
            }

            #[test]
            fn error_using_encryption_key_for_signing() {
                let key = Jwk {
                    key_id: None,
                    usage: Some(jwa::Usage::Encryption),
                    algorithm: None,
                    key: Key::Hmac(jwa::Hmac::new(Vec::new())),
                };

                let err = dbg!(key.verify(jwa::Algorithm::HS256, &[], &[])).unwrap_err();

                assert!(err.is_usage_mismatch());
            }

            #[test]
            fn verify_hs256() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "ZpRznY5wlc4XePyGCIBsDiDB6V5Io5ISEbJ4kplAAiw";
                verify(JWK_MINIMAL, jwa::Algorithm::HS256, MESSAGE, SIGNATURE)
            }

            #[test]
            fn verify_hs384() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str =
                    "be1yHATZaVG7CKNFIlod3ACqmMcqlSiNizytddhcSW65KopwGI7ZaSqkPEhSL6xh";
                verify(JWK_MINIMAL, jwa::Algorithm::HS384, MESSAGE, SIGNATURE)
            }

            #[test]
            fn verify_hs512() -> Result<(), error::JwkVerifyError> {
                const MESSAGE: &str = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6IkVrS2h5UHF0ZCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
                const SIGNATURE: &str = "WG8bVidGDLmvELNYw9MCXjme3er74L8i9PJ8a8X7lmYu0QHqpiY90glVmI9OAJJJvymL0U_Dc61AyyMjO9iqVA";
                verify(JWK_MINIMAL, jwa::Algorithm::HS512, MESSAGE, SIGNATURE)
            }
        }
    }
}

// #[cfg(test)]
// #[cfg(any(feature = "ec", feature = "rsa", feature = "hmac"))]
// mod tests {
//     use super::*;

//     mod serialization {
//         use crate::test;

//         use super::*;

//         #[cfg(feature = "ec")]
//         mod ec {
//             use super::*;

//             #[test]
//             #[ignore]
//             #[cfg(feature = "private-keys")]
//             fn generate() {
//                 let p256 = jwa::EllipticCurve::generate(jwa::ec::Curve::P256).unwrap();
//                 println!("ES256: {}", serde_json::to_string_pretty(&p256).unwrap());
//                 println!("ES256 (pub):\n{}", p256.public_key().to_pem());
//                 println!("ES256 (prv):\n{}", p256.private_key().unwrap().pkcs8());

//                 let p384 = jwa::EllipticCurve::generate(jwa::ec::Curve::P384).unwrap();
//                 println!("ES384: {}", serde_json::to_string_pretty(&p384).unwrap());
//                 println!("ES384 (pub):\n{}", p384.public_key().to_pem());
//                 println!("ES384 (prv):\n{}", p384.private_key().unwrap().pkcs8());

//                 let p521 = jwa::EllipticCurve::generate(jwa::ec::Curve::P521).unwrap();
//                 println!("ES512: {}", serde_json::to_string_pretty(&p521).unwrap());
//                 println!("ES512 (pub):\n{}", p521.public_key().to_pem());
//                 println!("ES512 (prv):\n{}", p521.private_key().unwrap().pkcs8());

//                 panic!("Done!");
//             }

//             mod public {
//                 use super::*;

//                 #[test]
//                 fn deserialize_p256() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P256)?;
//                     assert_eq!(key.algorithm, Some(jws::Algorithm::ES256));
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_p256_minimal() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P256_MINIMAL)?;
//                     assert_eq!(key.algorithm, None);
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_p384() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P384)?;
//                     assert_eq!(key.algorithm, Some(jws::Algorithm::ES384));
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_p384_minimal() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P384_MINIMAL)?;
//                     assert_eq!(key.algorithm, None);
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_p521() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P521)?;
//                     assert_eq!(key.algorithm, Some(jws::Algorithm::ES512));
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_p521_minimal() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P521_MINIMAL)?;
//                     assert_eq!(key.algorithm, None);
//                     Ok(())
//                 }
//             }

//             #[cfg(feature = "private-keys")]
//             mod private {
//                 use super::*;

//                 #[test]
//                 fn deserialize_p256_with_private_key() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P256_WITH_PRIVATE_KEY)?;
//                     assert_eq!(key.algorithm, Some(jws::Algorithm::ES256));
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_p256_minimal_with_private_key() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P256_WITH_MINIMAL_PRIVATE_KEY)?;
//                     assert_eq!(key.algorithm, None);
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_p384_with_private_key() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P384_WITH_PRIVATE_KEY)?;
//                     assert_eq!(key.algorithm, Some(jws::Algorithm::ES384));
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_p384_minimal_with_private_key() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P384_WITH_MINIMAL_PRIVATE_KEY)?;
//                     assert_eq!(key.algorithm, None);
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_p521_with_private_key() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P521_WITH_PRIVATE_KEY)?;
//                     assert_eq!(key.algorithm, Some(jws::Algorithm::ES512));
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_p521_minimal_with_private_key() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::ec::JWK_P521_WITH_MINIMAL_PRIVATE_KEY)?;
//                     assert_eq!(key.algorithm, None);
//                     Ok(())
//                 }
//             }
//         }

//         #[cfg(feature = "hmac")]
//         mod hmac {
//             use super::*;

//             #[test]
//             fn deserialize() -> Result<()> {
//                 let key: Jwk = serde_json::from_str(test::hmac::JWK)?;
//                 assert_eq!(key.algorithm, Some(jws::Algorithm::HS256));
//                 Ok(())
//             }

//             #[test]
//             fn deserialize_minimal() -> Result<()> {
//                 let key: Jwk = serde_json::from_str(test::hmac::JWK_MINIMAL)?;
//                 assert_eq!(key.algorithm, None);
//                 Ok(())
//             }
//         }

//         #[cfg(feature = "rsa")]
//         mod rsa {
//             use super::*;

//             mod public {
//                 use super::*;

//                 #[test]
//                 fn deserialize_with_private_key() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::rsa::JWK)?;
//                     assert_eq!(key.algorithm, Some(jws::Algorithm::RS256));
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_minimal_with_private_key() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::rsa::JWK_MINIMAL)?;
//                     assert_eq!(key.algorithm, None);
//                     Ok(())
//                 }
//             }

//             #[cfg(feature = "private-keys")]
//             mod private {
//                 use super::*;

//                 #[test]
//                 fn deserialize_with_private_key() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::rsa::JWK_WITH_PRIVATE_KEY)?;
//                     assert_eq!(key.algorithm, Some(jws::Algorithm::RS256));
//                     Ok(())
//                 }

//                 #[test]
//                 fn deserialize_minimal_with_private_key() -> Result<()> {
//                     let key: Jwk = serde_json::from_str(test::rsa::JWK_WITH_MINIMAL_PRIVATE_KEY)?;
//                     assert_eq!(key.algorithm, None);
//                     Ok(())
//                 }
//             }
//         }
//     }

//     #[cfg(feature = "private-keys")]
//     mod key_generation {
//         use crate::test;

//         use super::*;

//         #[cfg(feature = "ec")]
//         mod ec {
//             use super::*;

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_ES256() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::ES256)
//             }

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_ES384() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::ES384)
//             }
//         }

//         #[cfg(feature = "hmac")]
//         mod hmac {
//             use super::*;

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_HS256() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::HS256)
//             }

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_HS384() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::HS384)
//             }

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_HS512() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::HS512)
//             }
//         }

//         #[cfg(feature = "rsa")]
//         mod rsa {
//             use super::*;

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_RS256() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::RS256)
//             }

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_RS384() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::RS384)
//             }

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_RS512() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::RS512)
//             }

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_PS256() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::PS256)
//             }

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_PS384() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::PS384)
//             }

//             #[test]
//             #[allow(non_snake_case)]
//             fn get_and_rt_PS512() -> Result<()> {
//                 gen_and_rt(jws::Algorithm::PS512)
//             }
//         }

//         fn gen_and_rt(alg: jws::Algorithm) -> Result<()> {
//             let jwk_params = Parameters::generate(alg)?;
//             dbg!(&jwk_params);

//             let jwk = Jwk {
//                 id: None,
//                 usage: Some(jwa::Usage::Signing),
//                 algorithm: Some(alg),
//                 params: jwk_params,
//             };

//             let header = jwt::Headers::new(alg);

//             let claims = jwt::Claims::new()
//                 .with_audience(*test::TEST_AUD)
//                 .with_future_expiration(60 * 5);

//             let encoded = jwk.sign(&header, &claims)?;

//             dbg!(&encoded);

//             let validator = jwt::Validation::default()
//                 .add_approved_algorithm(alg)
//                 .add_allowed_audience(test::TEST_AUD.to_owned());

//             let data: jwt::Validated<jwt::Claims> = encoded.verify(&jwk, &validator)?;
//             dbg!(data.claims());

//             Ok(())
//         }
//     }
// }
