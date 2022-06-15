use serde::{Deserialize, Serialize};

/// The intended use for a JWA
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
pub enum Usage {
    /// The JWA is intended signing and verification
    #[serde(rename = "sig")]
    Signing,

    /// The JWA is intended for encryption
    #[serde(rename = "enc")]
    Encryption,
}
