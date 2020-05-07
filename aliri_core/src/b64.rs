use std::{
    borrow::Borrow,
    fmt,
    ops::{Deref, DerefMut},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A buffer of bytes that are serialized as Base64 strings in URL-safe form
///
/// Buffer can be otherwise treated as a vector of raw bytes.
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct Base64Url(Vec<u8>);

impl Base64Url {
    #[inline]
    pub const fn new(raw: Vec<u8>) -> Self {
        Self(raw)
    }

    pub fn from_encoded(enc: &str) -> Result<Self, anyhow::Error> {
        let data = base64::decode_config(enc, base64::URL_SAFE_NO_PAD)
            .map_err(|err| anyhow::anyhow!("{}", err))?;
        Ok(Self(data))
    }

    pub fn from_encoded_base64(enc: &str) -> Result<Self, anyhow::Error> {
        let data = base64::decode(enc).map_err(|err| anyhow::anyhow!("{}", err))?;
        Ok(Self(data))
    }

    #[inline]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Provides mutable access to the underlying vector
    #[inline]
    pub fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl From<Vec<u8>> for Base64Url {
    #[inline]
    fn from(raw: Vec<u8>) -> Self {
        Self::new(raw)
    }
}

impl From<&'_ [u8]> for Base64Url {
    #[inline]
    fn from(raw: &[u8]) -> Self {
        Self::new(raw.to_owned())
    }
}

impl From<Base64Url> for Vec<u8> {
    #[inline]
    fn from(wrapper: Base64Url) -> Self {
        wrapper.0
    }
}

impl AsRef<[u8]> for Base64Url {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Base64Url {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl fmt::Debug for Base64Url {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl Deref for Base64Url {
    type Target = Base64UrlRef;

    #[inline]
    fn deref(&self) -> &Base64UrlRef {
        Base64UrlRef::from_slice(self.0.as_slice())
    }
}

impl DerefMut for Base64Url {
    #[inline]
    fn deref_mut(&mut self) -> &mut Base64UrlRef {
        Base64UrlRef::from_mut_slice(self.0.as_mut_slice())
    }
}

impl Borrow<Base64UrlRef> for Base64Url {
    #[inline]
    fn borrow(&self) -> &Base64UrlRef {
        &self
    }
}

impl AsRef<Base64UrlRef> for Base64Url {
    #[inline]
    fn as_ref(&self) -> &Base64UrlRef {
        &self
    }
}

impl Serialize for Base64Url {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = base64::encode_config(&self.0, base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(encoded.as_str())
    }
}

impl<'de> Deserialize<'de> for Base64Url {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: &[u8] = Deserialize::deserialize(deserializer)?;
        let data = base64::decode_config(raw, base64::URL_SAFE_NO_PAD)
            .map_err(serde::de::Error::custom)?;
        Ok(Self(data))
    }
}

/// Reference to a `Base64Url`, serializes as string in Base64Url form
#[derive(Eq, PartialEq)]
#[repr(transparent)]
pub struct Base64UrlRef([u8]);

impl Base64UrlRef {
    /// Reinterprets the underlying slice as one that should be serialized in
    /// Base64Url form.
    #[allow(unsafe_code)]
    #[inline]
    pub fn from_slice(raw: &[u8]) -> &Self {
        // `Base64UrlRef` is a transparent wrapper around an `[u8]`, so this
        // transformation is safe to do.
        unsafe { &*(raw as *const [u8] as *const Self) }
    }

    /// Reinterprets the underlying slice as one that should be serialized in
    /// Base64Url form.
    #[allow(unsafe_code)]
    #[inline]
    pub fn from_mut_slice(raw: &mut [u8]) -> &mut Self {
        // `Base64UrlRef` is a transparent wrapper around an `[u8]`, so this
        // transformation is safe to do.
        unsafe { &mut *(raw as *mut [u8] as *mut Self) }
    }

    /// The length of the base64url encoded value of the underlying data
    #[inline]
    pub fn encoded_len(&self) -> usize {
        let len = self.as_slice().len();
        len / 3 + len % 3
    }

    /// Returns a reference to the underlying raw byte slice.
    #[inline]
    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the underlying raw byte slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<'a> From<&'a Base64UrlRef> for &'a [u8] {
    #[inline]
    fn from(s: &'a Base64UrlRef) -> Self {
        s.as_slice()
    }
}

impl<'a> From<&'a [u8]> for &'a Base64UrlRef {
    #[inline]
    fn from(s: &'a [u8]) -> Self {
        Base64UrlRef::from_slice(s)
    }
}

impl ToOwned for Base64UrlRef {
    type Owned = Base64Url;

    #[inline]
    fn to_owned(&self) -> Self::Owned {
        Base64Url::new(self.0.to_owned())
    }
}

impl PartialEq<Base64UrlRef> for Base64Url {
    #[inline]
    fn eq(&self, other: &Base64UrlRef) -> bool {
        self.0 == &other.0
    }
}

impl PartialEq<Base64Url> for Base64UrlRef {
    #[inline]
    fn eq(&self, other: &Base64Url) -> bool {
        other.0 == &self.0
    }
}

impl fmt::Display for Base64UrlRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded = base64::encode_config(&self.0, base64::URL_SAFE_NO_PAD);
        f.write_str(&encoded)
    }
}

impl fmt::Debug for Base64UrlRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded = base64::encode_config(&self.0, base64::URL_SAFE_NO_PAD);
        write!(f, "`{}`", encoded)
    }
}

impl Serialize for Base64UrlRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = base64::encode_config(&self.0, base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(encoded.as_str())
    }
}
