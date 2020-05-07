//! Wrappers for values that should be serialized or represented as base64
//!
//! ## Example
//!
//! ```
//! use aliri_core::base64::Base64;
//!
//! let data = Base64::from_raw("👋 hello, world! 👋".as_bytes());
//! let enc = data.to_string();
//! assert_eq!(enc, "8J+RiyBoZWxsbywgd29ybGQhIPCfkYs=");
//! ```
//!
//! ```
//! use aliri_core::base64::{Base64, Base64Url};
//!
//! let data = Base64Url::from_encoded("8J-RiyBoZWxsbywgd29ybGQhIPCfkYs").unwrap();
//! assert_eq!(data.as_slice(), "👋 hello, world! 👋".as_bytes());
//! let transcode = Base64::from_raw(data.into_inner());
//! let enc = transcode.to_string();
//! assert_eq!(enc, "8J+RiyBoZWxsbywgd29ybGQhIPCfkYs=");
//! ```

macro_rules! b64_builder {
    {
        $(#[$meta:meta])*
        $v:vis struct $ty:ident ($config:expr, $is_padded:expr);

        $(#[$meta_ref:meta])*
        $v_ref:vis struct $ty_ref:ident;
    } => {
        #[derive(Clone, Eq, PartialEq, Hash)]
        #[repr(transparent)]
        $(#[$meta])*
        ///
        /// Data is held in memory in its raw form. Costs of serialization
        /// are only incurred when serializing or displaying the value in
        /// its base64 representation.
        ///
        /// Data is held in memory in its raw form. Costs of converting to
        /// base64 form are only incurred when serializing or displaying the
        /// value. Cost of converting from base64 form are incurred on calling
        /// `from_encoded`.
        $v struct $ty(Vec<u8>);

        impl $ty {
            /// Creates a new buffer from an owned value
            ///
            /// To decode a base64-encoded buffer, use `from_encoded`.
            #[inline]
            pub fn from_raw<T: Into<Vec<u8>>>(raw: T) -> Self {
                Self(raw.into())
            }

            /// Constructs a new buffer from a base64-encoded slice
            pub fn from_encoded<T: AsRef<[u8]>>(enc: T) -> Result<Self, ::anyhow::Error> {
                let data = ::base64::decode_config(enc, $config)
                    .map_err(|err| anyhow::anyhow!("{}", err))?;
                Ok(Self(data))
            }

            /// Unwraps the underlying buffer
            #[inline]
            pub fn into_inner(self) -> Vec<u8> {
                self.0
            }

            /// Calculates the expected length of the base64-encoding for a buffer of size `len`
            #[inline]
            pub fn calc_encoded_len(len: usize) -> usize {
                if $is_padded {
                    (len + 2) / 3 * 4
                } else {
                    let d = len / 3 * 4;
                    let m = len % 3;
                    if m > 0 {
                        d + m + 1
                    } else {
                        d
                    }
                }
            }
        }

        // impl From<Vec<u8>> for $ty {
        //     #[inline]
        //     fn from(buf: Vec<u8>) -> Self {
        //         Self(buf)
        //     }
        // }

        // impl From<&'_ [u8]> for $ty {
        //     #[inline]
        //     fn from(slice: &[u8]) -> Self {
        //         Self::new(slice)
        //     }
        // }

        // impl From<&'_ $ty_ref> for $ty {
        //     #[inline]
        //     fn from(val: &$ty_ref) -> Self {
        //         Self::from(val.as_slice())
        //     }
        // }

        // impl From<$ty> for Vec<u8> {
        //     #[inline]
        //     fn from(val: $ty) -> Self {
        //         val.0
        //     }
        // }

        impl ::std::borrow::Borrow<$ty_ref> for $ty {
            #[inline]
            fn borrow(&self) -> &$ty_ref {
                &self
            }
        }

        impl ::std::ops::Deref for $ty {
            type Target = $ty_ref;

            #[inline]
            fn deref(&self) -> &Self::Target {
                $ty_ref::from_slice(self.0.as_slice())
            }
        }

        impl ::std::ops::DerefMut for $ty {
            #[inline]
            fn deref_mut(&mut self) -> &mut $ty_ref {
                $ty_ref::from_mut_slice(self.0.as_mut_slice())
            }
        }

        impl AsRef<$ty_ref> for $ty {
            #[inline]
            fn as_ref(&self) -> &$ty_ref {
                &self
            }
        }

        impl ::std::fmt::Display for $ty {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&**self, f)
            }
        }

        impl ::std::fmt::Debug for $ty {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::Debug::fmt(&**self, f)
            }
        }

        impl ::serde::Serialize for $ty {
            #[inline]
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.as_ref().serialize(serializer)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw: &[u8] = ::serde::Deserialize::deserialize(deserializer)?;
                let data = base64::decode_config(raw, $config)
                    .map_err(serde::de::Error::custom)?;
                Ok(Self(data))
            }
        }

        #[derive(Hash, PartialEq, Eq)]
        #[repr(transparent)]
        $(#[$meta_ref])*
        ///
        /// Data is borrowed in its raw form. Costs of converting to base64
        /// form are only incurred when serializing or displaying the value.
        $v_ref struct $ty_ref([u8]);

        impl $ty_ref {
            #[allow(unsafe_code)]
            #[inline]
            /// Transparently reinterprets the slice as base64
            pub fn from_slice(raw: &[u8]) -> &Self {
                let ptr: *const [u8] = raw;

                // This type is a transparent wrapper around an `[u8]`, so this
                // transformation is safe to do.
                unsafe {
                    &*(ptr as *const Self)
                }
            }

            #[allow(unsafe_code)]
            #[inline]
            /// Transparently reinterprets the mutable slice as base64
            pub fn from_mut_slice(raw: &mut [u8]) -> &mut Self {
                let ptr: *mut [u8] = raw;

                // This type is a transparent wrapper around an `[u8]`, so this
                // transformation is safe to do.
                unsafe {
                    &mut *(ptr as *mut Self)
                }
            }

            /// Calculates the expected length of the base64-encoding of this buffer
            #[inline]
            pub fn encoded_len(&self) -> usize {
                $ty::calc_encoded_len(self.as_slice().len())
            }

            /// Provides access to the underlying slice
            #[inline]
            pub const fn as_slice(&self) -> &[u8] {
                &self.0
            }

            /// Provides mutable access to the underlying slice
            #[inline]
            pub fn as_mut_slice(&mut self) -> &mut [u8] {
                &mut self.0
            }
        }

        impl ToOwned for $ty_ref {
            type Owned = $ty;

            #[inline]
            fn to_owned(&self) -> Self::Owned {
                $ty(self.0.to_owned())
            }
        }

        impl PartialEq<$ty_ref> for $ty {
            #[inline]
            fn eq(&self, other: &$ty_ref) -> bool {
                self.0 == &other.0
            }
        }

        impl PartialEq<$ty> for $ty_ref {
            #[inline]
            fn eq(&self, other: &$ty) -> bool {
                &self.0 == other.0.as_slice()
            }
        }

        impl<'a> ::std::fmt::Display for $ty_ref {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                let encoded = ::base64::encode_config(&self.0, $config);
                f.write_str(&encoded)
            }
        }

        impl<'a> ::std::fmt::Debug for $ty_ref {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                let encoded = ::base64::encode_config(&self.0, $config);
                write!(f, "`{}`", encoded)
            }
        }

        impl<'a> ::serde::Serialize for $ty_ref {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let encoded = ::base64::encode_config(&self.0, $config);
                serializer.serialize_str(encoded.as_str())
            }
        }

    }
}

b64_builder! {
    /// Owned data to be encoded as standard base64
    ///
    /// Encoding alphabet: `A`–`Z`, `a`–`z`, `0`–`9`, `+`, `/`
    ///
    /// Padding character: `=`
    pub struct Base64(base64::STANDARD, true);

    /// Borrowed data to be encoded as standard base64
    ///
    /// Encoding alphabet: `A`–`Z`, `a`–`z`, `0`–`9`, `+`, `/`
    ///
    /// Padding character: `=`
    pub struct Base64Ref;
}

b64_builder! {
    /// Owned data to be encoded as URL-safe base64 (no padding)
    ///
    /// Encoding alphabet: `A`–`Z`, `a`–`z`, `0`–`9`, `-`, `_`
    pub struct Base64Url(base64::URL_SAFE_NO_PAD, false);

    /// Borrowed data to be encoded as URL-safe base64 (no padding)
    ///
    /// Encoding alphabet: `A`–`Z`, `a`–`z`, `0`–`9`, `-`, `_`
    pub struct Base64UrlRef;
}
