//! # aliri_base64
//!
//! Wrappers for values that should be serialized or represented as base64
//!
//! Underlying data is stored as an actual byte slice. Costs of conversions
//! between base64 and raw bytes only occur for calls to `from_encoded()` or
//! conversions to strings via debug or display formatting.
//!
//! This can make debugging byte arrays significantly less annoying,
//! as [`Debug`][std::fmt::Debug] and [`Display`][std::fmt::Display]
//! implementations are provided as better views of the underlying byte data.
//!
//! ## Example
//!
//! Using [`ToString::to_string()`][std::string::ToString::to_string()]:
//!
//! ```
//! use aliri_base64::Base64;
//!
//! let data = Base64::from_raw("👋 hello, world! 👋".as_bytes());
//! let enc = data.to_string();
//! assert_eq!(enc, "8J+RiyBoZWxsbywgd29ybGQhIPCfkYs=");
//! ```
//!
//! Using [`format!`] and [`Display`][std::fmt::Display]:
//!
//! ```
//! use aliri_base64::Base64;
//!
//! let data = Base64::from_raw("👋 hello, world! 👋".as_bytes());
//! let enc = format!("MyData: {}", data);
//! assert_eq!(enc, "MyData: 8J+RiyBoZWxsbywgd29ybGQhIPCfkYs=");
//! ```
//!
//! Using [`format!`] and [`Debug`][std::fmt::Debug]:
//!
//! Note that the output data is fenced in backticks when formatted for
//! debugging.
//!
//! ```
//! use aliri_base64::Base64;
//!
//! let data = Base64::from_raw("👋 hello, world! 👋".as_bytes());
//! let enc = format!("MyData: {:?}", data);
//! assert_eq!(enc, "MyData: `8J+RiyBoZWxsbywgd29ybGQhIPCfkYs=`");
//! ```
//!
//! Reinterpreting raw data, moving from URL encoding with no padding to
//! standard encoding with padding:
//!
//! ```
//! use aliri_base64::{Base64, Base64Url};
//!
//! let data = Base64Url::from_encoded("8J-RiyBoZWxsbywgd29ybGQhIPCfkYs").unwrap();
//! assert_eq!(data.as_slice(), "👋 hello, world! 👋".as_bytes());
//! let transcode = Base64::from_raw(data.into_inner());
//! let enc = transcode.to_string();
//! assert_eq!(enc, "8J+RiyBoZWxsbywgd29ybGQhIPCfkYs=");
//! ```
//!
//! ## Serde
//!
//! With the `serde` feature enabled, serializers and deserializers will be
//! created that will encode the underlying byte array as a base64 string
//! using the relevant encoding.

#![warn(
    missing_docs,
    unused_import_braces,
    unused_imports,
    unused_qualifications
)]
#![deny(
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_must_use
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{error::Error, fmt};

/// An error while decoding a value which is not properly formatted
/// base64 data
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidBase64Data {
    source: ::base64::DecodeError,
}

impl From<::base64::DecodeError> for InvalidBase64Data {
    fn from(err: ::base64::DecodeError) -> Self {
        Self { source: err }
    }
}

impl fmt::Display for InvalidBase64Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid base64 data")
    }
}

impl Error for InvalidBase64Data {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

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
            pub fn from_encoded<T: AsRef<[u8]>>(enc: T) -> Result<Self, InvalidBase64Data> {
                let data = ::base64::decode_config(enc, $config)?;
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

        impl From<Vec<u8>> for $ty {
            #[inline]
            fn from(buf: Vec<u8>) -> Self {
                Self(buf)
            }
        }

        impl From<&'_ [u8]> for $ty {
            #[inline]
            fn from(slice: &[u8]) -> Self {
                Self::from_raw(slice)
            }
        }

        impl<'a> From<&'a [u8]> for &'a $ty_ref {
            #[inline]
            fn from(slice: &'a [u8]) -> Self {
                $ty_ref::from_slice(slice)
            }
        }

        impl From<&'_ $ty_ref> for $ty {
            #[inline]
            fn from(val: &$ty_ref) -> Self {
                Self::from(val.as_slice())
            }
        }

        impl From<$ty> for Vec<u8> {
            #[inline]
            fn from(val: $ty) -> Self {
                val.0
            }
        }

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

        /// Serialize the underlying byte array as a base64 string
        #[cfg(any(feature = "serde", doctest, doc))]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl ::serde::Serialize for $ty {
            #[inline]
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.as_ref().serialize(serializer)
            }
        }

        /// Deserialize a base64 string and decode it into a byte array
        #[cfg(any(feature = "serde", doctest, doc))]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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

        impl ::std::fmt::Display for $ty_ref {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                let encoded = ::base64::encode_config(&self.0, $config);
                f.write_str(&encoded)
            }
        }

        impl ::std::fmt::Debug for $ty_ref {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                let encoded = ::base64::encode_config(&self.0, $config);
                write!(f, "`{}`", encoded)
            }
        }

        /// Serialize the underlying byte array as a base64 string
        #[cfg(any(feature = "serde", doctest, doc))]
        #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
        impl ::serde::Serialize for $ty_ref {
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

#[cfg(doctest)]
#[doc(hidden)]
mod doctests {
    /// Verifies that `from_slice` does not extend lifetimes
    ///
    /// ```compile_fail
    /// use aliri_base64::Base64UrlRef;
    ///
    /// let b64 = {
    ///     let data = vec![0; 16];
    ///     Base64UrlRef::from_slice(data.as_slice())
    /// };
    ///
    /// println!("{}", b64);
    /// ```
    fn base64url_from_slice_does_not_extend_lifetimes() -> ! {
        loop {}
    }

    /// Verifies that `from_mut_slice` does not extend lifetimes
    ///
    /// ```compile_fail
    /// use aliri_base64::Base64UrlRef;
    ///
    /// let b64 = {
    ///     let mut data = vec![0; 16];
    ///     Base64UrlRef::from_mut_slice(data.as_mut_slice())
    /// };
    ///
    /// println!("{}", b64);
    /// ```
    fn base64url_from_mut_slice_does_not_extend_lifetimes() -> ! {
        loop {}
    }

    /// Verifies that `from_slice` does not extend lifetimes
    ///
    /// ```compile_fail
    /// use aliri_base64::Base64Ref;
    ///
    /// let b64 = {
    ///     let data = vec![0; 16];
    ///     Base64Ref::from_slice(data.as_slice())
    /// };
    ///
    /// println!("{}", b64);
    /// ```
    fn base64_from_slice_does_not_extend_lifetimes() -> ! {
        loop {}
    }

    /// Verifies that `from_mut_slice` does not extend lifetimes
    ///
    /// ```compile_fail
    /// use aliri_base64::Base64Ref;
    ///
    /// let b64 = {
    ///     let mut data = vec![0; 16];
    ///     Base64Ref::from_mut_slice(data.as_mut_slice())
    /// };
    ///
    /// println!("{}", b64);
    /// ```
    fn base64_from_mut_slice_does_not_extend_lifetimes() -> ! {
        loop {}
    }

    /// Verifies that `serde` serialization round-trips
    ///
    /// ```
    /// use serde::{Serialize, Deserialize};
    /// use aliri_base64::Base64Url;
    ///
    /// #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    /// struct MyData {
    ///     data: Base64Url,
    /// }
    ///
    /// let data = MyData {
    ///     data: Base64Url::from_raw("👋 hello, world! 👋".to_string().into_bytes()),
    /// };
    ///
    /// let serialized = serde_json::to_string(&data).unwrap();
    ///
    /// assert_eq!(serialized, r#"{"data":"8J-RiyBoZWxsbywgd29ybGQhIPCfkYs"}"#);
    ///
    /// let deserialized: MyData = serde_json::from_str(&serialized).unwrap();
    ///
    /// assert_eq!(data, deserialized);
    /// ```
    #[cfg(feature = "serde")]
    fn base64_round_trips_through_serde() -> ! {
        loop {}
    }
}
