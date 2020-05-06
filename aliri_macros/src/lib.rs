#![deny(unsafe_code)]

#[macro_export]
macro_rules! typed_string {
    {
        $(#[$meta:meta])*
        $v:vis struct $ty:ident (String);

        $(#[$meta_ref:meta])*
        $v_ref:vis struct $ty_ref:ident (str);
    } => {
        #[derive(Debug, Clone, Eq, PartialEq, Hash, ::serde::Serialize, ::serde::Deserialize)]
        #[repr(transparent)]
        $(#[$meta])*
        $v struct $ty(String);

        impl $ty {
            /// Strongly types the given `String`.
            #[inline]
            pub fn new<T: Into<String>>(raw: T) -> Self {
                Self(raw.into())
            }

            /// Unwraps the underlying value.
            #[inline]
            pub fn into_inner(self) -> String {
                self.0
            }

            /// Provides access to the underlying value as a string slice.
            #[inline]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl From<String> for $ty {
            #[inline]
            fn from(kid: String) -> Self {
                Self::new(kid)
            }
        }

        impl From<&'_ str> for $ty {
            #[inline]
            fn from(kid: &str) -> Self {
                Self::new(String::from(kid))
            }
        }

        impl From<&'_ $ty_ref> for $ty {
            #[inline]
            fn from(kid: &$ty_ref) -> Self {
                $ty::from(kid.as_str())
            }
        }

        impl From<$ty> for String {
            #[inline]
            fn from(wrapper: $ty) -> Self {
                wrapper.0
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

            fn deref(&self) -> &Self::Target {
                $ty_ref::from_str(self.0.as_str())
            }
        }

        impl AsRef<$ty_ref> for $ty {
            #[inline]
            fn as_ref(&self) -> &$ty_ref {
                &self
            }
        }

        impl<'a> ::std::fmt::Display for $ty {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        #[derive(Debug, Hash, PartialEq, Eq, ::serde::Serialize)]
        #[repr(transparent)]
        $(#[$meta_ref])*
        $v_ref struct $ty_ref(str);

        impl $ty_ref {
            #[allow(unsafe_code)]
            #[inline]
            /// Transparently reinterprets the string slice as a strongly-typed
            /// value.
            pub fn from_str<'a>(raw: &'a str) -> &'a Self {
                // `$ty_ref` is a transparent wrapper around an `str`, so this
                // transformation is safe to do.
                unsafe {
                    &*(raw as *const str as *const Self)
                }
            }

            /// Provides access to the underlying value as a string slice.
            #[inline]
            pub const fn as_str(&self) -> &str {
                &self.0
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
                &self.0 == other.0
            }
        }

        impl<'a> ::std::fmt::Display for &'a $ty_ref {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de: 'a, 'a> ::serde::Deserialize<'de> for &'a $ty_ref {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = <&str as ::serde::Deserialize<'de>>::deserialize(deserializer)?;
                Ok($ty_ref::from_str(raw))
            }
        }

    }
}
