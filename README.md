# Aliri

<!-- markdownlint-disable MD036 -->
_Esperanto for "access"_
<!-- markdownlint-enable MD036 -->

![CI](https://github.com/neoeinstein/aliri/workflows/CI/badge.svg?branch=master&event=push)

_Aliri_ is a family of crates intended to help build access control,
particularly of web APIs, where a token is the primary means of providing
access.

## Unsafe code

_Aliri_ does make use of very limited unsafe code. This unsafe code is limited
to a single function defined in macros that is used to generate strongly-typed
wrappers for `String` and `Vec<u8>` values. Unsafe is necessary here for the
reference types, in order to reinterpret the `&str` as `&MyTypeRef` or `&[u8]`
as `&Base64Ref`. This reinterpretation is safe because the wrappers around `str`
use `#[repr(transparent)]`, which means that the wrappers share the exact same
representation as the underlying slice.

For the above reason, my crates use `#![deny(unsafe_code)]` rather than
`#![forbid(unsafe_code)]`. The only `#![allow(unsafe_code)]` in the code base is
tucked away in the `typed_string!` and `b64_builder!` macros.

I have made this choice I prefer and value _strongly-typed_ APIs over
_stringly-typed_ APIs. I believe that consumers of this library will benefit
from this choice, as it will help them to prevent silly bugs.
