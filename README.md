# Aliri

<!-- markdownlint-disable MD036 -->
_Esperanto for "access"_
<!-- markdownlint-enable MD036 -->

![Quickstart](https://github.com/neoeinstein/aliri/workflows/Core%20Build/badge.svg?branch=master&event=push)

_Aliri_ is a family of crates intended to help build access control,
particularly of web APIs, where a token is the primary means of providing
access.

## Unsafe code

_Aliri_ does make use of very limited unsafe code. This unsafe code is limited
to a single line defined in a macro that is used to generate strongly-typed
wrappers for `String`- and `str`-based values. Unsafe is necessary here for the
reference types, in order to reinterpret the `&str` as `&MyTypeRef`. This
reinterpretation is safe because the `MyTypeRef` is a wrapper around `str` with
`#[repr(transparent)]`, which means that it shares the exact same representation
as `str`.

For the above reason, my crates use `#![deny(unsafe_code)]` rather than
`#![forbid(unsafe_code)]`. The only `#![allow(unsafe_code)]` in the code base is
tucked away in the `typed_string!` macro.

I have made this choice I prefer and value _strongly-typed_ APIs over
_stringly-typed_ APIs. I believe that consumers of this library will benefit
from this choice, as it will help them to prevent silly bugs.
