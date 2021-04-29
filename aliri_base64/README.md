# Aliri Base64

<!-- markdownlint-disable MD036 -->
_Esperanto for "access"_
<!-- markdownlint-enable MD036 -->

![CI](https://github.com/neoeinstein/aliri/workflows/CI/badge.svg?branch=master&event=push)

_Aliri_ is a family of crates intended to help build access control,
particularly of web APIs, where a token is the primary means of providing
access.

## Features

The [`aliri_base64`][] crate provides some utilities for more easily working
with byte arrays and buffers that need to be serialized using Base64 encoding.
This is particularly necessary for many of the types that [`aliri`][] works with,
but may also be of use to others as well.

The underlying encoding/decoding mechanism is provided by the [`base64`][]
crate.

  [`aliri`]: https://crates.io/crates/aliri
  [`aliri_base64`]: https://crates.io/crates/aliri_base64
  [`base64`]: https://crates.io/crates/base64

### Supported encodings

`Base64` and `Base64Ref` wrap owned and borrowed byte arrays that must be
serialized in the standard Base64 encoding with padding.

`Base64Url` and `Base64UrlRef` wrap owned and borrowed byte arrays that
must be serialized in the URL-safe Base64 encoding with no padding.

Additional encodings may be added in the future, but these were the two
primary encodings required to support my base set of use cases.

## Unsafe code

_Aliri Base64_ makes use of two lines of unsafe code. This unsafe code is limited
to the functions that allow the `Base64Ref` and `Base64UrlRef` to wrap borrowed
byte slices. This reinterpretation is safe because these types are transparent
wrappers around `[u8]`, use `#[repr(transparent)]`, and thus share the exact same
representation as the underlying slice. This is currently necessary as there is
currently no way to transmute equivalent representations of dynamically sized
values in safe Rust.

For the above reason, this crate uses `#![deny(unsafe_code)]` rather than
`#![forbid(unsafe_code)]`. The only `#![allow(unsafe_code)]` in the crate can
be located in the private `b64_builder!` macro.

Note that, because `cargo-geiger` has difficulty parsing out unsafe usage from
within macros, that tool won't report these crates as "radioactive", but
probably should. _Do your due diligence._
