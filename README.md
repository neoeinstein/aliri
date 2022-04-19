# Aliri

<!-- markdownlint-disable MD036 -->
_Esperanto for "access"_
<!-- markdownlint-enable MD036 -->

![CI](https://github.com/neoeinstein/aliri/workflows/CI/badge.svg?branch=master&event=push)

_Aliri_ is a family of crates intended to help build access control,
particularly of web APIs, where a token is the primary means of providing
access.

## Features

The [`aliri`][] crate provides primary support for the _JavaScript/JSON
Object Signing and Encryption (JOSE)_ standard. For more information about the
RFCs relating to this standard, see the
[crate's documentation][aliri:doc].

The [`aliri_oauth2`][] crate provides some support for incorporating checks to
ensure a bearer of a token has sufficient _scopes_ to permit access. It also
provides some functionality for using a local or remote _JSON Web Key Set
(JWKS)_ as an authority to authenticate tokens. Some of this functionality maybe
broken off as part of planned _OpenID Connect (OIDC)_ functionality.

The [`aliri_actix`][] crate provides some useful bindings to create scope guards
for the [`actix-web`][] web server.

Similarly, the [`aliri_warp`][] crate provides bindings to the [`warp`][] web
server, and includes filters useful for authenticating access to endpoints.

Other crates under the `aliri` header provide supporting functionality to these
primary crates.

  [`aliri`]: https://crates.io/crates/aliri
  [aliri:doc]: https://docs.rs/aliri
  [`aliri_oauth2`]: https://crates.io/crates/aliri_oauth2
  [`aliri_actix`]: https://crates.io/crates/aliri_actix
  [`actix-web`]: https://crates.io/crates/actix-web
  [`aliri_warp`]: https://crates.io/crates/aliri_warp
  [`warp`]: https://crates.io/crates/warp

### _JSON Web Signature (JWS)_ operations

Supported algorithms

Feature `hmac`:

* HS256, HS384, HS512

Feature `rsa`:

* RS256, RS384, RS512
* PS256, PS384, PS512

Feature `ec`:

* ES256, ES384

Note: `none` is explicitly not supported by this library due to the security
holes that algorithm raises when improperly accepted.

Support for private keys, to allow for signing operations and to generate new
keys, is provided by the `private-keys` feature.

Due to limitations in the ability to import and export generated keys in the
required JWK form, `openssl` is used to extract or handle the required
parameters. In addition, `ring` does not support RSA private keys that are
missing the `p`, `q`, `dmp1`, `dmq1`, or `iqmp` values. These parameters are
_highly recommended_ as they speed up signature calculation, but according to
the JWA specification are technically optional.

### Supported checks

* `iss` exact string match
* `aud` exact string match (list)
* `sub` regex match
* `jti` predicate function
* `nbf` against current time
* `exp` against current time
* `iat` max age check
* `alg` exact match (list)

## Future plans

* Support JWE
* Support OpenID Connect as a relying party
* Support obtaining tokens and token management

## Alternatives

This set of crates grew out of my prior use of `jsonwebtoken`, and was expanded
to fit larger goals of implementing the full JOSE suite. Further inspiration was
taken from `jsonwebtokens`, in particular the `Verifier` type.

* [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken)
* [`jsonwebtokens`](https://crates.io/crates/jsonwebtokens)
* [`frank_jwt`](https://crates.io/crates/frank_jwt)
* [`biscuit`](https://crates.io/crates/biscuit)

## Unsafe code

_Aliri_ does make use of very limited unsafe code. This unsafe code is limited
to a single function defined in macros that is used to generate strongly-typed
wrappers for `String` and `Vec<u8>` values. Unsafe is necessary here for the
reference types, in order to reinterpret the `&str` as `&MyTypeRef` or `&[u8]`
as `&Base64Ref`. This reinterpretation is safe because the wrappers around `str`
use `#[repr(transparent)]`, which means that the wrappers share the exact same
representation as the underlying slice.

For the above reason, some included crates use `#![deny(unsafe_code)]`
rather than `#![forbid(unsafe_code)]`. The only `#![allow(unsafe_code)]` in
the code base can be found in the `typed_string!` and `b64_builder!` macros.

I have made this choice because of my preference for _strongly-typed_ APIs over
_stringly-typed_ APIs. I believe that consumers of this library will benefit
from this choice, as it will help them to prevent silly bugs.

Note that, because `cargo-geiger` has difficulty parsing out unsafe usage from
within macros, that tool won't report these crates as "radioactive", but
probably should. _Do your due diligence._
