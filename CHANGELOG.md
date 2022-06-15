# Changelog

This changelog is based on the format from [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [2022-06-15]

- `aliri` to 0.6.0
- `aliri_actix` to 0.7.0
- `aliri_axum` to 0.1.0
- `aliri_base64` to 0.1.6
- `aliri_oauth2` to 0.8.0
- `aliri_reqwest` to 0.3.0
- `aliri_tokens` to 0.2.0
- `aliri_tower` to 0.2.0
- `aliri_warp` to 0.7.0

### Added

- New `aliri_axum` crate introduced
- Introduce new `scope_guards!` macro to make it easy to define scope guards
- Introduced `scope!` and `policy!` macros to make those easier to define as well
- Several examples added for `aliri_tower` and `aliri_axum`
- `aliri` crate now has an optional `tracing` feature (disabled by default)
- `Authority::spawn_refresh` spawns a task that will automatically refresh a remote JWKS as a background task

### Changed

- Updated to `aliri_braid` v0.2
  - This has several minor breaking changes on braid types, but should improve ergonomics overall
- `ScopeToken` now uses small-string optimizations for tokens up to 23 characters (on 64-bit architectures)
- `ScopePolicy` and `Scope` have been optimized for single entry cases

### Fixes

- `Jwks` is now able to deserialize and ignore JWKs with unrecognized algorithms and uses ([#11])

[#11]: https://github.com/neoeinstein/aliri/issues/11
