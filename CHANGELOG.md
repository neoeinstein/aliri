# Changelog

This changelog is based on the format from [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
- `ScopePolicy` and `Scope` have been optimized for single entry cases.

### Fixes

- `Jwks` is now able to deserialize and ignore JWKs with unrecognized algorithms and uses.
