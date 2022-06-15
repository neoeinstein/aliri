# Changelog

This changelog is based on the format from [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- New `aliri_axum` crate introduced
- Introduce new `scope_guards!` macro to make it easy to define scope guards

### Changed

- Updated to `aliri_braid` v0.2
  - This has several minor breaking changes on braid types, but should improve ergonomics overall
- `ScopeToken` now uses small-string optimizations for tokens up to 23 characters (on 64-bit architectures)
- `ScopePolicy` and `Scope` have been optimized for single entry cases.
