//! Facilities for efficient background management of access tokens
//!
//! This library is intended to support some best practices for background management of
//! authentication tokens for clients such that they can make the right trade-offs with regard
//! to reliability of their own application and reliance on the backend authentication
//! system always being available to issue tokens.
//!
//! In particular, this moves considerations about whether a token needs to be refreshed to the
//! background, provides a grace period where the existing token can continue to be used while
//! attempts are made to obtain a fresher token, and contemplates a mechanism whereby multiple
//! short-lived instances (such as serverless functions) can cooperate in order to reduce the
//! need for an always-up authentication server.
//!
//! This is done in such a way that consumers of the tokens need be hardly aware that the
//! refreshes are happening in the background at all.
//!
//! # General Flow (Client Credentials)
//!
//! On application start-up, you will need to set up your source and any intermediate caching
//! layers.
//!
//! In the example below, we pull some credentials in and set up a token source to
//! perform a token exchange against an OAuth2 token backend. That set up includes some
//! configuration for determining when a token should be considered _stale_ and eligible for
//! renewal.
//!
//! We next set up a file cache so that we can persist the token locally. This allows us to
//! continue using the same token across application restarts or for multiple instances on
//! the same logical filesystem to share tokens. In the case of serverless functions, you
//! might want to implement a token cache that uses a private cache such as Redis or a
//! private table.
//!
//! Finally, we construct our final token source from these to elements and spawn a token
//! watcher which will automatically renew the token in the background as it becomes stale.
//! The actual time that it attempts to perform this refresh is controlled by a
//! [JitterSource][jitter::JitterSource], which helps prevent stampedes of renewal attempts
//! by multiple instances seeing a token go stale at the same time. An error backoff configuration
//! is also provided to introduce a reasonable means of reducing load when the token authority
//! returns an error.
//!
//! ```
//! use aliri_clock::DurationSecs;
//! use aliri_tokens::{backoff, jitter, sources, ClientId, ClientSecret, TokenLifetimeConfig, TokenWatcher};
//!
//! # struct Opts {
//! #     client_id: ClientId,
//! #     client_secret: ClientSecret,
//! #     audience: aliri::jwt::Audience,
//! #     token_url: reqwest::Url,
//! #     credentials_file: std::path::PathBuf,
//! # }
//! #
//! # let opts = Opts {
//! #     client_id: ClientId::from_static("test"),
//! #     client_secret: ClientSecret::from_static("test"),
//! #     audience: aliri::jwt::Audience::from_static("test"),
//! #     token_url: reqwest::Url::parse("https://example.com/oauth/token").unwrap(),
//! #     credentials_file: std::path::PathBuf::from("credentials.json"),
//! # };
//! #
//! let credentials = sources::oauth2::dto::ClientCredentialsWithAudience {
//!     credentials: sources::oauth2::dto::ClientCredentials {
//!         client_id: opts.client_id,
//!         client_secret: opts.client_secret,
//!     }
//!     .into(),
//!     audience: opts.audience,
//! };
//!
//! let fallback = sources::oauth2::ClientCredentialsTokenSource::new(
//!     reqwest::Client::new(),
//!     opts.token_url,
//!     credentials,
//!     TokenLifetimeConfig::default(),
//! );
//!
//! let file_source = sources::file::FileTokenSource::new(opts.credentials_file);
//!
//! let token_source =
//!     sources::cache::CachedTokenSource::new(fallback).with_cache("file", file_source);
//!
//! let jitter_source = jitter::RandomEarlyJitter::new(DurationSecs(60));
//!
//! let watcher = TokenWatcher::spawn_from_token_source(
//!     token_source,
//!     jitter_source,
//!     backoff::ErrorBackoffConfig::default(),
//! )
//! # ;/* Commented out due to this trying to interact with the world.
//! .await?;
//!
//! tracing::info!(
//!     token = format_args!("{:#?}", watcher.token().access_token()),
//!     "first access token"
//! );
//! # */
//! ```
//!
//! This crate includes an example of doing a periodic refresh using a file cache in
//! the examples folder. Refer to that example for more details on usage.
//!
//! # Features
//!
//! The following features are supported by this crate, all of which are enabled by default:
//!
//! * `oauth2`: Provides implementations of token refresh sources corresponding to the _client
//!   credentials_ and _refresh token_ flows.
//! * `file`: Provides implementations of a token refresh source and cache using the local
//!   filesystem.
//! * `rand`: Provides for an implementation of [JitterSource][jitter::JitterSource] based on the
//!   random number generator provided by the [rand] crate.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_docs,
    unused_import_braces,
    unused_imports,
    unused_qualifications
)]
#![deny(
    missing_debug_implementations,
    trivial_numeric_casts,
    unsafe_code,
    unused_must_use
)]

pub mod backoff;
mod braids;
pub mod jitter;
pub mod sources;
mod tokens;
mod watcher;

pub use braids::*;
pub use tokens::{TokenLifetimeConfig, TokenStatus, TokenWithLifetime};
pub use watcher::{BorrowedToken, TokenPublisherQuit, TokenWatcher};
