#![deny(clippy::print_stdout)]
#![forbid(unsafe_code)]

//! Lightweight synchronous local Web UI (`klens-ui`) for Karasu Lens.
//!
//! Architecture & security invariants:
//! - Synchronous `tiny_http` (`default-features = false`, zero `tokio`/`axum`/`openssl`/`rustls`).
//! - Binds strictly to `127.0.0.1:<port>` (never `0.0.0.0`).
//! - Centralized [`security::security_guard`] runs before every route handler:
//!   strict `Host` check + cryptographic session token cookie (`HttpOnly; SameSite=Strict`)
//!   + triple CSRF gate (`Origin` + cookie + `X-Klens-Request: 1`) on all write endpoints.
//! - 100% offline embedded static assets (`include_str!`) with lightweight JSON i18n (`en`/`tr`/`de`/`es`/`fr`/`pt`).
//! - Zero coupling to `klens-mcp` and zero circular module dependencies.

pub mod assets;
pub mod error;
pub mod routes;
pub mod security;
pub mod server;
pub mod state;

pub use error::UiError;
pub use security::{
    CUSTOM_REQUEST_HEADER, CUSTOM_REQUEST_HEADER_VALUE, GuardOutcome, SESSION_COOKIE_NAME,
    generate_session_token, is_allowed_host, is_allowed_origin, parse_query_params,
    percent_decode_utf8, security_guard,
};
pub use server::{UiServer, is_safe_loopback_launch_url, open_browser};
pub use state::{UiConfig, UiState, directory_looks_like_project};
