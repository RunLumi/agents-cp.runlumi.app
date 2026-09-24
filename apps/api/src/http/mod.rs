//! HTTP boundary behavior shared by the Worker router.
//!
//! The module is deliberately small: product and identity policy remain in
//! their own layers, while this boundary establishes request diagnostics and
//! keeps transport failures inside the frozen API error contract.

pub mod auth;
mod middleware;
mod platform;

pub use middleware::{MAX_JSON_BODY_BYTES, json_body_limit, request_boundary};
