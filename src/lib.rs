// Library interface for miniserve
// This allows testing and external usage of miniserve components

pub mod archive;
pub mod args;
pub mod auth;
pub mod config;
pub mod consts;
pub mod errors;
pub mod file_op;
pub mod file_utils;
pub mod listing;
pub mod pipe;
pub mod renderer;
pub mod security;
pub mod webdav_fs;

// Re-export commonly used types
pub use config::MiniserveConfig;
pub use errors::{RuntimeError, StartupError};
pub use security::{RateLimitConfig, SecurityConfig, SecurityHeadersConfig, SecurityMiddleware};
