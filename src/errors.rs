use std::str::FromStr;

use actix_web::{
    HttpRequest, HttpResponse, ResponseError,
    body::{BoxBody, MessageBody},
    dev::{ResponseHead, ServiceRequest, ServiceResponse},
    http::{StatusCode, header},
    middleware::Next,
    web,
};
use thiserror::Error;

use crate::{MiniserveConfig, renderer::render_error};

#[derive(Debug, Error)]
pub enum StartupError {
    /// Any kind of IO errors
    #[error("{0}\ncaused by: {1}")]
    IoError(String, std::io::Error),

    /// In case miniserve was invoked without an interactive terminal and without an explicit path
    #[error(
        "Refusing to start as no explicit serve path was set and no interactive terminal was attached\nPlease set an explicit serve path like: `miniserve /my/path`"
    )]
    NoExplicitPathAndNoTerminal,

    /// In case miniserve was invoked with --no-symlinks but the serve path is a symlink
    #[error("The -P|--no-symlinks option was provided but the serve path '{0}' is a symlink")]
    NoSymlinksOptionWithSymlinkServePath(String),

    #[error("The --enable-webdav option was provided, but the serve path '{0}' is a file")]
    WebdavWithFileServePath(String),

    /// Configuration validation errors with detailed context
    #[error("Configuration validation failed: {0}")]
    #[allow(dead_code)]
    ConfigValidationError(ConfigValidationError),
}

#[derive(Debug, Error)]
pub enum ConfigValidationError {
    /// Port conflicts or invalid port ranges
    #[error("Port {port} is invalid or unavailable.\nSuggestion: {suggestion}")]
    PortError { port: u16, suggestion: String },

    /// Invalid file paths or access issues
    #[error("Path '{path}' is invalid: {reason}.\nSuggestion: {suggestion}")]
    PathError {
        path: String,
        reason: String,
        suggestion: String,
    },

    /// Incompatible option combinations
    #[error(
        "Option conflict: {primary_option} cannot be used with {conflicting_option}.\nReason: {reason}\nSuggestion: {suggestion}"
    )]
    OptionConflict {
        primary_option: String,
        conflicting_option: String,
        reason: String,
        suggestion: String,
    },

    /// Missing required dependencies between options
    #[error(
        "Option '{option}' requires '{required_option}' to be set.\nReason: {reason}\nSuggestion: {suggestion}"
    )]
    MissingDependency {
        option: String,
        required_option: String,
        reason: String,
        suggestion: String,
    },

    /// Authentication configuration errors
    #[error("Authentication configuration error: {reason}.\nSuggestion: {suggestion}")]
    AuthError { reason: String, suggestion: String },

    /// TLS configuration errors
    #[error("TLS configuration error: {reason}.\nSuggestion: {suggestion}")]
    TlsError { reason: String, suggestion: String },

    /// Upload configuration validation errors
    #[error("Upload configuration error: {reason}.\nSuggestion: {suggestion}")]
    UploadError { reason: String, suggestion: String },
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Any kind of IO errors with enhanced context
    #[error(
        "I/O operation failed: {operation}\nPath: {path}\nCaused by: {source}\nSuggestion: {suggestion}"
    )]
    IoError {
        operation: String,
        path: String,
        source: std::io::Error,
        suggestion: String,
    },

    /// Might occur during file upload, when processing the multipart request fails
    #[error(
        "Failed to process multipart upload request.\nDetails: {0}\nSuggestion: Check that the request contains valid multipart/form-data with proper field names"
    )]
    MultipartError(String),

    /// Might occur during file upload with enhanced context
    #[error(
        "File '{filename}' already exists in '{directory}'.\nCurrent policy: {policy}\nSuggestion: Use --overwrite-files or --rename-files to handle duplicates differently"
    )]
    DuplicateFileError {
        filename: String,
        directory: String,
        policy: String,
    },

    /// Uploaded hash not correct with enhanced context
    #[error(
        "File integrity check failed for '{filename}'.\nExpected hash: {expected}\nActual hash: {actual}\nAlgorithm: {algorithm}\nSuggestion: Verify the file wasn't corrupted during upload or check your hash calculation"
    )]
    UploadHashMismatchError {
        filename: String,
        expected: String,
        actual: String,
        algorithm: String,
    },

    /// Upload not allowed with enhanced context
    #[error(
        "Upload denied to '{directory}'.\nReason: {reason}\nAllowed directories: {allowed_dirs}\nSuggestion: {suggestion}"
    )]
    UploadForbiddenError {
        directory: String,
        reason: String,
        allowed_dirs: String,
        suggestion: String,
    },

    /// Any error related to an invalid path with enhanced context
    #[error("Invalid path operation: '{path}'\nReason: {reason}\nSuggestion: {suggestion}")]
    InvalidPathError {
        path: String,
        reason: String,
        suggestion: String,
    },

    /// Might occur if the user has insufficient permissions with enhanced context
    #[error(
        "Insufficient permissions for operation.\nPath: '{path}'\nOperation: {operation}\nRequired permissions: {required}\nSuggestion: {suggestion}"
    )]
    InsufficientPermissionsError {
        path: String,
        operation: String,
        required: String,
        suggestion: String,
    },

    /// Any error related to parsing
    #[error("Failed to parse {0}\ncaused by: {1}")]
    ParseError(String, String),

    /// Might occur when the creation of an archive fails
    #[error("An error occurred while creating the {0}\ncaused by: {1}")]
    ArchiveCreationError(String, Box<RuntimeError>),

    /// More specific archive creation failure reason
    #[error("{0}")]
    ArchiveCreationDetailError(String),

    /// Might occur when the HTTP credentials are not correct
    #[error("Invalid credentials for HTTP authentication")]
    InvalidHttpCredentials,

    /// Might occur when an HTTP request is invalid
    #[error("Invalid HTTP request\ncaused by: {0}")]
    InvalidHttpRequestError(String),

    /// Might occur when trying to access a page that does not exist
    #[error("Route {0} could not be found")]
    RouteNotFoundError(String),
}

impl ResponseError for RuntimeError {
    fn status_code(&self) -> StatusCode {
        use RuntimeError as E;
        use StatusCode as S;
        match self {
            E::IoError { .. } => S::INTERNAL_SERVER_ERROR,
            E::UploadHashMismatchError { .. } => S::BAD_REQUEST,
            E::MultipartError(_) => S::BAD_REQUEST,
            E::DuplicateFileError { .. } => S::CONFLICT,
            E::UploadForbiddenError { .. } => S::FORBIDDEN,
            E::InvalidPathError { .. } => S::BAD_REQUEST,
            E::InsufficientPermissionsError { .. } => S::FORBIDDEN,
            E::ParseError(_, _) => S::BAD_REQUEST,
            E::ArchiveCreationError(_, err) => err.status_code(),
            E::ArchiveCreationDetailError(_) => S::INTERNAL_SERVER_ERROR,
            E::InvalidHttpCredentials => S::UNAUTHORIZED,
            E::InvalidHttpRequestError(_) => S::BAD_REQUEST,
            E::RouteNotFoundError(_) => S::NOT_FOUND,
        }
    }

    fn error_response(&self) -> HttpResponse {
        log_error_chain(self.to_string());

        let mut resp = HttpResponse::build(self.status_code());
        if let Self::InvalidHttpCredentials = self {
            resp.append_header((
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Basic realm=\"miniserve\""),
            ));
        }

        resp.content_type(mime::TEXT_PLAIN_UTF_8)
            .body(self.to_string())
    }
}

/// Middleware to convert plain-text error responses to user-friendly web pages
pub async fn error_page_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let res = next.call(req).await?.map_into_boxed_body();

    if (res.status().is_client_error() || res.status().is_server_error())
        && res.request().path() != "/upload"
        && res
            .headers()
            .get(header::CONTENT_TYPE)
            .map(AsRef::as_ref)
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| mime::Mime::from_str(s).ok())
            .as_ref()
            .map(mime::Mime::essence_str)
            == Some(mime::TEXT_PLAIN.as_ref())
    {
        let req = res.request().clone();
        Ok(res.map_body(|head, body| map_error_page(&req, head, body)))
    } else {
        Ok(res)
    }
}

fn map_error_page(req: &HttpRequest, head: &mut ResponseHead, body: BoxBody) -> BoxBody {
    let error_msg = match body.try_into_bytes() {
        Ok(bytes) => bytes,
        Err(body) => return body,
    };

    let error_msg = match std::str::from_utf8(&error_msg) {
        Ok(msg) => msg,
        _ => return BoxBody::new(error_msg),
    };

    let conf = req.app_data::<web::Data<MiniserveConfig>>().unwrap();
    let return_address = req
        .headers()
        .get(header::REFERER)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("/");

    head.headers.insert(
        header::CONTENT_TYPE,
        mime::TEXT_HTML_UTF_8.essence_str().try_into().unwrap(),
    );

    BoxBody::new(render_error(error_msg, head.status, conf, return_address).into_string())
}

pub fn log_error_chain(description: String) {
    for cause in description.lines() {
        log::error!("{cause}");
    }
}

/// Log configuration validation failures with structured context
pub fn log_validation_failure(error: &ConfigValidationError, context: &str) {
    match error {
        ConfigValidationError::PortError { port, .. } => {
            log::error!(
                "Configuration validation failed in {context}: Port conflict on port {port}"
            );
        }
        ConfigValidationError::PathError { path, reason, .. } => {
            log::error!(
                "Configuration validation failed in {context}: Path error for '{path}' - {reason}"
            );
        }
        ConfigValidationError::OptionConflict {
            primary_option,
            conflicting_option,
            reason,
            ..
        } => {
            log::error!(
                "Configuration validation failed in {context}: Option conflict between '{primary_option}' and '{conflicting_option}' - {reason}"
            );
        }
        ConfigValidationError::MissingDependency {
            option,
            required_option,
            reason,
            ..
        } => {
            log::error!(
                "Configuration validation failed in {context}: Missing dependency '{option}' requires '{required_option}' - {reason}"
            );
        }
        ConfigValidationError::AuthError { reason, .. } => {
            log::error!("Configuration validation failed in {context}: Auth error - {reason}");
        }
        ConfigValidationError::TlsError { reason, .. } => {
            log::error!("Configuration validation failed in {context}: TLS error - {reason}");
        }
        ConfigValidationError::UploadError { reason, .. } => {
            log::error!("Configuration validation failed in {context}: Upload error - {reason}");
        }
    }
}
