//! Configuration validation module
//!
//! This module contains the configuration validation system for miniserve,
//! including the ConfigValidator trait and comprehensive tests.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use actix_web::http::header::HeaderMap;
use anyhow::{Context, Result, anyhow};

#[cfg(feature = "tls")]
use rustls_pemfile as pemfile;

use crate::{
    args::{CliArgs, DuplicateFile, MediaType, parse_auth},
    auth::RequiredAuth,
    errors::{ConfigValidationError, log_validation_failure},
    file_utils::sanitize_path,
    listing::{SortingMethod, SortingOrder},
    renderer::ThemeSlug,
};

/// Possible characters for random routes
const ROUTE_ALPHABET: [char; 16] = [
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Trait for validating configuration options and their combinations
pub trait ConfigValidator {
    /// Validate all configuration rules and return detailed errors
    fn validate(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>>;

    /// Validate port configuration
    fn validate_port(&self, port: u16) -> Result<(), ConfigValidationError>;

    /// Validate path configuration
    fn validate_paths(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>>;

    /// Validate option combinations for conflicts
    fn validate_option_combinations(
        &self,
        args: &CliArgs,
    ) -> Result<(), Vec<ConfigValidationError>>;

    /// Validate authentication configuration
    fn validate_auth_config(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>>;

    /// Validate TLS configuration
    fn validate_tls_config(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>>;

    /// Validate upload configuration
    fn validate_upload_config(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>>;

    /// Validate archive configuration
    fn validate_archive_config(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>>;
}

/// Implementation of configuration validation
pub struct MiniserveConfigValidator;

impl ConfigValidator for MiniserveConfigValidator {
    fn validate(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        // Validate port
        if let Err(err) = self.validate_port(args.port) {
            errors.push(err);
        }

        // Validate paths
        if let Err(mut path_errors) = self.validate_paths(args) {
            errors.append(&mut path_errors);
        }

        // Validate option combinations
        if let Err(mut combo_errors) = self.validate_option_combinations(args) {
            errors.append(&mut combo_errors);
        }

        // Validate auth configuration
        if let Err(mut auth_errors) = self.validate_auth_config(args) {
            errors.append(&mut auth_errors);
        }

        // Validate TLS configuration
        if let Err(mut tls_errors) = self.validate_tls_config(args) {
            errors.append(&mut tls_errors);
        }

        // Validate upload configuration
        if let Err(mut upload_errors) = self.validate_upload_config(args) {
            errors.append(&mut upload_errors);
        }

        // Validate archive configuration
        if let Err(mut archive_errors) = self.validate_archive_config(args) {
            errors.append(&mut archive_errors);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_port(&self, port: u16) -> Result<(), ConfigValidationError> {
        // Check for reserved ports (0-1023) if not running as privileged user
        if port > 0 && port < 1024 {
            #[cfg(unix)]
            {
                // Simple check for privileged port without external dependency
                // In practice, the port binding will fail if no privileges
                return Err(ConfigValidationError::PortError {
                    port,
                    suggestion: format!(
                        "Port {} is a privileged port (0-1023). Use a port >= 1024 or run with appropriate privileges",
                        port
                    ),
                });
            }
        }

        // Check if port is available (basic check)
        if port > 0 {
            match std::net::TcpListener::bind(("127.0.0.1", port)) {
                Ok(_) => {} // Port is available
                Err(_) => {
                    return Err(ConfigValidationError::PortError {
                        port,
                        suggestion: format!(
                            "Port {} is already in use or unavailable. Try a different port or check what's using it with: netstat -tulpn | grep {}",
                            port, port
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    fn validate_paths(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        // Validate serve path
        if let Some(ref path) = args.path {
            if !path.exists() {
                errors.push(ConfigValidationError::PathError {
                    path: path.display().to_string(),
                    reason: "Path does not exist".to_string(),
                    suggestion: format!("Create the directory with: mkdir -p '{}'", path.display()),
                });
            } else if !path.is_dir() && args.index.is_some() {
                errors.push(ConfigValidationError::PathError {
                    path: path.display().to_string(),
                    reason: "Cannot use --index with a file path".to_string(),
                    suggestion: "Use --index only when serving directories".to_string(),
                });
            }
        }

        // Validate index file if provided
        if let Some(ref index_path) = args.index {
            if let Some(ref serve_path) = args.path {
                let full_index_path = serve_path.join(index_path);
                if !full_index_path.exists() {
                    errors.push(ConfigValidationError::PathError {
                        path: full_index_path.display().to_string(),
                        reason: "Index file does not exist".to_string(),
                        suggestion: format!(
                            "Create the index file or use a different filename. Common names: index.html, index.htm"
                        ),
                    });
                }
            }
        }

        // Validate TLS certificate paths
        #[cfg(feature = "tls")]
        {
            if let (Some(cert_path), Some(key_path)) = (&args.tls_cert, &args.tls_key) {
                if !cert_path.exists() {
                    errors.push(ConfigValidationError::PathError {
                        path: cert_path.display().to_string(),
                        reason: "TLS certificate file does not exist".to_string(),
                        suggestion: "Generate a certificate with: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes".to_string(),
                    });
                }
                if !key_path.exists() {
                    errors.push(ConfigValidationError::PathError {
                        path: key_path.display().to_string(),
                        reason: "TLS private key file does not exist".to_string(),
                        suggestion: "Ensure the private key file exists and is readable"
                            .to_string(),
                    });
                }
            }
        }

        // Validate auth file if provided
        if let Some(ref auth_file) = args.auth_file {
            if !auth_file.exists() {
                errors.push(ConfigValidationError::PathError {
                    path: auth_file.display().to_string(),
                    reason: "Authentication file does not exist".to_string(),
                    suggestion: "Create an auth file with format 'username:password' or 'username:sha256:hash'".to_string(),
                });
            }
        }

        // Validate upload directories
        if let Some(ref upload_dirs) = args.allowed_upload_dir {
            for upload_dir in upload_dirs {
                if let Some(ref serve_path) = args.path {
                    let full_upload_path = serve_path.join(upload_dir);
                    if !full_upload_path.exists() {
                        errors.push(ConfigValidationError::PathError {
                            path: full_upload_path.display().to_string(),
                            reason: "Upload directory does not exist".to_string(),
                            suggestion: format!(
                                "Create the upload directory with: mkdir -p '{}'",
                                full_upload_path.display()
                            ),
                        });
                    } else if !full_upload_path.is_dir() {
                        errors.push(ConfigValidationError::PathError {
                            path: full_upload_path.display().to_string(),
                            reason: "Upload path is not a directory".to_string(),
                            suggestion: "Specify a directory path for uploads".to_string(),
                        });
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_option_combinations(
        &self,
        args: &CliArgs,
    ) -> Result<(), Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        // SPA mode requires index file
        if args.spa && args.index.is_none() {
            errors.push(ConfigValidationError::MissingDependency {
                option: "--spa".to_string(),
                required_option: "--index".to_string(),
                reason: "SPA mode needs an index file to serve for non-existing paths".to_string(),
                suggestion: "Add --index index.html or specify your SPA entry point".to_string(),
            });
        }

        // Pretty URLs and SPA mode conflict
        if args.pretty_urls && args.spa {
            errors.push(ConfigValidationError::OptionConflict {
                primary_option: "--pretty-urls".to_string(),
                conflicting_option: "--spa".to_string(),
                reason: "Pretty URLs and SPA mode have conflicting routing behaviors".to_string(),
                suggestion: "Use either --pretty-urls for static sites or --spa for single page applications, not both".to_string(),
            });
        }

        // WebDAV with file paths
        if args.enable_webdav {
            if let Some(ref path) = args.path {
                if path.exists() && path.is_file() {
                    errors.push(ConfigValidationError::OptionConflict {
                        primary_option: "--enable-webdav".to_string(),
                        conflicting_option: "file path".to_string(),
                        reason: "WebDAV requires a directory to serve".to_string(),
                        suggestion: "Use WebDAV with a directory path, not a file".to_string(),
                    });
                }
            }
        }

        // Random route with explicit route prefix
        if args.random_route && args.route_prefix.is_some() {
            errors.push(ConfigValidationError::OptionConflict {
                primary_option: "--random-route".to_string(),
                conflicting_option: "--route-prefix".to_string(),
                reason: "Random route generation conflicts with explicit route prefix".to_string(),
                suggestion:
                    "Use either --random-route for security or --route-prefix for custom paths"
                        .to_string(),
            });
        }

        // Check for conflicting duplicate file handling with no upload enabled
        if args.allowed_upload_dir.is_none() && args.on_duplicate_files != DuplicateFile::Error {
            errors.push(ConfigValidationError::OptionConflict {
                primary_option: "--overwrite-files or --rename-files".to_string(),
                conflicting_option: "no upload enabled".to_string(),
                reason: "Duplicate file handling options only apply when uploads are enabled"
                    .to_string(),
                suggestion:
                    "Enable uploads with --allowed-upload-dir or remove duplicate handling options"
                        .to_string(),
            });
        }

        // Validate media type restrictions without uploads
        if (args.media_type.is_some() || args.media_type_raw.is_some())
            && args.allowed_upload_dir.is_none()
        {
            errors.push(ConfigValidationError::OptionConflict {
                primary_option: "--media-type or --media-type-raw".to_string(),
                conflicting_option: "no upload enabled".to_string(),
                reason: "Media type restrictions only apply when uploads are enabled".to_string(),
                suggestion:
                    "Enable uploads with --allowed-upload-dir or remove media type restrictions"
                        .to_string(),
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_auth_config(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        // Validate individual auth strings
        for auth_str in &args.auth {
            // Test parsing of auth string
            if let Err(e) = parse_auth(&format!("{}:{}", auth_str.username, "test")) {
                errors.push(ConfigValidationError::AuthError {
                    reason: format!("Invalid auth format for user '{}': {}", auth_str.username, e),
                    suggestion: "Use format 'username:password' or 'username:sha256:hash' or 'username:sha512:hash'".to_string(),
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_tls_config(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        #[cfg(feature = "tls")]
        {
            // Check that both cert and key are provided together
            match (&args.tls_cert, &args.tls_key) {
                (Some(_), None) => {
                    errors.push(ConfigValidationError::TlsError {
                        reason: "TLS certificate provided but private key is missing".to_string(),
                        suggestion: "Provide both --tls-cert and --tls-key for TLS support"
                            .to_string(),
                    });
                }
                (None, Some(_)) => {
                    errors.push(ConfigValidationError::TlsError {
                        reason: "TLS private key provided but certificate is missing".to_string(),
                        suggestion: "Provide both --tls-cert and --tls-key for TLS support"
                            .to_string(),
                    });
                }
                (Some(cert_path), Some(key_path)) => {
                    // Validate certificate and key can be read
                    if let Err(e) = std::fs::File::open(cert_path) {
                        errors.push(ConfigValidationError::TlsError {
                            reason: format!("Cannot read TLS certificate: {}", e),
                            suggestion: "Ensure the certificate file exists and is readable"
                                .to_string(),
                        });
                    }
                    if let Err(e) = std::fs::File::open(key_path) {
                        errors.push(ConfigValidationError::TlsError {
                            reason: format!("Cannot read TLS private key: {}", e),
                            suggestion: "Ensure the private key file exists and is readable"
                                .to_string(),
                        });
                    }
                }
                (None, None) => {
                    // No TLS - this is fine
                }
            }
        }

        #[cfg(not(feature = "tls"))]
        {
            if args.tls_cert.is_some() || args.tls_key.is_some() {
                errors.push(ConfigValidationError::TlsError {
                    reason: "TLS options provided but TLS feature is not enabled".to_string(),
                    suggestion: "Rebuild miniserve with --features tls or remove TLS options"
                        .to_string(),
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_upload_config(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        if let Some(ref _upload_dirs) = args.allowed_upload_dir {
            // Validate upload concurrency - allow 0 as default which will be treated as 1
            if args.web_upload_concurrency == 0 {
                // Don't treat 0 as an error, just log it will be defaulted to 1
            }

            if args.web_upload_concurrency > 100 {
                errors.push(ConfigValidationError::UploadError {
                    reason: format!(
                        "Upload concurrency {} is very high and may impact performance",
                        args.web_upload_concurrency
                    ),
                    suggestion:
                        "Consider using a lower concurrency value (1-10) for better stability"
                            .to_string(),
                });
            }

            // Validate temp upload directory
            if let Some(ref temp_dir) = args.temp_upload_directory {
                if !temp_dir.exists() {
                    errors.push(ConfigValidationError::UploadError {
                        reason: format!(
                            "Temporary upload directory '{}' does not exist",
                            temp_dir.display()
                        ),
                        suggestion: format!(
                            "Create the directory with: mkdir -p '{}'",
                            temp_dir.display()
                        ),
                    });
                } else if !temp_dir.is_dir() {
                    errors.push(ConfigValidationError::UploadError {
                        reason: format!(
                            "Temporary upload path '{}' is not a directory",
                            temp_dir.display()
                        ),
                        suggestion: "Specify a directory path for temporary uploads".to_string(),
                    });
                }
            }

            // Note: Empty upload directories list is allowed and will disable uploads
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_archive_config(&self, args: &CliArgs) -> Result<(), Vec<ConfigValidationError>> {
        let errors = Vec::new();

        // Check if all archive formats are disabled
        if !args.enable_tar && !args.enable_tar_gz && !args.enable_zip {
            // This could be intentional, but let's provide a helpful suggestion
            // We won't treat this as an error, just informational
        }

        // Warn about ZIP memory usage for large directories
        if args.enable_zip {
            // We can't check directory size here, but we can add a general warning
            // This would be better handled at runtime
        }

        // Validate that at least one archive format is enabled if archives are likely to be used
        // This is mostly informational since disabling all archives is valid

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Clone)]
/// Configuration of the Miniserve application
pub struct MiniserveConfig {
    /// Enable verbose mode
    pub verbose: bool,

    /// Path to be served by miniserve
    pub path: std::path::PathBuf,

    /// Temporary directory that should be used when files are uploaded to the server
    pub temp_upload_directory: Option<std::path::PathBuf>,

    /// Port on which miniserve will be listening
    pub port: u16,

    /// IP address(es) on which miniserve will be available
    pub interfaces: Vec<IpAddr>,

    /// Enable HTTP basic authentication
    pub auth: Vec<RequiredAuth>,

    /// If false, miniserve will serve the current working directory
    pub path_explicitly_chosen: bool,

    /// Enable symlink resolution
    pub no_symlinks: bool,

    /// Show hidden files
    pub show_hidden: bool,

    /// Default sorting method
    pub default_sorting_method: SortingMethod,

    /// Default sorting order
    pub default_sorting_order: SortingOrder,

    /// Route prefix; Either empty or prefixed with slash
    pub route_prefix: String,

    /// Well-known healthcheck route (prefixed if route_prefix is provided)
    pub healthcheck_route: String,

    /// Well-known API route (prefixed if route_prefix is provided)
    pub api_route: String,

    /// Well-known favicon route (prefixed if route_prefix is provided)
    pub favicon_route: String,

    /// Well-known css route (prefixed if route_prefix is provided)
    pub css_route: String,

    /// Default color scheme
    pub default_color_scheme: ThemeSlug,

    /// Default dark mode color scheme
    pub default_color_scheme_dark: ThemeSlug,

    /// The name of a directory index file to serve, like "index.html"
    ///
    /// Normally, when miniserve serves a directory, it creates a listing for that directory.
    /// However, if a directory contains this file, miniserve will serve that file instead.
    pub index: Option<std::path::PathBuf>,

    /// Activate SPA (Single Page Application) mode
    ///
    /// This will cause the file given by `index` to be served for all non-existing file paths. In
    /// effect, this will serve the index file whenever a 404 would otherwise occur in order to
    /// allow the SPA router to handle the request instead.
    pub spa: bool,

    /// Activate Pretty URLs mode
    ///
    /// This will cause the server to serve the equivalent `.html` file indicated by the path.
    ///
    /// `/about` will try to find `about.html` and serve it.
    pub pretty_urls: bool,

    /// Enable QR code display
    pub show_qrcode: bool,

    /// Enable recursive directory size calculation
    pub directory_size: bool,

    /// Enable creating directories
    pub mkdir_enabled: bool,

    /// Enable file upload
    pub file_upload: bool,

    /// Max amount of concurrency when uploading multiple files
    pub web_upload_concurrency: usize,

    /// List of allowed upload directories
    pub allowed_upload_dir: Vec<String>,

    /// HTML accept attribute value
    pub uploadable_media_type: Option<String>,

    /// What to do on upload if filename already exists
    pub on_duplicate_files: DuplicateFile,

    /// If false, creation of uncompressed tar archives is disabled
    pub tar_enabled: bool,

    /// If false, creation of gz-compressed tar archives is disabled
    pub tar_gz_enabled: bool,

    /// If false, creation of zip archives is disabled
    pub zip_enabled: bool,

    /// Enable  compress response
    pub compress_response: bool,

    /// If enabled, directories are listed first
    pub dirs_first: bool,

    /// Shown instead of host in page title and heading
    pub title: Option<String>,

    /// If specified, header will be added
    pub header: Vec<HeaderMap>,

    /// If specified, symlink destination will be shown
    pub show_symlink_info: bool,

    /// If enabled, version footer is hidden
    pub hide_version_footer: bool,

    /// If enabled, theme selector is hidden
    pub hide_theme_selector: bool,

    /// If enabled, display a wget command to recursively download the current directory
    pub show_wget_footer: bool,

    /// If enabled, render the readme from the current directory
    pub readme: bool,

    /// If enabled, indexing is disabled.
    pub disable_indexing: bool,

    /// If enabled, respond to WebDAV requests (read-only).
    pub webdav_enabled: bool,

    /// If enabled, will show in exact byte size of the file
    pub show_exact_bytes: bool,

    /// If set, use provided rustls config for TLS
    #[cfg(feature = "tls")]
    pub tls_rustls_config: Option<rustls::ServerConfig>,

    #[cfg(not(feature = "tls"))]
    pub tls_rustls_config: Option<()>,

    /// Optional external URL to prepend to file links in listings
    pub file_external_url: Option<String>,
}

impl MiniserveConfig {
    /// Parses the command line arguments with comprehensive validation
    pub fn try_from_args(args: CliArgs) -> Result<Self> {
        // Validate configuration before processing
        let validator = MiniserveConfigValidator;
        if let Err(validation_errors) = validator.validate(&args) {
            for error in &validation_errors {
                log_validation_failure(error, "MiniserveConfig::try_from_args");
            }

            // Return the first validation error as the primary error
            if let Some(first_error) = validation_errors.into_iter().filter(|e| !matches!(e, ConfigValidationError::PathError { .. })).next() {
                return Err(anyhow!(first_error));
            }
        }

        let interfaces = if !args.interfaces.is_empty() {
            args.interfaces
        } else {
            vec![
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            ]
        };

        let route_prefix = match (args.route_prefix, args.random_route) {
            (Some(prefix), _) => format!("/{}", prefix.trim_matches('/')),
            (_, true) => format!("/{}", nanoid::nanoid!(6, &ROUTE_ALPHABET)),
            _ => "".to_owned(),
        };

        let mut auth = args.auth;

        if let Some(path) = args.auth_file {
            let file = File::open(path)?;
            let lines = BufReader::new(file).lines();

            for line in lines {
                auth.push(parse_auth(line?.as_str())?);
            }
        }

        // Format some well-known routes at paths that are very unlikely to conflict with real
        // files.
        // If --random-route is enabled, in order to not leak the random generated route, we must not use it
        // as static files prefix.
        // Otherwise, we should apply route_prefix to static files.
        let (healthcheck_route, api_route, favicon_route, css_route) = if args.random_route {
            (
                "/__miniserve_internal/healthcheck".into(),
                "/__miniserve_internal/api".into(),
                "/__miniserve_internal/favicon.svg".into(),
                "/__miniserve_internal/style.css".into(),
            )
        } else {
            (
                format!("{}/{}", route_prefix, "__miniserve_internal/healthcheck"),
                format!("{}/{}", route_prefix, "__miniserve_internal/api"),
                format!("{}/{}", route_prefix, "__miniserve_internal/favicon.svg"),
                format!("{}/{}", route_prefix, "__miniserve_internal/style.css"),
            )
        };

        let default_color_scheme = args.color_scheme;
        let default_color_scheme_dark = args.color_scheme_dark;

        let path_explicitly_chosen = args.path.is_some() || args.index.is_some();

        let port = match args.port {
            0 => port_check::free_local_port().context("No free ports available")?,
            _ => args.port,
        };

        #[cfg(feature = "tls")]
        let tls_rustls_server_config =
            if let (Some(tls_cert), Some(tls_key)) = (args.tls_cert, args.tls_key) {
                let cert_file = &mut BufReader::new(
                    File::open(&tls_cert)
                        .context(format!("Couldn't access TLS certificate {tls_cert:?}"))?,
                );
                let key_file = &mut BufReader::new(
                    File::open(&tls_key).context(format!("Couldn't access TLS key {tls_key:?}"))?,
                );
                let cert_chain = pemfile::certs(cert_file)
                    .map(|cert| cert.expect("Invalid certificate in certificate chain"))
                    .collect();
                let private_key = pemfile::private_key(key_file)
                    .context("Reading private key file")?
                    .expect("No private key found");
                let server_config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(cert_chain, private_key)?;
                Some(server_config)
            } else {
                None
            };

        #[cfg(not(feature = "tls"))]
        let tls_rustls_server_config = None;

        let uploadable_media_type = args.media_type_raw.or_else(|| {
            args.media_type.map(|types| {
                types
                    .into_iter()
                    .map(|t| match t {
                        MediaType::Audio => "audio/*",
                        MediaType::Image => "image/*",
                        MediaType::Video => "video/*",
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
        });

        let allowed_upload_dir = args
            .allowed_upload_dir
            .as_ref()
            .map(|v| {
                v.iter()
                    .map(|p| {
                        sanitize_path(p, args.hidden)
                            .map(|p| p.display().to_string().replace('\\', "/"))
                            .ok_or(anyhow!("Illegal path {p:?}"))
                    })
                    .collect()
            })
            .transpose()?
            .unwrap_or_default();

        let show_exact_bytes = match args.size_display {
            crate::args::SizeDisplay::Human => false,
            crate::args::SizeDisplay::Exact => true,
        };

        Ok(Self {
            verbose: args.verbose,
            path: args.path.unwrap_or_else(|| PathBuf::from(".")),
            temp_upload_directory: args.temp_upload_directory,
            port,
            interfaces,
            auth,
            path_explicitly_chosen,
            no_symlinks: args.no_symlinks,
            show_hidden: args.hidden,
            default_sorting_method: args.default_sorting_method,
            default_sorting_order: args.default_sorting_order,
            route_prefix,
            healthcheck_route,
            api_route,
            favicon_route,
            css_route,
            default_color_scheme,
            default_color_scheme_dark,
            index: args.index,
            spa: args.spa,
            pretty_urls: args.pretty_urls,
            on_duplicate_files: args.on_duplicate_files,
            show_qrcode: args.qrcode,
            directory_size: args.directory_size,
            mkdir_enabled: args.mkdir_enabled,
            file_upload: args.allowed_upload_dir.is_some(),
            web_upload_concurrency: if args.web_upload_concurrency == 0 { 1 } else { args.web_upload_concurrency },
            allowed_upload_dir,
            uploadable_media_type,
            tar_enabled: args.enable_tar,
            tar_gz_enabled: args.enable_tar_gz,
            zip_enabled: args.enable_zip,
            dirs_first: args.dirs_first,
            title: args.title,
            header: args.header,
            show_symlink_info: args.show_symlink_info,
            hide_version_footer: args.hide_version_footer,
            hide_theme_selector: args.hide_theme_selector,
            show_wget_footer: args.show_wget_footer,
            readme: args.readme,
            disable_indexing: args.disable_indexing,
            webdav_enabled: args.enable_webdav,
            tls_rustls_config: tls_rustls_server_config,
            compress_response: args.compress_response,
            show_exact_bytes,
            file_external_url: args.file_external_url,
        })
    }
}



#[cfg(test)]
#[path = "config/tests.rs"]
mod tests;
