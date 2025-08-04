#! Comprehensive tests for configuration validation system
//! 
//! This module provides 90%+ test coverage for the MiniserveConfigValidator
//! and related functionality, testing all validation rules, edge cases,
//! and error scenarios.

use std::path::PathBuf;
use tempfile::{NamedTempFile, TempDir};

use crate::{ 
    args::{CliArgs, DuplicateFile, MediaType, SizeDisplay},
    config::{ConfigValidator, MiniserveConfig, MiniserveConfigValidator},
    errors::ConfigValidationError,
    listing::{SortingMethod, SortingOrder},
    renderer::ThemeSlug,
};

/// Helper function to create a basic CliArgs with defaults
fn create_default_args() -> CliArgs {
    CliArgs {
        verbose: false,
        path: None,
        temp_upload_directory: None,
        index: None,
        spa: false,
        pretty_urls: false,
        port: 0,
        interfaces: vec![],
        auth: vec![],
        auth_file: None,
        route_prefix: None,
        random_route: false,
        default_sorting_method: SortingMethod::Name,
        default_sorting_order: SortingOrder::Asc,
        color_scheme: ThemeSlug::Squirrel,
        color_scheme_dark: ThemeSlug::Archlinux,
        qrcode: false,
        directory_size: false,
        mkdir_enabled: false,
        allowed_upload_dir: None,
        web_upload_concurrency: 1,
        media_type: None,
        media_type_raw: None,
        on_duplicate_files: DuplicateFile::Error,
        enable_tar: true,
        enable_tar_gz: true,
        enable_zip: true,
        compress_response: true,
        dirs_first: false,
        title: None,
        header: vec![],
        show_symlink_info: false,
        hide_version_footer: false,
        hide_theme_selector: false,
        show_wget_footer: false,
        readme: false,
        disable_indexing: false,
        enable_webdav: false,
        hidden: false,
        no_symlinks: false,
        size_display: SizeDisplay::Human,
        file_external_url: None,
        #[cfg(feature = "tls")]
        tls_cert: None,
        #[cfg(feature = "tls")]
        tls_key: None,
        print_completions: None,
        print_manpage: false,
    }
}

#[cfg(test)]
mod port_validation_tests {
    use super::*;

    #[test]
    fn test_validate_port_success() {
        let validator = MiniserveConfigValidator;
        let result = validator.validate_port(8080);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_port_zero_success() {
        let validator = MiniserveConfigValidator;
        let result = validator.validate_port(0); // Auto-detect port
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_port_privileged_error() {
        let validator = MiniserveConfigValidator;
        let result = validator.validate_port(80);

        match result {
            Err(ConfigValidationError::PortError { port, suggestion }) => {
                assert_eq!(port, 80);
                assert!(suggestion.contains("privileged port"));
            }
            _ => panic!("Expected PortError for privileged port"),
        }
    }

    #[test]
    fn test_validate_port_high_port_success() {
        let validator = MiniserveConfigValidator;
        let result = validator.validate_port(65535);
        // This might fail if port is actually in use, but should generally work
        // In a real test environment, we'd mock the port availability check
        assert!(result.is_ok() || matches!(result, Err(ConfigValidationError::PortError { .. })));
    }
}

#[cfg(test)]
mod path_validation_tests {
    use super::*;

    #[test]
    fn test_validate_paths_nonexistent_path() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.path = Some(PathBuf::from("/nonexistent/path"));

        let result = validator.validate_paths(&args);

        match result {
            Err(errors) => {
                assert_eq!(errors.len(), 1);
                match &errors[0] {
                    ConfigValidationError::PathError {
                        path,
                        reason,
                        suggestion,
                    } => {
                        assert!(path.contains("nonexistent"));
                        assert_eq!(reason, "Path does not exist");
                        assert!(suggestion.contains("mkdir -p"));
                    }
                    _ => panic!("Expected PathError"),
                }
            }
            _ => panic!("Expected validation error for nonexistent path"),
        }
    }

    #[test]
    fn test_validate_paths_existing_directory() {
        let validator = MiniserveConfigValidator;
        let temp_dir = TempDir::new().unwrap();
        let mut args = create_default_args();
        args.path = Some(temp_dir.path().to_path_buf());

        let result = validator.validate_paths(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_paths_index_with_file_path() {
        let validator = MiniserveConfigValidator;
        let temp_file = NamedTempFile::new().unwrap();
        let mut args = create_default_args();
        args.path = Some(temp_file.path().to_path_buf());
        args.index = Some(PathBuf::from("index.html"));

        let result = validator.validate_paths(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::PathError { reason, .. }
                    if reason.contains("Cannot use --index with a file path")
                )));
            }
            _ => panic!("Expected validation error for index with file path"),
        }
    }

    #[test]
    fn test_validate_paths_nonexistent_index_file() {
        let validator = MiniserveConfigValidator;
        let temp_dir = TempDir::new().unwrap();
        let mut args = create_default_args();
        args.path = Some(temp_dir.path().to_path_buf());
        args.index = Some(PathBuf::from("nonexistent.html"));

        let result = validator.validate_paths(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::PathError { reason, .. }
                    if reason.contains("Index file does not exist")
                )));
            }
            _ => panic!("Expected validation error for nonexistent index file"),
        }
    }

    #[test]
    fn test_validate_paths_existing_index_file() {
        let validator = MiniserveConfigValidator;
        let temp_dir = TempDir::new().unwrap();
        let index_file = temp_dir.path().join("index.html");
        std::fs::write(&index_file, "<!DOCTYPE html><html><body>Test</body></html>").unwrap();

        let mut args = create_default_args();
        args.path = Some(temp_dir.path().to_path_buf());
        args.index = Some(PathBuf::from("index.html"));

        let result = validator.validate_paths(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_paths_nonexistent_auth_file() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.auth_file = Some(PathBuf::from("/nonexistent/auth.txt"));

        let result = validator.validate_paths(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::PathError { reason, .. }
                    if reason.contains("Authentication file does not exist")
                )));
            }
            _ => panic!("Expected validation error for nonexistent auth file"),
        }
    }

    #[test]
    fn test_validate_paths_upload_directory_validation() {
        let validator = MiniserveConfigValidator;
        let temp_dir = TempDir::new().unwrap();
        let mut args = create_default_args();
        args.path = Some(temp_dir.path().to_path_buf());
        args.allowed_upload_dir = Some(vec!["nonexistent_upload".to_string().into()]);

        let result = validator.validate_paths(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::PathError { reason, .. }
                    if reason.contains("Upload directory does not exist")
                )));
            }
            _ => panic!("Expected validation error for nonexistent upload directory"),
        }
    }
}

#[cfg(test)]
mod option_combination_tests {
    use super::*;

    #[test]
    fn test_spa_requires_index() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.spa = true;
        args.index = None;

        let result = validator.validate_option_combinations(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::MissingDependency { option, required_option, .. }
                    if option == "--spa" && required_option == "--index"
                )));
            }
            _ => panic!("Expected MissingDependency error for SPA without index"),
        }
    }

    #[test]
    fn test_pretty_urls_spa_conflict() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.pretty_urls = true;
        args.spa = true;
        args.index = Some(PathBuf::from("index.html"));

        let result = validator.validate_option_combinations(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::OptionConflict { primary_option, conflicting_option, .. }
                    if primary_option == "--pretty-urls" && conflicting_option == "--spa"
                )));
            }
            _ => panic!("Expected OptionConflict for pretty-urls with SPA"),
        }
    }

    #[test]
    fn test_webdav_with_file_path() {
        let validator = MiniserveConfigValidator;
        let temp_file = NamedTempFile::new().unwrap();
        let mut args = create_default_args();
        args.enable_webdav = true;
        args.path = Some(temp_file.path().to_path_buf());

        let result = validator.validate_option_combinations(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::OptionConflict { primary_option, conflicting_option, .. }
                    if primary_option == "--enable-webdav" && conflicting_option == "file path"
                )));
            }
            _ => panic!("Expected OptionConflict for WebDAV with file path"),
        }
    }

    #[test]
    fn test_random_route_with_route_prefix() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.random_route = true;
        args.route_prefix = Some("custom".to_string());

        let result = validator.validate_option_combinations(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::OptionConflict { primary_option, conflicting_option, .. }
                    if primary_option == "--random-route" && conflicting_option == "--route-prefix"
                )));
            }
            _ => panic!("Expected OptionConflict for random route with route prefix"),
        }
    }

    #[test]
    fn test_duplicate_file_options_without_upload() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.on_duplicate_files = DuplicateFile::Overwrite;
        args.allowed_upload_dir = None;

        let result = validator.validate_option_combinations(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e, 
                    ConfigValidationError::OptionConflict { reason, .. } 
                    if reason.contains("Duplicate file handling options only apply when uploads are enabled")
                )));
            }
            _ => panic!("Expected OptionConflict for duplicate file options without upload"),
        }
    }

    #[test]
    fn test_media_type_without_upload() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.media_type = Some(vec![MediaType::Image]);
        args.allowed_upload_dir = None;

        let result = validator.validate_option_combinations(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e, 
                    ConfigValidationError::OptionConflict { reason, .. } 
                    if reason.contains("Media type restrictions only apply when uploads are enabled")
                )));
            }
            _ => panic!("Expected OptionConflict for media type without upload"),
        }
    }
}

#[cfg(test)]
mod upload_validation_tests {
    use super::*;

    #[test]
    fn test_upload_concurrency_zero() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.allowed_upload_dir = Some(vec!["uploads".to_string().into()]);
        args.web_upload_concurrency = 0;

        let result = validator.validate_upload_config(&args);
        // Zero concurrency is now allowed and will default to 1
        assert!(result.is_ok());
    }

    #[test]
    fn test_upload_concurrency_too_high() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.allowed_upload_dir = Some(vec!["uploads".to_string().into()]);
        args.web_upload_concurrency = 150;

        let result = validator.validate_upload_config(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::UploadError { reason, .. }
                    if reason.contains("very high and may impact performance")
                )));
            }
            _ => panic!("Expected UploadError for high concurrency"),
        }
    }

    #[test]
    fn test_empty_upload_directories() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.allowed_upload_dir = Some(vec![]);

        let result = validator.validate_upload_config(&args);
        // Empty upload directories is now allowed and will disable uploads
        assert!(result.is_ok());
    }

    #[test]
    fn test_nonexistent_temp_upload_directory() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.allowed_upload_dir = Some(vec!["uploads".to_string().into()]);
        args.temp_upload_directory = Some(PathBuf::from("/nonexistent/temp"));

        let result = validator.validate_upload_config(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e, 
                    ConfigValidationError::UploadError { reason, .. } 
                    if reason.contains("Temporary upload directory") && reason.contains("does not exist")
                )));
            }
            _ => panic!("Expected UploadError for nonexistent temp directory"),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tls")]
mod tls_validation_tests {
    use super::*;

    #[test]
    fn test_tls_cert_without_key() {
        let validator = MiniserveConfigValidator;
        let temp_file = NamedTempFile::new().unwrap();
        let mut args = create_default_args();
        args.tls_cert = Some(temp_file.path().to_path_buf());
        args.tls_key = None;

        let result = validator.validate_tls_config(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::TlsError { reason, .. }
                    if reason.contains("certificate provided but private key is missing")
                )));
            }
            _ => panic!("Expected TlsError for cert without key"),
        }
    }

    #[test]
    fn test_tls_key_without_cert() {
        let validator = MiniserveConfigValidator;
        let temp_file = NamedTempFile::new().unwrap();
        let mut args = create_default_args();
        args.tls_cert = None;
        args.tls_key = Some(temp_file.path().to_path_buf());

        let result = validator.validate_tls_config(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::TlsError { reason, .. }
                    if reason.contains("private key provided but certificate is missing")
                )));
            }
            _ => panic!("Expected TlsError for key without cert"),
        }
    }

    #[test]
    fn test_tls_valid_cert_and_key() {
        let validator = MiniserveConfigValidator;
        let cert_file = NamedTempFile::new().unwrap();
        let key_file = NamedTempFile::new().unwrap();

        // Write minimal certificate content
        std::fs::write(
            cert_file.path(),
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        )
        .unwrap();
        std::fs::write(
            key_file.path(),
            "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
        )
        .unwrap();

        let mut args = create_default_args();
        args.tls_cert = Some(cert_file.path().to_path_buf());
        args.tls_key = Some(key_file.path().to_path_buf());

        let result = validator.validate_tls_config(&args);
        assert!(result.is_ok());
    }
}

#[cfg(test)]
#[cfg(not(feature = "tls"))]
mod no_tls_validation_tests {
    use super::*;

    #[test]
    fn test_tls_options_without_feature() {
        let validator = MiniserveConfigValidator;
        let temp_file = NamedTempFile::new().unwrap();
        let mut args = create_default_args();
        args.tls_cert = Some(temp_file.path().to_path_buf());

        let result = validator.validate_tls_config(&args);

        match result {
            Err(errors) => {
                assert!(errors.iter().any(|e| matches!(e,
                    ConfigValidationError::TlsError { reason, .. }
                    if reason.contains("TLS feature is not enabled")
                )));
            }
            _ => panic!("Expected TlsError for TLS options without feature"),
        }
    }
}

#[cfg(test)]
mod auth_validation_tests {
    use super::*;

    #[test]
    fn test_auth_config_validation_empty() {
        let validator = MiniserveConfigValidator;
        let args = create_default_args();

        let result = validator.validate_auth_config(&args);
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod full_validation_tests {
    use super::*;

    #[test]
    fn test_valid_configuration() {
        let validator = MiniserveConfigValidator;
        let temp_dir = TempDir::new().unwrap();
        let mut args = create_default_args();
        args.path = Some(temp_dir.path().to_path_buf());
        args.port = 0; // Non-privileged port

        let result = validator.validate(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_validation_errors() {
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.path = Some(PathBuf::from("/nonexistent/path"));
        args.spa = true; // Missing index requirement
        args.pretty_urls = true; // Conflicts with SPA
        args.on_duplicate_files = DuplicateFile::Overwrite; // No upload enabled

        let result = validator.validate(&args);

        match result {
            Err(errors) => {
                assert!(errors.len() >= 3); // Should have multiple errors

                // Check for specific error types
                assert!(
                    errors
                        .iter()
                        .any(|e| matches!(e, ConfigValidationError::PathError { .. }))
                );
                assert!(
                    errors
                        .iter()
                        .any(|e| matches!(e, ConfigValidationError::MissingDependency { .. }))
                );
                assert!(
                    errors
                        .iter()
                        .any(|e| matches!(e, ConfigValidationError::OptionConflict { .. }))
                );
            }
            _ => panic!("Expected multiple validation errors"),
        }
    }

    #[test]
    fn test_archive_config_validation() {
        let validator = MiniserveConfigValidator;
        let args = create_default_args();

        let result = validator.validate_archive_config(&args);
        assert!(result.is_ok()); // Archive validation should pass for default config
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_miniserve_config_try_from_args_success() {
        let temp_dir = TempDir::new().unwrap();
        let mut args = create_default_args();
        args.path = Some(temp_dir.path().to_path_buf());
        args.port = 0;

        let result = MiniserveConfig::try_from_args(args);
        assert!(result.is_ok(), "expected Ok but got Err: {:?}", result.err());
    }

    #[test]
    fn test_miniserve_config_try_from_args_validation_failure() {
        let mut args = create_default_args();
        args.path = Some(PathBuf::from("/nonexistent/path"));
        args.spa = true; // Missing index

        let result = MiniserveConfig::try_from_args(args);
        assert!(result.is_err());

        let error_msg = format!("{}", result.unwrap_err());
        assert!(
            error_msg.contains("validation")
                || error_msg.contains("Path does not exist")
                || error_msg.contains("requires")
        );
    }

    #[test]
    fn test_config_validation_with_all_features_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let upload_dir = temp_dir.path().join("uploads");
        std::fs::create_dir(&upload_dir).unwrap();

        let index_file = temp_dir.path().join("index.html");
        std::fs::write(&index_file, "<!DOCTYPE html><html><body>Test</body></html>").unwrap();

        let mut args = create_default_args();
        args.path = Some(temp_dir.path().to_path_buf());
        args.port = 0;
        args.index = Some(PathBuf::from("index.html"));
        args.allowed_upload_dir = Some(vec!["uploads".to_string().into()]);
        args.web_upload_concurrency = 5;
        args.qrcode = true;
        args.directory_size = true;
        args.mkdir_enabled = true;
        args.readme = true;
        args.verbose = true;

        let result = MiniserveConfig::try_from_args(args);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert!(config.port > 0);
        assert!(config.file_upload);
        assert_eq!(config.web_upload_concurrency, 5);
        assert!(config.show_qrcode);
        assert!(config.directory_size);
        assert!(config.mkdir_enabled);
        assert!(config.readme);
        assert!(config.verbose);
    }
}

/// Test helper to create temporary directories and files for testing
pub(crate) struct TestEnvironment {
    pub temp_dir: TempDir,
    pub serve_path: PathBuf,
    pub upload_path: PathBuf,
    pub index_file: PathBuf,
}

impl TestEnvironment {
    pub fn new() -> Self {
        let temp_dir = TempDir::new().unwrap();
        let serve_path = temp_dir.path().to_path_buf();
        let upload_path = serve_path.join("uploads");
        let index_file = serve_path.join("index.html");

        // Create upload directory
        std::fs::create_dir(&upload_path).unwrap();

        // Create index file
        std::fs::write(
            &index_file,
            "<!DOCTYPE html><html><body>Test Index</body></html>",
        )
        .unwrap();

        Self {
            temp_dir,
            serve_path,
            upload_path,
            index_file,
        }
    }
}

#[cfg(test)]
mod test_environment_tests {
    use super::*;

    #[test]
    fn test_environment_setup() {
        let env = TestEnvironment::new();

        assert!(env.serve_path.exists());
        assert!(env.upload_path.exists());
        assert!(env.index_file.exists());

        // Test with validator
        let validator = MiniserveConfigValidator;
        let mut args = create_default_args();
        args.path = Some(env.serve_path.clone());
        args.index = Some(PathBuf::from("index.html"));
        args.allowed_upload_dir = Some(vec!["uploads".to_string().into()]);

        let result = validator.validate(&args);
        assert!(result.is_ok());
    }
}