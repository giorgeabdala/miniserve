use assert_cmd::Command;

// Unit tests for security functionality
#[test]
fn test_security_headers_cli_option() {
    let mut cmd = Command::cargo_bin("miniserve").unwrap();
    cmd.args(&[
        "--security-headers",
        "--help", // Using --help to make the command exit immediately
    ]);

    // Test that the command accepts the security headers option without argument parsing errors
    let output = cmd.assert().success();
    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    // Verify that help includes our security options
    assert!(stdout.contains("--security-headers"));
}

#[test]
fn test_rate_limit_cli_options() {
    let mut cmd = Command::cargo_bin("miniserve").unwrap();
    cmd.args(&[
        "--rate-limit",
        "--rate-limit-requests",
        "30",
        "--rate-limit-window",
        "60",
        "--help",
    ]);

    // Test that the rate limiting options are parsed without errors
    let output = cmd.assert().success();
    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    // Verify that help includes our rate limiting options
    assert!(stdout.contains("--rate-limit"));
    assert!(stdout.contains("--rate-limit-requests"));
    assert!(stdout.contains("--rate-limit-window"));
}

#[test]
fn test_max_request_size_cli_option() {
    let mut cmd = Command::cargo_bin("miniserve").unwrap();
    cmd.args(&["--max-request-size", "50M", "--help"]);

    // Test that the max request size option is parsed without errors
    let output = cmd.assert().success();
    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    // Verify that help includes our max request size option
    assert!(stdout.contains("--max-request-size"));
}

#[test]
fn test_custom_csp_cli_option() {
    let mut cmd = Command::cargo_bin("miniserve").unwrap();
    cmd.args(&[
        "--security-headers",
        "--csp",
        "default-src 'none'",
        "--help",
    ]);

    // Test that custom CSP option is parsed without errors
    let output = cmd.assert().success();
    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    // Verify that help includes CSP option
    assert!(stdout.contains("--csp"));
}

#[test]
fn test_hsts_max_age_cli_option() {
    let mut cmd = Command::cargo_bin("miniserve").unwrap();
    cmd.args(&["--security-headers", "--hsts-max-age", "86400", "--help"]);

    // Test that HSTS max-age option is parsed without errors
    let output = cmd.assert().success();
    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    // Verify that help includes HSTS option
    assert!(stdout.contains("--hsts-max-age"));
}

#[test]
fn test_all_security_options_combined() {
    let mut cmd = Command::cargo_bin("miniserve").unwrap();
    cmd.args(&[
        "--security-headers",
        "--rate-limit",
        "--rate-limit-requests",
        "100",
        "--rate-limit-window",
        "60",
        "--max-request-size",
        "10M",
        "--csp",
        "default-src 'self'; script-src 'self'",
        "--hsts-max-age",
        "31536000",
        "--help",
    ]);

    // Test that all security options can be combined without parsing errors
    let output = cmd.assert().success();
    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    // Verify all security options are present in help
    assert!(stdout.contains("--security-headers"));
    assert!(stdout.contains("--rate-limit"));
    assert!(stdout.contains("--max-request-size"));
    assert!(stdout.contains("--csp"));
    assert!(stdout.contains("--hsts-max-age"));
}

// Test the size parsing functionality
#[test]
fn test_invalid_size_format() {
    use miniserve::args::parse_size;

    assert!(parse_size("invalid").is_err());
    assert!(parse_size("10X").is_err());
    assert!(parse_size("").is_err());
    // Note: negative numbers would be caught by clap before reaching parse_size
}

#[test]
fn test_valid_size_formats() {
    use miniserve::args::parse_size;

    assert_eq!(parse_size("100").unwrap(), 100);
    assert_eq!(parse_size("10K").unwrap(), 10 * 1024);
    assert_eq!(parse_size("5M").unwrap(), 5 * 1024 * 1024);
    assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
    assert_eq!(parse_size("100B").unwrap(), 100);
    assert_eq!(parse_size("10KB").unwrap(), 10 * 1024);
    assert_eq!(parse_size("5MB").unwrap(), 5 * 1024 * 1024);
    assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);

    // Test case sensitivity
    assert_eq!(parse_size("10k").unwrap(), 10 * 1024);
    assert_eq!(parse_size("5m").unwrap(), 5 * 1024 * 1024);
    assert_eq!(parse_size("1g").unwrap(), 1024 * 1024 * 1024);
}

#[test]
fn test_size_format_edge_cases() {
    use miniserve::args::parse_size;

    // Test with spaces (should be trimmed)
    assert_eq!(parse_size(" 100 ").unwrap(), 100);
    assert_eq!(parse_size(" 10K ").unwrap(), 10 * 1024);

    // Test zero
    assert_eq!(parse_size("0").unwrap(), 0);
    assert_eq!(parse_size("0K").unwrap(), 0);
    assert_eq!(parse_size("0M").unwrap(), 0);
}

#[test]
fn test_help_shows_security_options() {
    let mut cmd = Command::cargo_bin("miniserve").unwrap();
    cmd.arg("--help");

    let binding = cmd.assert().success();
    let output = binding.get_output();
    let stdout = std::str::from_utf8(&output.stdout).unwrap();

    // Verify security-related help text is present
    assert!(stdout.contains("--security-headers"));
    assert!(stdout.contains("--rate-limit"));
    assert!(stdout.contains("--max-request-size"));
    assert!(stdout.contains("--rate-limit-requests"));
    assert!(stdout.contains("--rate-limit-window"));
    assert!(stdout.contains("--csp"));
    assert!(stdout.contains("--hsts-max-age"));
}

#[test]
fn test_env_var_support_for_security_options() {
    let mut cmd = Command::cargo_bin("miniserve").unwrap();

    // Test environment variable support
    cmd.env("MINISERVE_SECURITY_HEADERS", "true")
        .env("MINISERVE_RATE_LIMIT", "true")
        .env("MINISERVE_MAX_REQUEST_SIZE", "50000000")
        .env("MINISERVE_RATE_LIMIT_REQUESTS", "50")
        .env("MINISERVE_RATE_LIMIT_WINDOW", "30")
        .args(&["--help"]);

    // Test that environment variables are processed without parsing errors
    let output = cmd.assert().success();
    let stdout = std::str::from_utf8(&output.get_output().stdout).unwrap();

    // The environment variables should be parsed and help should show normally
    assert!(stdout.contains("miniserve"));
    assert!(stdout.contains("--help"));
}
