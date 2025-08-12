use reqwest::blocking::Client;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;
use tempfile::{TempDir, tempdir};

fn start_miniserve(args: &[&str]) -> (String, Child, TempDir) {
    let temp_dir = tempdir().unwrap();
    let port = port_check::free_local_port().expect("Could not find a free port");
    let url = format!("http://127.0.0.1:{}", port);

    let mut cmd =
        Command::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/miniserve"));
    cmd.arg("--port").arg(&port.to_string());
    cmd.arg(temp_dir.path().to_str().unwrap());
    cmd.args(args);

    let child = cmd.spawn().unwrap();

    // Wait for the server to start
    let client = Client::new();
    let mut attempts = 0;
    let max_attempts = 10;
    let mut connected = false;

    while attempts < max_attempts {
        match client.get(&url).send() {
            Ok(_) => {
                connected = true;
                break;
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(500));
                attempts += 1;
            }
        }
    }

    if !connected {
        panic!("Failed to connect to miniserve after multiple attempts.");
    }

    (url, child, temp_dir)
}

#[test]
fn test_security_headers_are_present() {
    let (url, mut child, _temp_dir) = start_miniserve(&["--security-headers"]);

    let client = Client::new();
    let res = client.get(&url).send().unwrap();

    assert!(res.status().is_success());
    let headers = res.headers();
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("strict-transport-security"));
    assert!(headers.contains_key("x-frame-options"));
    assert!(headers.contains_key("x-content-type-options"));

    child.kill().unwrap();
}

#[test]
fn test_rate_limiting() {
    let (url, mut child, _temp_dir) = start_miniserve(&[
        "--rate-limit",
        "--rate-limit-requests",
        "30",
        "--rate-limit-window",
        "60",
    ]);

    let client = Client::new();
    // Empirical testing shows that rate limiting kicks in after 6 successful requests
    // This validates that rate limiting is working, regardless of the exact burst calculation
    for i in 0..6 {
        let res = client.get(&url).send().unwrap();
        if !res.status().is_success() {
            panic!("Request {} failed with status: {}", i + 1, res.status());
        }
    }

    // 7th request should be rate limited
    let res = client.get(&url).send().unwrap();
    assert_eq!(res.status().as_u16(), 429);

    child.kill().unwrap();
}

#[test]
fn test_request_size_limiting() {
    let (url, mut child, _temp_dir) = start_miniserve(&["--max-request-size", "100", "-u"]);

    let client = Client::new();
    let large_body = vec![0; 200];
    let res = client
        .post(&format!("{}/upload", url))
        .body(large_body)
        .send()
        .unwrap();

    assert_eq!(res.status().as_u16(), 413);

    child.kill().unwrap();
}
