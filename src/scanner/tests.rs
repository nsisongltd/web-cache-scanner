use super::*;
use mockito::{mock, Matcher};
use std::time::Duration;

#[tokio::test]
async fn test_scanner_creation() {
    let scanner = Scanner::new(
        10,
        Duration::from_secs(30),
        vec![("X-Test".to_string(), "test".to_string())],
        vec![("session".to_string(), "123".to_string())],
        true,
        5,
        true,
    );

    assert_eq!(scanner.threads, 10);
    assert_eq!(scanner.timeout, Duration::from_secs(30));
}

#[tokio::test]
async fn test_target_validation() {
    let mut server = mockito::Server::new();
    let mock = mock("GET", "/")
        .with_status(200)
        .with_header("content-type", "text/plain")
        .with_body("test response")
        .create();

    let scanner = Scanner::new(
        10,
        Duration::from_secs(30),
        vec![],
        vec![],
        true,
        5,
        true,
    );

    let url = format!("{}/", server.url());
    let result = scanner.validate_target(&url).await;
    assert!(result.is_ok());
    mock.assert();
}

#[tokio::test]
async fn test_target_validation_failure() {
    let scanner = Scanner::new(
        10,
        Duration::from_secs(30),
        vec![],
        vec![],
        true,
        5,
        true,
    );

    let result = scanner.validate_target("http://invalid-url-that-does-not-exist.com").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_cache_poisoning_detection() {
    let mut server = mockito::Server::new();
    let mock = mock("GET", "/")
        .with_status(200)
        .with_header("Cache-Control", "public, max-age=3600")
        .with_header("X-Cache", "HIT")
        .with_body("test response")
        .create();

    let scanner = Scanner::new(
        10,
        Duration::from_secs(30),
        vec![],
        vec![],
        true,
        5,
        true,
    );

    let url = format!("{}/", server.url());
    let result = scanner.run_test(&url, CacheTest::Poisoning).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_poisoned);
    mock.assert();
}

#[tokio::test]
async fn test_cache_deception_detection() {
    let mut server = mockito::Server::new();
    let mock = mock("GET", "/")
        .with_status(200)
        .with_header("Cache-Control", "public, max-age=3600")
        .with_header("X-Cache", "HIT")
        .with_body("test response")
        .create();

    let scanner = Scanner::new(
        10,
        Duration::from_secs(30),
        vec![],
        vec![],
        true,
        5,
        true,
    );

    let url = format!("{}/", server.url());
    let result = scanner.run_test(&url, CacheTest::Deception).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_deceptive);
    mock.assert();
}

#[tokio::test]
async fn test_cache_timing_detection() {
    let mut server = mockito::Server::new();
    let mock = mock("GET", "/")
        .with_status(200)
        .with_header("Cache-Control", "public, max-age=3600")
        .with_body("test response")
        .create();

    let scanner = Scanner::new(
        10,
        Duration::from_secs(30),
        vec![],
        vec![],
        true,
        5,
        true,
    );

    let url = format!("{}/", server.url());
    let result = scanner.run_test(&url, CacheTest::Timing).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_timing_based);
    mock.assert();
}

#[tokio::test]
async fn test_cache_probing_detection() {
    let mut server = mockito::Server::new();
    let mock = mock("GET", "/")
        .with_status(200)
        .with_header("Cache-Control", "public, max-age=3600")
        .with_body("test response")
        .create();

    let scanner = Scanner::new(
        10,
        Duration::from_secs(30),
        vec![],
        vec![],
        true,
        5,
        true,
    );

    let url = format!("{}/", server.url());
    let result = scanner.run_test(&url, CacheTest::Probing).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_probed);
    mock.assert();
}

#[tokio::test]
async fn test_concurrent_scanning() {
    let mut server = mockito::Server::new();
    let mock = mock("GET", "/")
        .with_status(200)
        .with_header("Cache-Control", "public, max-age=3600")
        .with_body("test response")
        .create();

    let scanner = Scanner::new(
        10,
        Duration::from_secs(30),
        vec![],
        vec![],
        true,
        5,
        true,
    );

    let url = format!("{}/", server.url());
    let results = scanner.run_tests(&url).await;
    assert!(results.is_ok());
    assert!(!results.unwrap().is_empty());
    mock.assert();
}

#[tokio::test]
async fn test_full_scan() {
    let mut server = mockito::Server::new();
    let mock = mock("GET", "/")
        .with_status(200)
        .with_header("Cache-Control", "public, max-age=3600")
        .with_body("test response")
        .create();

    let scanner = Scanner::new(
        10,
        Duration::from_secs(30),
        vec![],
        vec![],
        true,
        5,
        true,
    );

    let url = format!("{}/", server.url());
    let result = scanner.scan(&url).await;
    assert!(result.is_ok());
    assert!(!result.unwrap().vulnerabilities.is_empty());
    mock.assert();
} 