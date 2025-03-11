use super::*;
use mockito::{mock, Matcher};
use std::time::Duration;

#[tokio::test]
async fn test_client_creation() {
    let client = Client::new()
        .with_timeout(Duration::from_secs(5))
        .with_headers(vec![("X-Test".to_string(), "test".to_string())])
        .with_cookies(vec![("session".to_string(), "123".to_string())])
        .build();

    assert_eq!(client.headers.get("X-Test").unwrap(), "test");
    assert_eq!(client.cookies.get("session").unwrap(), "123");
}

#[tokio::test]
async fn test_get_request() {
    let mut server = mockito::Server::new();
    let mock = mock("GET", "/")
        .with_status(200)
        .with_header("content-type", "text/plain")
        .with_body("test response")
        .create();

    let client = Client::new().build();
    let url = format!("{}/", server.url());
    let response = client.get(&url).await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "test response");
    mock.assert();
}

#[tokio::test]
async fn test_cache_detection() {
    let mut server = mockito::Server::new();
    let mock = mock("GET", "/")
        .with_status(200)
        .with_header("Cache-Control", "public, max-age=3600")
        .with_header("ETag", "W/\"123\"")
        .with_body("test response")
        .create();

    let client = Client::new().build();
    let url = format!("{}/", server.url());
    let response = client.get(&url).await.unwrap();
    let cache_info = client.detect_cache_behavior(&response).await.unwrap();

    assert!(cache_info.is_cached);
    assert_eq!(cache_info.cache_control, Some("public, max-age=3600".to_string()));
    assert_eq!(cache_info.etag, Some("W/\"123\"".to_string()));
    mock.assert();
}

#[tokio::test]
async fn test_cache_testing() {
    let mut server = mockito::Server::new();
    let mock = mock("GET", "/")
        .with_status(200)
        .with_header("Cache-Control", "public, max-age=3600")
        .with_body("test response")
        .create();

    let client = Client::new().build();
    let url = format!("{}/", server.url());
    let cache_info = client.test_cache_headers(&url).await.unwrap();

    assert!(cache_info.is_cached);
    assert_eq!(cache_info.cache_control, Some("public, max-age=3600".to_string()));
    mock.assert();
}

#[tokio::test]
async fn test_timeout() {
    let client = Client::new()
        .with_timeout(Duration::from_millis(100))
        .build();

    let result = client.get("http://httpstat.us/200?sleep=1000").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_redirect_handling() {
    let mut server = mockito::Server::new();
    let mock1 = mock("GET", "/redirect")
        .with_status(301)
        .with_header("Location", "/target")
        .create();
    let mock2 = mock("GET", "/target")
        .with_status(200)
        .with_body("target response")
        .create();

    let client = Client::new()
        .with_follow_redirects(true)
        .with_max_redirects(5)
        .build();

    let url = format!("{}/redirect", server.url());
    let response = client.get(&url).await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "target response");
    mock1.assert();
    mock2.assert();
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

    let client = Client::new().build();
    let url = format!("{}/", server.url());
    let cache_info = client.test_cache_headers(&url).await.unwrap();

    assert!(cache_info.is_cached);
    assert!(cache_info.is_poisoned);
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

    let client = Client::new().build();
    let url = format!("{}/", server.url());
    let cache_info = client.test_cache_headers(&url).await.unwrap();

    assert!(cache_info.is_cached);
    assert!(cache_info.is_deceptive);
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

    let client = Client::new().build();
    let url = format!("{}/", server.url());
    let cache_info = client.test_cache_headers(&url).await.unwrap();

    assert!(cache_info.is_cached);
    assert!(cache_info.is_timing_based);
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

    let client = Client::new().build();
    let url = format!("{}/", server.url());
    let cache_info = client.test_cache_headers(&url).await.unwrap();

    assert!(cache_info.is_cached);
    assert!(cache_info.is_probed);
    mock.assert();
} 