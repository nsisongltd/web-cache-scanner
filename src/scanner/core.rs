use std::time::Instant;
use anyhow::{Result, Context};
use async_trait::async_trait;
use tokio::time::timeout;
use tracing::{info, warn, error, debug};
use url::Url;
use std::sync::Arc;
use tokio::sync::Semaphore;
use futures::future::join_all;

use super::{
    ScannerTrait,
    ScanResult,
    Vulnerability,
    cache_tests::CacheTest,
};
use crate::http::Client;

pub struct Scanner {
    client: Client,
    threads: usize,
    timeout: std::time::Duration,
    cache_test: CacheTest,
    semaphore: Arc<Semaphore>,
}

impl Scanner {
    pub fn new(
        threads: usize,
        timeout_secs: u64,
        headers: Vec<String>,
        cookies: Vec<String>,
        follow_redirects: bool,
        max_redirects: u32,
        verify_ssl: bool,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .follow_redirects(follow_redirects)
            .max_redirects(max_redirects)
            .verify_ssl(verify_ssl)
            .add_headers(headers)?
            .add_cookies(cookies)
            .build()?;

        Ok(Self {
            client: client.clone(),
            threads,
            timeout: std::time::Duration::from_secs(timeout_secs),
            cache_test: CacheTest::new(client),
            semaphore: Arc::new(Semaphore::new(threads)),
        })
    }

    async fn validate_target(&self, target: &str) -> Result<Url> {
        let url = Url::parse(target)
            .with_context(|| format!("Invalid URL provided: {}", target))?;
        
        if !url.scheme().starts_with("http") {
            anyhow::bail!("Only HTTP/HTTPS URLs are supported");
        }

        // Test if the target is reachable
        let response = timeout(
            self.timeout,
            self.client.get(url.as_str())
        ).await
            .with_context(|| "Connection timed out")?
            .with_context(|| "Failed to connect to target")?;

        if !response.status().is_success() {
            warn!("Target returned non-200 status code: {}", response.status());
        }

        Ok(url)
    }

    async fn run_test<F, Fut>(&self, url: &Url, test_fn: F) -> Result<Vec<Vulnerability>>
    where
        F: Fn(&CacheTest, &Url) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<Vulnerability>>>,
    {
        let permit = self.semaphore.acquire().await?;
        let result = test_fn(&self.cache_test, url).await;
        drop(permit);
        result
    }
}

#[async_trait]
impl ScannerTrait for Scanner {
    async fn scan(&self, target: &str) -> Result<ScanResult> {
        info!("Starting scan of target: {}", target);
        let start_time = Instant::now();
        let mut requests_sent = 0;

        // Validate target URL
        let url = self.validate_target(target).await?;
        requests_sent += 1;

        // Initialize results vector
        let mut vulnerabilities = Vec::new();

        // Run all tests concurrently
        let test_futures = vec![
            self.run_test(&url, |ct, u| ct.test_cache_poisoning(u)),
            self.run_test(&url, |ct, u| ct.test_cache_deception(u)),
            self.run_test(&url, |ct, u| ct.test_cache_timing(u)),
            self.run_test(&url, |ct, u| ct.test_cache_key_manipulation(u)),
            self.run_test(&url, |ct, u| ct.test_cache_probing(u)),
        ];

        let results = join_all(test_futures).await;
        for result in results {
            match result {
                Ok(mut vulns) => vulnerabilities.append(&mut vulns),
                Err(e) => error!("Test failed: {}", e),
            }
        }

        let scan_duration = start_time.elapsed();
        info!("Scan completed in {:?}", scan_duration);
        debug!("Found {} vulnerabilities", vulnerabilities.len());

        Ok(ScanResult {
            target: target.to_string(),
            vulnerabilities,
            scan_duration,
            requests_sent,
            scan_timestamp: chrono::Utc::now(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }

    async fn test_cache_poisoning(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        self.run_test(url, |ct, u| ct.test_cache_poisoning(u)).await
    }

    async fn test_cache_deception(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        self.run_test(url, |ct, u| ct.test_cache_deception(u)).await
    }

    async fn test_cache_timing(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        self.run_test(url, |ct, u| ct.test_cache_timing(u)).await
    }

    async fn test_cache_key_manipulation(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        self.run_test(url, |ct, u| ct.test_cache_key_manipulation(u)).await
    }

    async fn test_cache_probing(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        self.run_test(url, |ct, u| ct.test_cache_probing(u)).await
    }
} 