use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use url::Url;
use tracing::{debug, info};
use tokio::time::Duration;

use super::{Vulnerability, VulnerabilityType, Severity};
use crate::http::{Client, CacheBehavior};

pub struct CacheTest {
    client: Client,
}

impl CacheTest {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn test_cache_poisoning(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        info!("Testing for cache poisoning vulnerabilities...");
        let mut vulnerabilities = Vec::new();

        // Test 1: Unkeyed header injection
        if let Some(vuln) = self.test_unkeyed_headers(url).await? {
            vulnerabilities.push(vuln);
        }

        // Test 2: Parameter cloaking
        if let Some(vuln) = self.test_parameter_cloaking(url).await? {
            vulnerabilities.push(vuln);
        }

        // Test 3: Cache key manipulation
        if let Some(vuln) = self.test_cache_key_manipulation(url).await? {
            vulnerabilities.push(vuln);
        }

        debug!("Found {} cache poisoning vulnerabilities", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    async fn test_unkeyed_headers(&self, url: &Url) -> Result<Option<Vulnerability>> {
        let test_headers = vec![
            "X-Forwarded-Host",
            "X-Forwarded-Proto",
            "X-Host",
            "X-Forwarded-Server",
            "X-HTTP-Host-Override",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Custom-IP-Authorization",
        ];

        for header in test_headers {
            let mut headers = HeaderMap::new();
            headers.insert(
                HeaderName::from_bytes(header.to_lowercase().as_bytes())?,
                HeaderValue::from_static("evil-domain.com"),
            );

            let response = self.client.get_with_headers(url.as_str(), headers).await?;
            
            // Check if the response reflects our injected value
            if let Ok(body) = response.text().await {
                if body.contains("evil-domain.com") {
                    return Ok(Some(Vulnerability {
                        vulnerability_type: VulnerabilityType::CachePoisoning,
                        url: url.to_string(),
                        description: format!("Unkeyed header {} is reflected in the response", header),
                        severity: Severity::High,
                        proof_of_concept: format!("curl -H '{}: evil-domain.com' {}", header, url),
                        remediation: "Configure cache to key on this header or strip it before caching".to_string(),
                        discovered_at: chrono::Utc::now(),
                        cvss_score: Some(7.5),
                        references: vec![
                            "https://portswigger.net/research/practical-web-cache-poisoning".to_string(),
                            "https://cwe.mitre.org/data/definitions/444.html".to_string(),
                        ],
                    }));
                }
            }
        }

        Ok(None)
    }

    async fn test_parameter_cloaking(&self, url: &Url) -> Result<Option<Vulnerability>> {
        let test_cases = vec![
            "?param=normal&param=evil",
            "?param=normal%0d%0aparam=evil",
            "?param=normal%0aparam=evil",
            "?param=normal%23param=evil",
            "?param=normal%0dparam=evil",
            "?param=normal%0a%0dparam=evil",
        ];

        for test_case in test_cases {
            let test_url = format!("{}{}", url, test_case);
            let response = self.client.get(&test_url).await?;

            if let Ok(body) = response.text().await {
                if body.contains("evil") {
                    return Ok(Some(Vulnerability {
                        vulnerability_type: VulnerabilityType::CachePoisoning,
                        url: url.to_string(),
                        description: "Parameter cloaking vulnerability detected".to_string(),
                        severity: Severity::High,
                        proof_of_concept: format!("curl '{}'", test_url),
                        remediation: "Normalize parameters before caching and validate parameter encoding".to_string(),
                        discovered_at: chrono::Utc::now(),
                        cvss_score: Some(7.0),
                        references: vec![
                            "https://portswigger.net/research/web-cache-entanglement".to_string(),
                            "https://cwe.mitre.org/data/definitions/444.html".to_string(),
                        ],
                    }));
                }
            }
        }

        Ok(None)
    }

    pub async fn test_cache_deception(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        info!("Testing for cache deception vulnerabilities...");
        let mut vulnerabilities = Vec::new();

        // Test path confusion
        if let Some(vuln) = self.test_path_confusion(url).await? {
            vulnerabilities.push(vuln);
        }

        // Test content type confusion
        if let Some(vuln) = self.test_content_type_confusion(url).await? {
            vulnerabilities.push(vuln);
        }

        debug!("Found {} cache deception vulnerabilities", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    async fn test_path_confusion(&self, url: &Url) -> Result<Option<Vulnerability>> {
        let test_paths = vec![
            "/static/../private/data",
            "/static/%2e%2e/private/data",
            "/static/..%2fprivate/data",
            "/static/%252e%252e/private/data",
            "/.%2e/private/data",
        ];

        for path in test_paths {
            let mut test_url = url.clone();
            test_url.set_path(path);

            let response = self.client.get(test_url.as_str()).await?;
            
            if response.status().is_success() {
                return Ok(Some(Vulnerability {
                    vulnerability_type: VulnerabilityType::CacheDeception,
                    url: url.to_string(),
                    description: "Path confusion vulnerability detected".to_string(),
                    severity: Severity::High,
                    proof_of_concept: format!("curl '{}'", test_url),
                    remediation: "Normalize paths before caching and implement strict path validation".to_string(),
                    discovered_at: chrono::Utc::now(),
                    cvss_score: Some(6.5),
                    references: vec![
                        "https://portswigger.net/research/web-cache-deception-attack".to_string(),
                        "https://cwe.mitre.org/data/definitions/526.html".to_string(),
                    ],
                }));
            }
        }

        Ok(None)
    }

    async fn test_content_type_confusion(&self, url: &Url) -> Result<Option<Vulnerability>> {
        let test_extensions = vec![
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".gif",
        ];

        for ext in test_extensions {
            let mut test_url = url.clone();
            let new_path = format!("{}{}", test_url.path(), ext);
            test_url.set_path(&new_path);

            let response = self.client.get(test_url.as_str()).await?;
            
            if response.status().is_success() {
                let content_type = response.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                if !content_type.contains(ext.trim_start_matches('.')) {
                    return Ok(Some(Vulnerability {
                        vulnerability_type: VulnerabilityType::CacheDeception,
                        url: url.to_string(),
                        description: format!("Content-Type confusion with {} extension", ext),
                        severity: Severity::Medium,
                        proof_of_concept: format!("curl '{}'", test_url),
                        remediation: "Ensure proper content type validation and caching rules".to_string(),
                        discovered_at: chrono::Utc::now(),
                        cvss_score: Some(5.5),
                        references: vec![
                            "https://portswigger.net/research/web-cache-deception-attack".to_string(),
                        ],
                    }));
                }
            }
        }

        Ok(None)
    }

    pub async fn test_cache_timing(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        info!("Testing for cache timing vulnerabilities...");
        let mut vulnerabilities = Vec::new();

        // Test cache timing differences
        if let Some(vuln) = self.test_timing_differences(url).await? {
            vulnerabilities.push(vuln);
        }

        debug!("Found {} cache timing vulnerabilities", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    async fn test_timing_differences(&self, url: &Url) -> Result<Option<Vulnerability>> {
        const SAMPLE_SIZE: usize = 10;
        let mut cached_times = Vec::with_capacity(SAMPLE_SIZE);
        let mut uncached_times = Vec::with_capacity(SAMPLE_SIZE);

        // Test cached responses
        for _ in 0..SAMPLE_SIZE {
            let start = std::time::Instant::now();
            let _ = self.client.get(url.as_str()).await?;
            cached_times.push(start.elapsed());
        }

        // Test uncached responses with cache-busting parameter
        for i in 0..SAMPLE_SIZE {
            let mut test_url = url.clone();
            test_url.set_query(Some(&format!("cb={}", i)));
            
            let start = std::time::Instant::now();
            let _ = self.client.get(test_url.as_str()).await?;
            uncached_times.push(start.elapsed());
        }

        // Calculate average times
        let avg_cached: u128 = cached_times.iter().map(|d| d.as_micros()).sum::<u128>() / SAMPLE_SIZE as u128;
        let avg_uncached: u128 = uncached_times.iter().map(|d| d.as_micros()).sum::<u128>() / SAMPLE_SIZE as u128;

        // If there's a significant difference (>50%), might indicate cache timing vulnerability
        if (avg_cached as f64 / avg_uncached as f64) < 0.5 {
            return Ok(Some(Vulnerability {
                vulnerability_type: VulnerabilityType::CacheTiming,
                url: url.to_string(),
                description: format!(
                    "Significant timing difference detected between cached ({} µs) and uncached ({} µs) responses",
                    avg_cached, avg_uncached
                ),
                severity: Severity::Medium,
                proof_of_concept: format!("Compare timing: curl '{}' vs curl '{}?cb=1'", url, url),
                remediation: "Implement consistent response times regardless of cache status".to_string(),
                discovered_at: chrono::Utc::now(),
                cvss_score: Some(4.3),
                references: vec![
                    "https://portswigger.net/research/web-cache-entanglement".to_string(),
                ],
            }));
        }

        Ok(None)
    }

    pub async fn test_cache_key_manipulation(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        info!("Testing for cache key manipulation vulnerabilities...");
        let mut vulnerabilities = Vec::new();

        // Test various cache key manipulation techniques
        let test_cases = vec![
            ("Cache-Key Override", "X-Cache-Key", "custom-key"),
            ("Cache-Control Override", "Cache-Control", "max-age=0"),
            ("Vary Override", "Vary", "*"),
        ];

        for (name, header, value) in test_cases {
            let mut headers = HeaderMap::new();
            headers.insert(header, HeaderValue::from_str(value)?);

            let response = self.client.get_with_headers(url.as_str(), headers).await?;
            let cache_behavior = self.client.detect_cache_behavior(url.as_str()).await?;

            if cache_behavior == CacheBehavior::Cached {
                vulnerabilities.push(Vulnerability {
                    vulnerability_type: VulnerabilityType::CacheKeyManipulation,
                    url: url.to_string(),
                    description: format!("{} vulnerability detected", name),
                    severity: Severity::High,
                    proof_of_concept: format!("curl -H '{}: {}' {}", header, value, url),
                    remediation: "Implement proper cache key generation and validation".to_string(),
                    discovered_at: chrono::Utc::now(),
                    cvss_score: Some(6.8),
                    references: vec![
                        "https://portswigger.net/research/practical-web-cache-poisoning".to_string(),
                    ],
                });
            }
        }

        debug!("Found {} cache key manipulation vulnerabilities", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    pub async fn test_cache_probing(&self, url: &Url) -> Result<Vec<Vulnerability>> {
        info!("Testing for cache probing vulnerabilities...");
        let mut vulnerabilities = Vec::new();

        // Test various cache probing techniques
        let probing_paths = vec![
            "/admin",
            "/api",
            "/internal",
            "/private",
            "/config",
        ];

        for path in probing_paths {
            let mut test_url = url.clone();
            test_url.set_path(path);

            let response = self.client.get(test_url.as_str()).await?;
            let cache_behavior = self.client.detect_cache_behavior(test_url.as_str()).await?;

            if response.status().is_success() && cache_behavior == CacheBehavior::Cached {
                vulnerabilities.push(Vulnerability {
                    vulnerability_type: VulnerabilityType::CacheProbing,
                    url: test_url.to_string(),
                    description: format!("Sensitive path {} is being cached", path),
                    severity: Severity::High,
                    proof_of_concept: format!("curl '{}'", test_url),
                    remediation: "Review and adjust caching rules for sensitive paths".to_string(),
                    discovered_at: chrono::Utc::now(),
                    cvss_score: Some(7.2),
                    references: vec![
                        "https://portswigger.net/research/web-cache-entanglement".to_string(),
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema".to_string(),
                    ],
                });
            }
        }

        debug!("Found {} cache probing vulnerabilities", vulnerabilities.len());
        Ok(vulnerabilities)
    }
} 