mod core;
mod cache_tests;
mod utils;

pub use self::core::Scanner;
pub use self::cache_tests::CacheTest;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use url::Url;
use std::time::Duration;

#[async_trait]
pub trait ScannerTrait {
    async fn scan(&self, target: &str) -> Result<ScanResult>;
    async fn test_cache_poisoning(&self, url: &Url) -> Result<Vec<Vulnerability>>;
    async fn test_cache_deception(&self, url: &Url) -> Result<Vec<Vulnerability>>;
    async fn test_cache_timing(&self, url: &Url) -> Result<Vec<Vulnerability>>;
    async fn test_cache_key_manipulation(&self, url: &Url) -> Result<Vec<Vulnerability>>;
    async fn test_cache_probing(&self, url: &Url) -> Result<Vec<Vulnerability>>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan_duration: Duration,
    pub requests_sent: usize,
    pub scan_timestamp: chrono::DateTime<chrono::Utc>,
    pub scanner_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vulnerability {
    pub vulnerability_type: VulnerabilityType,
    pub url: String,
    pub description: String,
    pub severity: Severity,
    pub proof_of_concept: String,
    pub remediation: String,
    pub discovered_at: chrono::DateTime<chrono::Utc>,
    pub cvss_score: Option<f32>,
    pub references: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum VulnerabilityType {
    CachePoisoning,
    CacheDeception,
    CacheTiming,
    CacheKeyManipulation,
    CacheProbing,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }

    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s >= 0.1 => Severity::Low,
            _ => Severity::Info,
        }
    }
}

impl std::fmt::Display for VulnerabilityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilityType::CachePoisoning => write!(f, "Cache Poisoning"),
            VulnerabilityType::CacheDeception => write!(f, "Cache Deception"),
            VulnerabilityType::CacheTiming => write!(f, "Cache Timing"),
            VulnerabilityType::CacheKeyManipulation => write!(f, "Cache Key Manipulation"),
            VulnerabilityType::CacheProbing => write!(f, "Cache Probing"),
        }
    }
} 