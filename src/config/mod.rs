use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use anyhow::Result;

pub mod tests;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub scan: ScanConfig,
    pub http: HttpConfig,
    pub reporting: ReportingConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanConfig {
    pub threads: usize,
    pub timeout: u64,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
    pub rate_limit: u32,
    pub depth: usize,
    pub passive: bool,
    pub paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub wordlists: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpConfig {
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub user_agent: Option<String>,
    pub proxy: Option<String>,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReportingConfig {
    pub output_format: String,
    pub output_dir: String,
    pub include_evidence: bool,
    pub include_references: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            scan: ScanConfig {
                threads: 10,
                timeout: 30,
                follow_redirects: true,
                max_redirects: 5,
                verify_ssl: true,
                rate_limit: 100,
                depth: 3,
                passive: false,
                paths: vec![],
                exclude_paths: vec![],
                wordlists: vec![],
            },
            http: HttpConfig {
                headers: vec![],
                cookies: vec![],
                user_agent: Some("Web Cache Vulnerability Scanner/1.0".to_string()),
                proxy: None,
                auth: None,
            },
            reporting: ReportingConfig {
                output_format: "json".to_string(),
                output_dir: "reports".to_string(),
                include_evidence: true,
                include_references: true,
            },
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            headers: vec![],
            cookies: vec![],
            user_agent: Some("Web Cache Vulnerability Scanner/1.0".to_string()),
            proxy: None,
            auth: None,
        }
    }
}

impl Default for ReportingConfig {
    fn default() -> Self {
        ReportingConfig {
            output_format: "json".to_string(),
            output_dir: "reports".to_string(),
            include_evidence: true,
            include_references: true,
        }
    }
}

pub fn validate_config(config: &Config) -> Result<()> {
    if config.scan.threads == 0 {
        anyhow::bail!("Number of threads must be greater than 0");
    }
    if config.scan.timeout == 0 {
        anyhow::bail!("Timeout must be greater than 0");
    }
    if config.scan.max_redirects == 0 {
        anyhow::bail!("Maximum redirects must be greater than 0");
    }
    if config.scan.rate_limit == 0 {
        anyhow::bail!("Rate limit must be greater than 0");
    }
    if config.scan.depth == 0 {
        anyhow::bail!("Depth must be greater than 0");
    }

    if let Some(ref proxy) = config.http.proxy {
        url::Url::parse(proxy)?;
    }

    match config.reporting.output_format.to_lowercase().as_str() {
        "json" | "html" | "markdown" => Ok(()),
        _ => anyhow::bail!("Unsupported output format"),
    }
}

pub fn validate_config_file(path: &str) -> Result<()> {
    let contents = fs::read_to_string(path)?;
    let config: Config = serde_yaml::from_str(&contents)?;
    validate_config(&config)
}

pub fn generate_sample_config(path: &str) -> Result<()> {
    let config = Config::default();
    let yaml = serde_yaml::to_string(&config)?;
    fs::write(path, yaml)?;
    Ok(())
} 