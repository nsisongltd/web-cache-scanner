use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub scan: ScanConfig,
    pub http: HttpConfig,
    pub reporting: ReportingConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanConfig {
    pub threads: usize,
    pub timeout: u64,
    pub follow_redirects: bool,
    pub max_redirects: u32,
    pub verify_ssl: bool,
    pub rate_limit: Option<u32>,
    pub depth: u32,
    pub passive: bool,
    pub paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub wordlists: WordlistConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpConfig {
    pub headers: Vec<String>,
    pub cookies: Vec<String>,
    pub user_agent: Option<String>,
    pub proxy: Option<String>,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WordlistConfig {
    pub paths: Option<String>,
    pub parameters: Option<String>,
    pub headers: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportingConfig {
    pub format: String,
    pub output_dir: String,
    pub include_evidence: bool,
    pub include_references: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanConfig {
                threads: 10,
                timeout: 30,
                follow_redirects: true,
                max_redirects: 10,
                verify_ssl: true,
                rate_limit: Some(50),
                depth: 2,
                passive: false,
                paths: vec![],
                exclude_paths: vec![],
                wordlists: WordlistConfig {
                    paths: None,
                    parameters: None,
                    headers: None,
                },
            },
            http: HttpConfig {
                headers: vec![],
                cookies: vec![],
                user_agent: Some("Web-Cache-Scanner/1.0 (Nsisong Labs)".to_string()),
                proxy: None,
                auth: None,
            },
            reporting: ReportingConfig {
                format: "html".to_string(),
                output_dir: "reports".to_string(),
                include_evidence: true,
                include_references: true,
            },
        }
    }
}

pub fn validate_config(path: &Path) -> Result<Config> {
    let content = fs::read_to_string(path)?;
    let config: Config = serde_yaml::from_str(&content)?;

    // Validate threads
    if config.scan.threads == 0 {
        anyhow::bail!("Number of threads must be greater than 0");
    }

    // Validate timeout
    if config.scan.timeout == 0 {
        anyhow::bail!("Timeout must be greater than 0");
    }

    // Validate rate limit
    if let Some(rate) = config.scan.rate_limit {
        if rate == 0 {
            anyhow::bail!("Rate limit must be greater than 0");
        }
    }

    // Validate depth
    if config.scan.depth == 0 {
        anyhow::bail!("Scan depth must be greater than 0");
    }

    // Validate wordlists
    if let Some(path) = &config.scan.wordlists.paths {
        if !Path::new(path).exists() {
            anyhow::bail!("Paths wordlist file does not exist: {}", path);
        }
    }
    if let Some(path) = &config.scan.wordlists.parameters {
        if !Path::new(path).exists() {
            anyhow::bail!("Parameters wordlist file does not exist: {}", path);
        }
    }
    if let Some(path) = &config.scan.wordlists.headers {
        if !Path::new(path).exists() {
            anyhow::bail!("Headers wordlist file does not exist: {}", path);
        }
    }

    // Validate proxy URL if present
    if let Some(proxy) = &config.http.proxy {
        url::Url::parse(proxy)?;
    }

    // Validate output format
    match config.reporting.format.to_lowercase().as_str() {
        "json" | "html" | "markdown" => {}
        _ => anyhow::bail!("Unsupported output format: {}", config.reporting.format),
    }

    Ok(config)
}

pub fn generate_sample_config(path: &Path) -> Result<()> {
    let config = Config::default();
    let yaml = serde_yaml::to_string(&config)?;
    fs::write(path, yaml)?;
    Ok(())
} 