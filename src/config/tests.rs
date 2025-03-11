use super::*;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_default_config() {
    let config = Config::default();
    assert_eq!(config.scan.threads, 10);
    assert_eq!(config.scan.timeout, 30);
    assert_eq!(config.scan.max_redirects, 5);
    assert!(config.scan.verify_ssl);
    assert_eq!(config.scan.rate_limit, 100);
    assert_eq!(config.scan.depth, 3);
    assert!(!config.scan.passive);
}

#[test]
fn test_config_validation() {
    let config = Config {
        scan: ScanConfig {
            threads: 0,
            timeout: 0,
            max_redirects: 0,
            verify_ssl: true,
            rate_limit: 0,
            depth: 0,
            passive: false,
            paths: vec![],
            exclude_paths: vec![],
            wordlists: vec![],
        },
        http: HttpConfig::default(),
        reporting: ReportingConfig::default(),
    };

    let result = validate_config(&config);
    assert!(result.is_err());
}

#[test]
fn test_config_serialization() {
    let config = Config::default();
    let yaml = serde_yaml::to_string(&config).unwrap();
    let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(config.scan.threads, deserialized.scan.threads);
    assert_eq!(config.scan.timeout, deserialized.scan.timeout);
    assert_eq!(config.scan.max_redirects, deserialized.scan.max_redirects);
}

#[test]
fn test_generate_sample_config() {
    let temp_file = NamedTempFile::new().unwrap();
    let result = generate_sample_config(temp_file.path().to_str().unwrap());
    assert!(result.is_ok());

    let contents = fs::read_to_string(temp_file.path()).unwrap();
    let config: Config = serde_yaml::from_str(&contents).unwrap();
    assert_eq!(config.scan.threads, 10);
    assert_eq!(config.scan.timeout, 30);
    assert_eq!(config.scan.max_redirects, 5);
}

#[test]
fn test_validate_config_file() {
    let temp_file = NamedTempFile::new().unwrap();
    let config = Config::default();
    let yaml = serde_yaml::to_string(&config).unwrap();
    fs::write(temp_file.path(), yaml).unwrap();

    let result = validate_config_file(temp_file.path().to_str().unwrap());
    assert!(result.is_ok());
}

#[test]
fn test_invalid_config_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), "invalid: yaml: content").unwrap();

    let result = validate_config_file(temp_file.path().to_str().unwrap());
    assert!(result.is_err());
}

#[test]
fn test_config_with_custom_settings() {
    let config = Config {
        scan: ScanConfig {
            threads: 20,
            timeout: 60,
            max_redirects: 10,
            verify_ssl: false,
            rate_limit: 200,
            depth: 5,
            passive: true,
            paths: vec!["/api".to_string()],
            exclude_paths: vec!["/admin".to_string()],
            wordlists: vec!["wordlist.txt".to_string()],
        },
        http: HttpConfig {
            headers: vec![("X-Custom".to_string(), "value".to_string())],
            cookies: vec![("session".to_string(), "123".to_string())],
            user_agent: Some("Custom User Agent".to_string()),
            proxy: Some("http://proxy:8080".to_string()),
            auth: Some(AuthConfig {
                username: "user".to_string(),
                password: "pass".to_string(),
            }),
        },
        reporting: ReportingConfig {
            output_format: "json".to_string(),
            output_dir: "reports".to_string(),
            include_evidence: true,
            include_references: true,
        },
    };

    let yaml = serde_yaml::to_string(&config).unwrap();
    let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(config.scan.threads, deserialized.scan.threads);
    assert_eq!(config.http.headers.len(), deserialized.http.headers.len());
    assert_eq!(config.reporting.output_format, deserialized.reporting.output_format);
} 