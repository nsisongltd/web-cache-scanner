use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "wcvs")]
#[command(author = "Nsisong Labs <contact@nsisonglabs.com>")]
#[command(version)]
#[command(about = "Advanced Web Cache Vulnerability Scanner", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a target for web cache vulnerabilities
    Scan {
        /// Target URL to scan
        #[arg(required = true)]
        target: String,

        /// Number of concurrent threads
        #[arg(short, long, default_value = "10")]
        threads: usize,

        /// Timeout in seconds for each request
        #[arg(short, long, default_value = "30")]
        timeout: u64,

        /// Custom headers (format: "Header: Value")
        #[arg(short = 'H', long)]
        headers: Vec<String>,

        /// Cookies to include (format: "name=value")
        #[arg(short, long)]
        cookies: Vec<String>,

        /// Follow redirects
        #[arg(short = 'r', long, default_value = "true")]
        follow_redirects: bool,

        /// Maximum number of redirects to follow
        #[arg(short = 'm', long, default_value = "10")]
        max_redirects: u32,

        /// Skip SSL certificate verification
        #[arg(short = 'k', long)]
        insecure: bool,

        /// Output format (json, html, markdown)
        #[arg(short, long, default_value = "html")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Enable debug logging
        #[arg(short, long)]
        debug: bool,

        /// Scan specific paths only
        #[arg(short = 'p', long)]
        paths: Vec<String>,

        /// Exclude paths from scanning
        #[arg(short = 'x', long)]
        exclude: Vec<String>,

        /// Custom wordlist for path discovery
        #[arg(short = 'w', long)]
        wordlist: Option<PathBuf>,

        /// Rate limit (requests per second)
        #[arg(long, default_value = "50")]
        rate_limit: u32,

        /// Proxy URL (e.g., "http://127.0.0.1:8080")
        #[arg(long)]
        proxy: Option<String>,

        /// Basic auth credentials (format: "username:password")
        #[arg(long)]
        auth: Option<String>,

        /// Scan depth for crawling
        #[arg(long, default_value = "2")]
        depth: u32,

        /// Enable passive scan mode
        #[arg(long)]
        passive: bool,

        /// Custom user agent
        #[arg(long)]
        user_agent: Option<String>,
    },

    /// Validate configuration file
    ValidateConfig {
        /// Path to configuration file
        #[arg(required = true)]
        config: PathBuf,
    },

    /// Generate a sample configuration file
    GenerateConfig {
        /// Output path for configuration file
        #[arg(required = true)]
        output: PathBuf,
    },
} 