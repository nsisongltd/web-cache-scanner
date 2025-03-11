use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use url::Url;

mod config;
mod http;
mod scanner;

use crate::config::{generate_sample_config, validate_config_file};
use crate::scanner::Scanner;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a target for web cache vulnerabilities
    Scan {
        /// Target URL to scan
        #[arg(short, long)]
        target: String,

        /// Number of concurrent threads
        #[arg(short, long, default_value = "10")]
        threads: usize,

        /// Timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,

        /// Configuration file path
        #[arg(short, long)]
        config: Option<String>,

        /// Enable debug logging
        #[arg(short, long)]
        debug: bool,

        /// Output format (json, html, markdown)
        #[arg(short, long, default_value = "json")]
        output: String,

        /// Output directory
        #[arg(short, long, default_value = "reports")]
        dir: String,
    },

    /// Validate a configuration file
    ValidateConfig {
        /// Path to configuration file
        #[arg(short, long)]
        config: String,
    },

    /// Generate a sample configuration file
    GenerateConfig {
        /// Output path for the configuration file
        #[arg(short, long)]
        output: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            threads,
            timeout,
            config,
            debug,
            output,
            dir,
        } => {
            // Set up logging
            let level = if debug { Level::DEBUG } else { Level::INFO };
            let subscriber = FmtSubscriber::builder()
                .with_max_level(level)
                .with_target(false)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .pretty()
                .init();

            // Validate target URL
            let url = Url::parse(&target)?;
            if !url.scheme().starts_with("http") {
                anyhow::bail!("Target URL must use HTTP/HTTPS scheme");
            }

            // Initialize scanner
            let scanner = if let Some(config_path) = config {
                Scanner::from_config(&config_path).await?
            } else {
                Scanner::new(
                    threads,
                    std::time::Duration::from_secs(timeout),
                    vec![],
                    vec![],
                    true,
                    5,
                    true,
                )
            };

            // Run scan
            info!("Starting scan of {}", target);
            let result = scanner.scan(&target).await?;

            // Generate report
            match output.to_lowercase().as_str() {
                "json" => {
                    let json = serde_json::to_string_pretty(&result)?;
                    std::fs::write(format!("{}/report.json", dir), json)?;
                }
                "html" => {
                    let html = result.to_html()?;
                    std::fs::write(format!("{}/report.html", dir), html)?;
                }
                "markdown" => {
                    let md = result.to_markdown()?;
                    std::fs::write(format!("{}/report.md", dir), md)?;
                }
                _ => anyhow::bail!("Unsupported output format"),
            }

            info!("Scan completed. Report saved in {}", dir);
        }

        Commands::ValidateConfig { config } => {
            match validate_config_file(&config) {
                Ok(_) => println!("Configuration file is valid"),
                Err(e) => println!("Configuration file is invalid: {}", e),
            }
        }

        Commands::GenerateConfig { output } => {
            match generate_sample_config(&output) {
                Ok(_) => println!("Sample configuration file generated at {}", output),
                Err(e) => println!("Failed to generate configuration file: {}", e),
            }
        }
    }

    Ok(())
}
