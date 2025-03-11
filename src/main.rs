use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use url::Url;

mod cli;
mod config;
mod http;
mod reporting;
mod scanner;

use cli::{Cli, Commands};
use scanner::core::Scanner;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan {
            target,
            threads,
            timeout,
            headers,
            cookies,
            follow_redirects,
            max_redirects,
            insecure,
            format,
            output,
            debug,
            paths: _,
            exclude: _,
            wordlist: _,
            rate_limit: _,
            proxy,
            auth,
            depth: _,
            passive: _,
            user_agent,
        } => {
            // Setup logging
            let level = if *debug { Level::DEBUG } else { Level::INFO };
            let subscriber = FmtSubscriber::builder()
                .with_max_level(level)
                .with_target(false)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
                .with_thread_names(true)
                .with_level(true)
                .with_ansi(true)
                .pretty()
                .build();
            tracing::subscriber::set_global_default(subscriber)?;

            info!("Starting Web Cache Vulnerability Scanner");
            info!("Target: {}", target);

            // Validate target URL
            let url = Url::parse(target)?;
            if !url.scheme().starts_with("http") {
                anyhow::bail!("Only HTTP/HTTPS URLs are supported");
            }

            // Initialize scanner
            let mut scanner_builder = Scanner::new(
                *threads,
                *timeout,
                headers.clone(),
                cookies.clone(),
                *follow_redirects,
                *max_redirects,
                !*insecure,
            )?;

            // Configure proxy if specified
            if let Some(proxy_url) = proxy {
                scanner_builder = scanner_builder.with_proxy(proxy_url)?;
            }

            // Configure basic auth if specified
            if let Some(auth_str) = auth {
                let parts: Vec<&str> = auth_str.splitn(2, ':').collect();
                if parts.len() != 2 {
                    anyhow::bail!("Invalid auth format. Expected 'username:password'");
                }
                scanner_builder = scanner_builder.with_basic_auth(parts[0], parts[1])?;
            }

            // Configure user agent if specified
            if let Some(ua) = user_agent {
                scanner_builder = scanner_builder.with_user_agent(&ua)?;
            }

            // Run scan
            let scan_result = scanner_builder.scan(&url.to_string()).await?;

            // Generate report
            let report = reporting::Report::new(scan_result);
            if let Some(output_path) = output {
                match format.to_lowercase().as_str() {
                    "json" => report.save_json(&output_path).await?,
                    "html" => report.save_html(&output_path).await?,
                    "markdown" => report.save_markdown(&output_path).await?,
                    _ => anyhow::bail!("Unsupported output format: {}", format),
                }
                info!("Report saved to: {}", output_path.display());
            } else {
                // Print summary to console
                println!("\nScan Summary:");
                println!("Target: {}", scan_result.target);
                println!("Duration: {:?}", scan_result.scan_duration);
                println!("Vulnerabilities found: {}", scan_result.vulnerabilities.len());
                println!("Requests sent: {}", scan_result.requests_sent);
            }
        }
        Commands::ValidateConfig { config } => {
            match config::validate_config(config) {
                Ok(_) => println!("Configuration file is valid"),
                Err(e) => println!("Configuration file is invalid: {}", e),
            }
        }
        Commands::GenerateConfig { output } => {
            config::generate_sample_config(output)?;
            println!("Sample configuration file generated at: {}", output.display());
        }
    }

    Ok(())
}
