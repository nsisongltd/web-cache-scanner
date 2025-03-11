use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod scanner;
mod http;
mod reporting;
mod cli;

#[derive(Parser)]
#[command(
    name = "web-cache-scanner",
    author = "Nsisong Labs <hello@nsisonglabs.com>",
    version,
    about = "A high-performance web cache vulnerability scanner",
    long_about = None
)]
struct Cli {
    /// Sets the level of verbosity
    #[arg(short, long, default_value = "info")]
    verbose: Level,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a target for web cache vulnerabilities
    Scan {
        /// The target URL to scan
        #[arg(short, long)]
        url: String,

        /// Number of concurrent threads
        #[arg(short, long, default_value = "10")]
        threads: usize,

        /// Timeout in seconds for each request
        #[arg(short, long, default_value = "30")]
        timeout: u64,

        /// Output file for the report
        #[arg(short, long)]
        output: Option<String>,

        /// Report format (json, html, text)
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Custom headers to include in requests (format: "Header: Value")
        #[arg(short = 'H', long)]
        headers: Vec<String>,

        /// Custom cookies to include in requests (format: "name=value")
        #[arg(short = 'C', long)]
        cookies: Vec<String>,

        /// Follow redirects
        #[arg(short = 'r', long, default_value = "true")]
        follow_redirects: bool,

        /// Maximum number of redirects to follow
        #[arg(long, default_value = "10")]
        max_redirects: u32,

        /// Disable SSL verification
        #[arg(long)]
        no_verify_ssl: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize logging with pretty format
    let subscriber = FmtSubscriber::builder()
        .with_max_level(cli.verbose)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(true)
        .with_level(true)
        .pretty()
        .init();

    info!("Web Cache Vulnerability Scanner starting up...");
    info!("Built by Nsisong Labs (https://nsisonglabs.com)");

    match cli.command {
        Commands::Scan {
            url,
            threads,
            timeout,
            output,
            format,
            headers,
            cookies,
            follow_redirects,
            max_redirects,
            no_verify_ssl,
        } => {
            info!("Starting scan of {}", url);
            
            let scanner = scanner::Scanner::new(
                threads,
                timeout,
                headers,
                cookies,
                follow_redirects,
                max_redirects,
                !no_verify_ssl,
            );

            let result = scanner.scan(&url).await?;
            
            // Generate and save report
            reporting::generate_report(result, &format, output).await?;
            
            info!("Scan complete");
        }
    }

    Ok(())
}
