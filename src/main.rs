//! cysense — Passive network sensor by Cybrium AI.
//!
//! Captures traffic from SPAN/TAP/mirror ports, dissects IT/OT/medical protocols,
//! discovers assets, and streams events to the Cybrium platform.

mod capture;
mod dissect;
mod assets;
mod anomaly;
mod output;

use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "cysense", version, about = "Passive network sensor — Cybrium AI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start passive network monitoring
    Listen {
        /// Network interface to capture on (e.g., eth0, en0)
        #[arg(short, long)]
        interface: String,

        /// Duration in seconds (0 = indefinite)
        #[arg(short, long, default_value = "0")]
        duration: u64,

        /// BPF filter (e.g., "tcp port 2575" for HL7)
        #[arg(short, long)]
        filter: Option<String>,

        /// Output format: text, json, events
        #[arg(short = 'f', long, default_value = "text")]
        format: String,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Platform API URL for live event streaming
        #[arg(long)]
        platform: Option<String>,

        /// API key for platform authentication (or set CYSENSE_TOKEN env var)
        #[arg(long)]
        token: Option<String>,

        /// Enable anomaly detection (requires baseline)
        #[arg(long)]
        anomaly: bool,

        /// Promiscuous mode (capture all traffic, not just to this host)
        #[arg(long, default_value = "true")]
        promisc: bool,
    },

    /// List available network interfaces
    Interfaces,

    /// Show captured asset inventory from a previous session
    Assets {
        /// Path to cysense JSON output or session file
        #[arg(short, long)]
        file: String,
    },

    /// Check for updates and self-update
    Update,

    /// Show version
    Version,
}

fn print_banner() {
    eprintln!("\x1b[35m");
    eprintln!(r#"   ___  _   _  ___  ___  _  _  ___  ___ "#);
    eprintln!(r#"  / __|| | | |/ __|| __|| \| |/ __|| __|"#);
    eprintln!(r#" | (__ | |_| |\__ \| _| | .` |\__ \| _| "#);
    eprintln!(r#"  \___| \__, ||___/|___||_|\_||___/|___|"#);
    eprintln!(r#"        |___/                           "#);
    eprintln!("\x1b[0m");
    eprintln!(
        "  \x1b[35m\x1b[1mcysense\x1b[0m v{} — \x1b[2mCybrium AI Network Sensor\x1b[0m",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!();
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("cysense=info".parse().unwrap()))
        .without_time()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Listen {
            interface,
            duration,
            filter,
            format,
            output: out_file,
            platform,
            token,
            anomaly,
            promisc,
        } => {
            print_banner();
            eprintln!("  {} {}", "Interface:".white().bold(), interface.yellow());
            if let Some(ref f) = filter {
                eprintln!("  {} {}", "BPF Filter:".white().bold(), f);
            }
            if duration > 0 {
                eprintln!("  {} {}s", "Duration:".white().bold(), duration);
            } else {
                eprintln!("  {} continuous (Ctrl+C to stop)", "Duration:".white().bold());
            }
            if platform.is_some() {
                eprintln!("  {} live streaming enabled", "Platform:".white().bold());
            }
            eprintln!();

            let config = capture::CaptureConfig {
                interface,
                duration,
                filter,
                promisc,
                anomaly_detection: anomaly,
                platform_url: platform,
                platform_token: token,
            };

            match capture::start_capture(config).await {
                Ok(session) => {
                    match format.as_str() {
                        "json" => {
                            let json = output::to_json(&session);
                            if let Some(path) = &out_file {
                                std::fs::write(path, &json).expect("Failed to write output");
                                eprintln!("\n{} {}", "Session saved to".green(), path);
                            } else {
                                println!("{json}");
                            }
                        }
                        "events" => {
                            let events = output::to_events(&session);
                            if let Some(path) = &out_file {
                                std::fs::write(path, &events).expect("Failed to write output");
                            } else {
                                println!("{events}");
                            }
                        }
                        _ => {
                            output::print_summary(&session);
                            if let Some(path) = &out_file {
                                let json = output::to_json(&session);
                                std::fs::write(path, &json).expect("Failed to write output");
                                eprintln!("\n{} {}", "Session saved to".green(), path);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    std::process::exit(2);
                }
            }
        }

        Commands::Interfaces => {
            print_banner();
            capture::list_interfaces();
        }

        Commands::Assets { file } => {
            print_banner();
            match std::fs::read_to_string(&file) {
                Ok(content) => {
                    if let Ok(session) = serde_json::from_str::<capture::CaptureSession>(&content) {
                        output::print_assets(&session);
                    } else {
                        eprintln!("{} Cannot parse session file", "Error:".red());
                    }
                }
                Err(e) => eprintln!("{} {}", "Error:".red(), e),
            }
        }

        Commands::Update => {
            eprintln!("Checking for updates...");
            // Same self-update pattern as cyweb
            let current = env!("CARGO_PKG_VERSION");
            let client = reqwest::Client::builder()
                .user_agent(format!("cysense/{current}"))
                .timeout(std::time::Duration::from_secs(5))
                .build().unwrap();
            match client.get("https://api.github.com/repos/cybrium-ai/cysense/releases/latest")
                .header("Accept", "application/vnd.github+json")
                .send().await {
                Ok(resp) if resp.status().is_success() => {
                    let data: serde_json::Value = resp.json().await.unwrap_or_default();
                    let latest = data["tag_name"].as_str().unwrap_or("").trim_start_matches('v');
                    if latest == current || latest.is_empty() {
                        eprintln!("{}", "Already up to date!".green());
                    } else {
                        eprintln!("New version: {} -> {}", current, latest.green().bold());
                        eprintln!("Download from: https://github.com/cybrium-ai/cysense/releases/latest");
                    }
                }
                _ => eprintln!("{}", "Cannot reach GitHub API".red()),
            }
        }

        Commands::Version => {
            println!("cysense {} — Cybrium AI Network Sensor", env!("CARGO_PKG_VERSION"));
            println!("https://github.com/cybrium-ai/cysense");
        }
    }
}
