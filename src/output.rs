//! Output formatters for capture sessions.

use crate::capture::CaptureSession;
use colored::Colorize;

pub fn print_summary(session: &CaptureSession) {
    eprintln!();
    eprintln!("{}", "═══════════════════════════════════════════════════".dimmed());
    eprintln!("  {} {}", "CAPTURE SUMMARY".green().bold(), session.interface.white());
    eprintln!("  Duration: {}s | Packets: {} | Bytes: {}",
        session.duration_secs,
        session.packets_captured,
        format_bytes(session.bytes_captured),
    );
    eprintln!("{}", "═══════════════════════════════════════════════════".dimmed());

    // Protocol breakdown
    eprintln!("\n  {}", "Protocols:".white().bold());
    let mut protos: Vec<_> = session.protocols_seen.iter().collect();
    protos.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in &protos {
        let bar_len = (**count as f64 / session.packets_captured.max(1) as f64 * 30.0) as usize;
        let bar = "█".repeat(bar_len.max(1));
        eprintln!("    {:<12} {:>8}  {}", proto.cyan(), count, bar.purple());
    }

    // Asset summary
    eprintln!("\n  {} {} hosts discovered", "Assets:".white().bold(), session.assets.len());
    print_assets(session);

    // Stats
    eprintln!("\n  {}", "Stats:".white().bold());
    eprintln!("    OT packets:      {}", session.stats.ot_packets.to_string().yellow());
    eprintln!("    Medical packets:  {}", session.stats.medical_packets.to_string().green());
    eprintln!("    TCP:             {}", session.stats.tcp_packets);
    eprintln!("    UDP:             {}", session.stats.udp_packets);
    eprintln!("    ARP:             {}", session.stats.arp_packets);

    // Events
    if !session.events.is_empty() {
        eprintln!("\n  {} {}", "Events:".white().bold(), session.events.len());
        for evt in session.events.iter().take(20) {
            let sev = match evt.severity.as_str() {
                "critical" => "CRIT".red().bold().to_string(),
                "high" => "HIGH".yellow().bold().to_string(),
                "medium" => " MED".blue().to_string(),
                _ => "INFO".dimmed().to_string(),
            };
            eprintln!("    [{}] {} {}", sev, evt.protocol.cyan(), evt.description.dimmed());
        }
        if session.events.len() > 20 {
            eprintln!("    ... and {} more", session.events.len() - 20);
        }
    }
}

pub fn print_assets(session: &CaptureSession) {
    if session.assets.is_empty() {
        eprintln!("    No assets discovered");
        return;
    }

    eprintln!();
    eprintln!("    {:<16} {:<18} {:<20} {:<18} {}", "IP".white().bold(), "MAC".dimmed(), "Type".cyan(), "Vendor".dimmed(), "Purdue".dimmed());
    eprintln!("    {}", "─".repeat(90).dimmed());

    let mut assets = session.assets.clone();
    assets.sort_by_key(|a| a.purdue_level.unwrap_or(9));

    for asset in &assets {
        let level = asset.purdue_level
            .map(|l| format!("L{l}"))
            .unwrap_or_else(|| "?".into());
        let level_colored = match asset.purdue_level {
            Some(0) => level.red().to_string(),
            Some(1) => level.yellow().to_string(),
            Some(2) => level.yellow().to_string(),
            Some(3) => level.cyan().to_string(),
            _ => level.dimmed().to_string(),
        };
        eprintln!(
            "    {:<16} {:<18} {:<20} {:<18} {}",
            asset.ip, asset.mac, asset.device_type, asset.vendor, level_colored,
        );
    }
}

pub fn to_json(session: &CaptureSession) -> String {
    serde_json::to_string_pretty(session).unwrap_or_else(|_| "{}".into())
}

pub fn to_events(session: &CaptureSession) -> String {
    session.events.iter()
        .map(|e| serde_json::to_string(e).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 { format!("{:.1} GB", bytes as f64 / 1_073_741_824.0) }
    else if bytes >= 1_048_576 { format!("{:.1} MB", bytes as f64 / 1_048_576.0) }
    else if bytes >= 1024 { format!("{:.1} KB", bytes as f64 / 1024.0) }
    else { format!("{bytes} B") }
}
