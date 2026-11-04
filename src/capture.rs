//! Packet capture engine — passive SPAN/TAP traffic capture.

use crate::assets::AssetInventory;
use crate::dissect;
use chrono::Utc;
use pcap::{Capture, Device};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub interface: String,
    pub duration: u64,
    pub filter: Option<String>,
    pub promisc: bool,
    pub anomaly_detection: bool,
    pub platform_url: Option<String>,
    pub platform_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Path to a saved pcap/pcapng file.
    pub pcap: String,
    /// Optional BPF filter, applied to the file the same way as live capture.
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSession {
    pub interface: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration_secs: u64,
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub protocols_seen: HashMap<String, u64>,
    pub assets: Vec<DiscoveredAsset>,
    pub events: Vec<NetworkEvent>,
    pub stats: SessionStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub vendor: String,
    pub device_type: String,
    pub protocols: Vec<String>,
    pub ports: Vec<u16>,
    pub first_seen: String,
    pub last_seen: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub purdue_level: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub timestamp: String,
    pub event_type: String,
    pub severity: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub protocol: String,
    pub port: u16,
    pub description: String,
    pub raw_data: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub arp_packets: u64,
    pub ot_packets: u64,
    pub medical_packets: u64,
    pub unique_hosts: u64,
    pub unique_conversations: u64,
}

pub fn list_interfaces() {
    match Device::list() {
        Ok(devices) => {
            eprintln!("Available interfaces:\n");
            for (i, dev) in devices.iter().enumerate() {
                let desc = dev.desc.as_deref().unwrap_or("");
                let addrs: Vec<String> = dev.addresses.iter()
                    .map(|a| a.addr.to_string())
                    .collect();
                eprintln!(
                    "  {}  {} {}",
                    format!("{:>2}.", i + 1).dimmed(),
                    dev.name.white().bold(),
                    if !desc.is_empty() { format!("({})", desc).dimmed().to_string() } else { String::new() },
                );
                if !addrs.is_empty() {
                    eprintln!("      {}", addrs.join(", ").dimmed());
                }
            }
        }
        Err(e) => eprintln!("Error listing interfaces: {e}"),
    }
}

use colored::Colorize;

/// Per-packet pipeline — dissect, update protocol/asset/event state, and
/// classify. Shared verbatim by live capture (`start_capture`) and offline
/// pcap replay (`start_replay`) so the two paths produce an identical
/// `CaptureSession` contract. Do NOT fork the dissection/classification logic
/// here; both callers must go through this one function.
fn process_packet(
    data: &[u8],
    stats: &mut SessionStats,
    inventory: &Arc<Mutex<AssetInventory>>,
    events: &Arc<Mutex<Vec<NetworkEvent>>>,
    protocols: &Arc<Mutex<HashMap<String, u64>>>,
) {
    stats.total_packets += 1;
    stats.total_bytes += data.len() as u64;

    // Dissect the packet
    let dissected = dissect::dissect_packet(data);

    // Update protocol stats
    if let Ok(mut protos) = protocols.lock() {
        *protos.entry(dissected.protocol.clone()).or_insert(0) += 1;
    }

    // Update asset inventory
    if let Ok(mut inv) = inventory.lock() {
        inv.update_from_packet(&dissected);
    }

    // Classify packet
    match dissected.protocol.as_str() {
        "TCP" | "HTTP" | "HTTPS" => stats.tcp_packets += 1,
        "UDP" | "DNS" | "NTP" => stats.udp_packets += 1,
        "ARP" => stats.arp_packets += 1,
        "Modbus" | "DNP3" | "BACnet" | "ENIP" | "S7" | "OPC-UA" | "IEC104" => {
            stats.ot_packets += 1;
            // OT protocol event
            if let Ok(mut evts) = events.lock() {
                evts.push(NetworkEvent {
                    timestamp: Utc::now().to_rfc3339(),
                    event_type: "ot_traffic".into(),
                    severity: "info".into(),
                    source_ip: dissected.src_ip.clone(),
                    dest_ip: dissected.dst_ip.clone(),
                    protocol: dissected.protocol.clone(),
                    port: dissected.dst_port,
                    description: format!("{} traffic: {} -> {}:{}", dissected.protocol, dissected.src_ip, dissected.dst_ip, dissected.dst_port),
                    raw_data: None,
                });
            }
        }
        "HL7" | "DICOM" | "FHIR" => {
            stats.medical_packets += 1;
            if let Ok(mut evts) = events.lock() {
                evts.push(NetworkEvent {
                    timestamp: Utc::now().to_rfc3339(),
                    event_type: "medical_traffic".into(),
                    severity: "info".into(),
                    source_ip: dissected.src_ip.clone(),
                    dest_ip: dissected.dst_ip.clone(),
                    protocol: dissected.protocol.clone(),
                    port: dissected.dst_port,
                    description: format!("{} medical data: {} -> {}:{}", dissected.protocol, dissected.src_ip, dissected.dst_ip, dissected.dst_port),
                    raw_data: dissected.payload_preview.clone(),
                });
            }
        }
        _ => {}
    }
}

/// Build the final `CaptureSession` from accumulated state. Shared by live and
/// replay so the emitted JSON contract is identical on both paths.
fn finalize_session(
    interface: String,
    started_at: String,
    duration_secs: u64,
    mut stats: SessionStats,
    inventory: Arc<Mutex<AssetInventory>>,
    events: Arc<Mutex<Vec<NetworkEvent>>>,
    protocols: Arc<Mutex<HashMap<String, u64>>>,
) -> CaptureSession {
    let asset_list = inventory.lock()
        .map(|i| i.to_discovered_assets())
        .unwrap_or_default();

    stats.unique_hosts = asset_list.len() as u64;
    let protocol_map = protocols.lock()
        .map(|p| p.clone())
        .unwrap_or_default();
    let event_list = events.lock()
        .map(|e| e.clone())
        .unwrap_or_default();

    CaptureSession {
        interface,
        started_at,
        completed_at: Utc::now().to_rfc3339(),
        duration_secs,
        packets_captured: stats.total_packets,
        bytes_captured: stats.total_bytes,
        protocols_seen: protocol_map,
        assets: asset_list,
        events: event_list,
        stats,
    }
}

/// Replay a saved pcap through the same pipeline as live capture, for
/// reproducible offline analysis and benchmarking. Emits the identical
/// `CaptureSession` contract as `start_capture`.
pub fn start_replay(config: ReplayConfig) -> Result<CaptureSession, String> {
    let mut cap = Capture::from_file(&config.pcap)
        .map_err(|e| format!("Cannot open pcap '{}': {e}", config.pcap))?;

    if let Some(ref filter) = config.filter {
        cap.filter(filter, true)
            .map_err(|e| format!("Invalid BPF filter: {e}"))?;
    }

    let started_at = Utc::now().to_rfc3339();
    let start_time = Instant::now();
    let inventory = Arc::new(Mutex::new(AssetInventory::new()));
    let events: Arc<Mutex<Vec<NetworkEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let protocols: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut stats = SessionStats::default();

    eprintln!("{} {}", "Replaying pcap:".green(), config.pcap.yellow());

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                process_packet(packet.data, &mut stats, &inventory, &events, &protocols);
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("\nReplay error: {e}");
                break;
            }
        }
    }

    eprintln!(
        "  {} packets | {} OT | {} medical",
        stats.total_packets.to_string().white(),
        stats.ot_packets.to_string().cyan(),
        stats.medical_packets.to_string().green(),
    );

    Ok(finalize_session(
        format!("pcap:{}", config.pcap),
        started_at,
        start_time.elapsed().as_secs(),
        stats,
        inventory,
        events,
        protocols,
    ))
}

pub async fn start_capture(config: CaptureConfig) -> Result<CaptureSession, String> {
    let device = Device::list()
        .map_err(|e| format!("Cannot list devices: {e}"))?
        .into_iter()
        .find(|d| d.name == config.interface)
        .ok_or_else(|| format!("Interface '{}' not found. Run 'cysense interfaces' to list available.", config.interface))?;

    let mut cap = Capture::from_device(device)
        .map_err(|e| format!("Cannot open device: {e}"))?
        .promisc(config.promisc)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .map_err(|e| format!("Cannot start capture: {e} (try running with sudo)"))?;

    if let Some(ref filter) = config.filter {
        cap.filter(filter, true)
            .map_err(|e| format!("Invalid BPF filter: {e}"))?;
    }

    let started_at = Utc::now().to_rfc3339();
    let start_time = Instant::now();
    let inventory = Arc::new(Mutex::new(AssetInventory::new()));
    let events: Arc<Mutex<Vec<NetworkEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let protocols: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut stats = SessionStats::default();

    eprintln!("{}", "Capturing... (Ctrl+C to stop)".green());
    eprintln!();

    let mut packet_count: u64 = 0;
    let mut last_status = Instant::now();

    loop {
        // Check duration
        if config.duration > 0 && start_time.elapsed() > Duration::from_secs(config.duration) {
            break;
        }

        // Check Ctrl+C
        if std::sync::atomic::AtomicBool::new(false).load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                process_packet(packet.data, &mut stats, &inventory, &events, &protocols);
                packet_count = stats.total_packets;

                // Status update every 5 seconds
                if last_status.elapsed() > Duration::from_secs(5) {
                    let inv_count = inventory.lock().map(|i| i.host_count()).unwrap_or(0);
                    let ot = stats.ot_packets;
                    let med = stats.medical_packets;
                    eprint!(
                        "\r  {} packets | {} hosts | {} OT | {} medical    ",
                        packet_count.to_string().white(),
                        inv_count.to_string().yellow(),
                        ot.to_string().cyan(),
                        med.to_string().green(),
                    );
                    last_status = Instant::now();
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("\nCapture error: {e}");
                break;
            }
        }
    }

    eprintln!("\n\n{} Capture stopped.", "Done.".green().bold());

    Ok(finalize_session(
        config.interface,
        started_at,
        start_time.elapsed().as_secs(),
        stats,
        inventory,
        events,
        protocols,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Replay the committed OT sample pcap and assert the file-capture path
    // produces the same CaptureSession contract as live capture, with the
    // dissection/classification pipeline intact (device_type, purdue_level,
    // protocols). This is the reproducible, offline guarantee the benchmark
    // relies on.
    #[test]
    fn replay_ot_sample_classifies_assets() {
        let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ot_sample.pcap");
        let session = start_replay(ReplayConfig { pcap: pcap.to_string(), filter: None })
            .expect("replay should open and parse the fixture pcap");

        assert_eq!(session.packets_captured, 2, "both fixture packets processed");
        assert!(session.protocols_seen.contains_key("Modbus"), "Modbus dissected");
        assert!(session.protocols_seen.contains_key("S7"), "S7 dissected");
        assert_eq!(session.stats.ot_packets, 2, "both classified as OT");

        // At least one asset classified as an OT Controller with a real Purdue level.
        let ot = session.assets.iter().find(|a| a.device_type == "OT Controller")
            .expect("an OT Controller asset is discovered");
        assert!(ot.purdue_level.is_some(), "Purdue level assigned");

        // Interface label records provenance without breaking the shape.
        assert!(session.interface.starts_with("pcap:"));
    }

    #[test]
    fn replay_missing_file_errors_cleanly() {
        let err = start_replay(ReplayConfig {
            pcap: "/nonexistent/does-not-exist.pcap".to_string(),
            filter: None,
        });
        assert!(err.is_err(), "a missing pcap returns Err, not a panic");
    }
}
