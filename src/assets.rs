//! Asset inventory — track discovered hosts, classify device types.

use crate::capture::DiscoveredAsset;
use crate::dissect::DissectedPacket;
use chrono::Utc;
use std::collections::{HashMap, HashSet};

pub struct AssetInventory {
    hosts: HashMap<String, AssetEntry>,
}

struct AssetEntry {
    mac: String,
    ip: String,
    vendor: String,
    protocols: HashSet<String>,
    ports: HashSet<u16>,
    first_seen: String,
    last_seen: String,
    packet_count: u64,
    byte_count: u64,
}

impl AssetInventory {
    pub fn new() -> Self {
        Self { hosts: HashMap::new() }
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    pub fn update_from_packet(&mut self, pkt: &DissectedPacket) {
        let now = Utc::now().to_rfc3339();

        // Update source host
        if pkt.src_ip != "0.0.0.0" {
            let entry = self.hosts.entry(pkt.src_ip.clone()).or_insert_with(|| AssetEntry {
                mac: pkt.src_mac.clone(),
                ip: pkt.src_ip.clone(),
                vendor: pkt.vendor_hint.clone().unwrap_or_default(),
                protocols: HashSet::new(),
                ports: HashSet::new(),
                first_seen: now.clone(),
                last_seen: now.clone(),
                packet_count: 0,
                byte_count: 0,
            });
            entry.last_seen = now.clone();
            entry.packet_count += 1;
            entry.byte_count += pkt.length as u64;
            entry.protocols.insert(pkt.protocol.clone());
            if pkt.src_port > 0 { entry.ports.insert(pkt.src_port); }
        }

        // Update destination host
        if pkt.dst_ip != "0.0.0.0" && pkt.dst_ip != "255.255.255.255" {
            let entry = self.hosts.entry(pkt.dst_ip.clone()).or_insert_with(|| AssetEntry {
                mac: pkt.dst_mac.clone(),
                ip: pkt.dst_ip.clone(),
                vendor: String::new(),
                protocols: HashSet::new(),
                ports: HashSet::new(),
                first_seen: now.clone(),
                last_seen: now.clone(),
                packet_count: 0,
                byte_count: 0,
            });
            entry.last_seen = now;
            entry.protocols.insert(pkt.protocol.clone());
            if pkt.dst_port > 0 { entry.ports.insert(pkt.dst_port); }
        }
    }

    pub fn to_discovered_assets(&self) -> Vec<DiscoveredAsset> {
        self.hosts.values().map(|e| {
            let device_type = classify_device(&e.protocols, &e.ports, &e.vendor);
            let purdue_level = classify_purdue(&device_type, &e.protocols);
            DiscoveredAsset {
                mac: e.mac.clone(),
                ip: e.ip.clone(),
                hostname: None,
                vendor: e.vendor.clone(),
                device_type,
                protocols: e.protocols.iter().cloned().collect(),
                ports: e.ports.iter().cloned().collect(),
                first_seen: e.first_seen.clone(),
                last_seen: e.last_seen.clone(),
                packet_count: e.packet_count,
                byte_count: e.byte_count,
                purdue_level: Some(purdue_level),
            }
        }).collect()
    }
}

fn classify_device(protocols: &HashSet<String>, ports: &HashSet<u16>, vendor: &str) -> String {
    // Medical devices
    if protocols.contains("HL7") || protocols.contains("DICOM") || protocols.contains("FHIR") {
        return "Medical Device".into();
    }
    // OT/SCADA
    if protocols.contains("Modbus") || protocols.contains("DNP3") || protocols.contains("S7")
        || protocols.contains("ENIP") || protocols.contains("OPC-UA") || protocols.contains("IEC104") {
        return "OT Controller".into();
    }
    // Building automation
    if protocols.contains("BACnet") {
        return "Building Automation".into();
    }
    // IoT
    if protocols.contains("MQTT") {
        return "IoT Device".into();
    }
    // Servers
    if ports.contains(&80) || ports.contains(&443) || ports.contains(&8080) {
        return "Web Server".into();
    }
    if ports.contains(&3306) || ports.contains(&5432) || ports.contains(&27017) {
        return "Database Server".into();
    }
    if ports.contains(&22) {
        return "Server (SSH)".into();
    }
    if ports.contains(&3389) {
        return "Workstation (RDP)".into();
    }
    if ports.contains(&445) || ports.contains(&139) {
        return "Windows Host".into();
    }
    // Network infrastructure
    if protocols.contains("SNMP") {
        return "Network Device".into();
    }

    "Unknown Host".into()
}

fn classify_purdue(device_type: &str, protocols: &HashSet<String>) -> u8 {
    match device_type {
        "OT Controller" => {
            if protocols.contains("S7") || protocols.contains("ENIP") { 2 }  // PLC
            else if protocols.contains("Modbus") { 1 }  // I/O
            else { 2 }
        }
        "Building Automation" => 1,
        "IoT Device" => 0,
        "Medical Device" => 3,  // Site operations
        "Web Server" | "Database Server" => 4,  // IT/DMZ
        "Workstation (RDP)" | "Windows Host" | "Server (SSH)" => 5,  // Enterprise
        "Network Device" => 3,  // Site operations
        _ => 5,
    }
}
