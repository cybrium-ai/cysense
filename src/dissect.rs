//! Protocol dissection — identify IT, OT, and medical protocols from raw packets.

use etherparse::SlicedPacket;

#[derive(Debug, Clone)]
pub struct DissectedPacket {
    pub src_mac: String,
    pub dst_mac: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: usize,
    pub payload_preview: Option<String>,
    pub vendor_hint: Option<String>,
}

/// Known OT/medical port → protocol mappings.
fn port_to_protocol(port: u16) -> Option<&'static str> {
    match port {
        // OT/SCADA protocols
        502 => Some("Modbus"),
        20000 => Some("DNP3"),
        47808 => Some("BACnet"),
        44818 => Some("ENIP"),
        102 => Some("S7"),
        4840 => Some("OPC-UA"),
        2404 => Some("IEC104"),
        1883 | 8883 => Some("MQTT"),
        // Medical protocols
        2575 => Some("HL7"),
        104 | 11112 => Some("DICOM"),
        // IT protocols
        80 | 8080 | 8443 => Some("HTTP"),
        443 => Some("HTTPS"),
        53 => Some("DNS"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        21 => Some("FTP"),
        25 | 587 => Some("SMTP"),
        3389 => Some("RDP"),
        445 => Some("SMB"),
        3306 => Some("MySQL"),
        5432 => Some("PostgreSQL"),
        6379 => Some("Redis"),
        27017 => Some("MongoDB"),
        123 => Some("NTP"),
        161 | 162 => Some("SNMP"),
        514 => Some("Syslog"),
        1433 => Some("MSSQL"),
        389 | 636 => Some("LDAP"),
        _ => None,
    }
}

/// Deep payload inspection for protocol identification.
fn identify_from_payload(payload: &[u8], port: u16) -> Option<&'static str> {
    if payload.len() < 4 {
        return None;
    }

    // Modbus TCP: transaction ID (2) + protocol ID (2, always 0x0000) + length (2) + unit ID (1)
    if payload.len() >= 7 && payload[2] == 0x00 && payload[3] == 0x00 && port == 502 {
        return Some("Modbus");
    }

    // DNP3: start bytes 0x0564
    if payload.len() >= 2 && payload[0] == 0x05 && payload[1] == 0x64 {
        return Some("DNP3");
    }

    // BACnet/IP: BVLC type byte 0x81
    if payload[0] == 0x81 && port == 47808 {
        return Some("BACnet");
    }

    // S7comm: TPKT header (0x03 0x00) + COTP
    if payload.len() >= 4 && payload[0] == 0x03 && payload[1] == 0x00 {
        return Some("S7");
    }

    // ENIP: command (2 bytes) at offset 0, 0x0004 = ListServices, 0x0063 = ListIdentity
    if port == 44818 && payload.len() >= 4 {
        let cmd = u16::from_le_bytes([payload[0], payload[1]]);
        if cmd <= 0x0070 {
            return Some("ENIP");
        }
    }

    // HL7v2: starts with MSH|^~\&
    if payload.len() >= 8 {
        let start = std::str::from_utf8(&payload[..8.min(payload.len())]).unwrap_or("");
        if start.starts_with("MSH|") || start.starts_with("\x0bMSH|") {
            return Some("HL7");
        }
    }

    // DICOM: A-ASSOCIATE-RQ starts with 0x01 0x00
    if payload.len() >= 6 && payload[0] == 0x01 && payload[1] == 0x00 {
        let pdu_len = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
        if pdu_len > 20 && pdu_len < 65535 {
            return Some("DICOM");
        }
    }

    // HTTP
    if payload.len() >= 4 {
        let start = std::str::from_utf8(&payload[..4.min(payload.len())]).unwrap_or("");
        if start.starts_with("GET ") || start.starts_with("POST")
            || start.starts_with("PUT ") || start.starts_with("HTTP") {
            // Check for FHIR
            let full = std::str::from_utf8(&payload[..payload.len().min(200)]).unwrap_or("");
            if full.contains("fhir") || full.contains("FHIR") || full.contains("application/fhir") {
                return Some("FHIR");
            }
            return Some("HTTP");
        }
    }

    // MQTT: CONNECT packet type = 0x10
    if payload[0] == 0x10 && (port == 1883 || port == 8883) {
        return Some("MQTT");
    }

    None
}

/// MAC OUI → vendor mapping (top vendors in hospital environments).
fn mac_to_vendor(mac: &str) -> String {
    let oui = mac.to_uppercase().replace(':', "");
    let prefix = if oui.len() >= 6 { &oui[..6] } else { "" };

    match prefix {
        // Medical device manufacturers
        "000E8F" | "001E8F" => "Cisco (Medical)".into(),
        "00A0D1" => "Inventec".into(),
        "001AA0" => "Dell EMC".into(),
        "0050C2" => "IEEE Registration".into(),
        "00055D" => "D-Link".into(),
        "001B78" => "Hewlett-Packard".into(),
        "00242C" => "Cisco".into(),
        "D4CA6D" => "Apple".into(),
        "3C22FB" => "Apple".into(),
        "ACDE48" => "Apple".into(),
        "A4B805" => "Apple".into(),
        "F8FF0A" => "Broadcom".into(),
        "0019B9" => "Dell".into(),
        "000D3A" => "Microsoft".into(),
        "001517" => "Intel".into(),
        "7085C2" => "ASRock".into(),
        // Medical OUI ranges (simplified)
        "0004A3" => "Microchip (Medical IoT)".into(),
        "001E58" => "D-Link".into(),
        "E0D55E" => "LITEON".into(),
        "7C2F80" => "Gigabyte".into(),
        _ => {
            // Generic OUI lookup — first 3 bytes
            if prefix.starts_with("00") { "Unknown (local)".into() }
            else { "Unknown".into() }
        }
    }
}

pub fn dissect_packet(data: &[u8]) -> DissectedPacket {
    let mut result = DissectedPacket {
        src_mac: String::new(),
        dst_mac: String::new(),
        src_ip: "0.0.0.0".into(),
        dst_ip: "0.0.0.0".into(),
        src_port: 0,
        dst_port: 0,
        protocol: "Unknown".into(),
        length: data.len(),
        payload_preview: None,
        vendor_hint: None,
    };

    // Extract MACs from raw ethernet header
    if data.len() >= 14 {
        result.dst_mac = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[0], data[1], data[2], data[3], data[4], data[5]);
        result.src_mac = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            data[6], data[7], data[8], data[9], data[10], data[11]);
        result.vendor_hint = Some(mac_to_vendor(&result.src_mac));
    }

    // Check for ARP (ethertype 0x0806)
    if data.len() >= 14 && data[12] == 0x08 && data[13] == 0x06 {
        result.protocol = "ARP".into();
        return result;
    }

    match SlicedPacket::from_ethernet(data) {
        Ok(pkt) => {
            // IP layer
            match &pkt.net {
                Some(etherparse::NetSlice::Ipv4(hdr)) => {
                    result.src_ip = format!("{}", hdr.header().source_addr());
                    result.dst_ip = format!("{}", hdr.header().destination_addr());
                }
                Some(etherparse::NetSlice::Ipv6(hdr)) => {
                    result.src_ip = format!("{}", hdr.header().source_addr());
                    result.dst_ip = format!("{}", hdr.header().destination_addr());
                }
                None => {}
            }

            // Transport layer
            match &pkt.transport {
                Some(etherparse::TransportSlice::Tcp(tcp)) => {
                    result.src_port = tcp.source_port();
                    result.dst_port = tcp.destination_port();
                    result.protocol = "TCP".into();
                }
                Some(etherparse::TransportSlice::Udp(udp)) => {
                    result.src_port = udp.source_port();
                    result.dst_port = udp.destination_port();
                    result.protocol = "UDP".into();
                }
                _ => {}
            }

            // Deep protocol identification
            let payload = pkt.ip_payload().map(|p| p.payload).unwrap_or(&[]);
            if !payload.is_empty() {
                // Try port-based first
                if let Some(proto) = port_to_protocol(result.dst_port) {
                    result.protocol = proto.into();
                } else if let Some(proto) = port_to_protocol(result.src_port) {
                    result.protocol = proto.into();
                }

                // Then deep payload inspection (overrides port guess)
                if let Some(proto) = identify_from_payload(payload, result.dst_port) {
                    result.protocol = proto.into();
                }

                // Save payload preview for medical protocols
                if matches!(result.protocol.as_str(), "HL7" | "DICOM" | "FHIR" | "HTTP") {
                    let preview = String::from_utf8_lossy(&payload[..payload.len().min(200)]);
                    result.payload_preview = Some(preview.replace('\0', ".").replace('\n', "\\n"));
                }
            }
        }
        Err(_) => {}
    }

    result
}
