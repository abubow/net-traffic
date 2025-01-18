use std::process::Command;
use std::path::Path;
use std::io::{self};
use serde_json::{Value};
use chrono::DateTime;
use crate::packet::*;
use chrono::Utc;

/// Error types for PCAP parsing
#[derive(Debug)]
pub enum PcapError {
    IoError(io::Error),
    TsharkNotFound,
    ParseError(String),
    JsonError(serde_json::Error),
}

impl From<io::Error> for PcapError {
    fn from(error: io::Error) -> Self {
        PcapError::IoError(error)
    }
}

impl From<serde_json::Error> for PcapError {
    fn from(error: serde_json::Error) -> Self {
        PcapError::JsonError(error)
    }
}

/// Parse a PCAP file using tshark and return a vector of NetworkPackets
pub fn parse_pcap<P: AsRef<Path>>(pcap_path: P) -> Result<Vec<NetworkPacket>, PcapError> {
    // Check if tshark is available
    if !is_tshark_installed() {
        return Err(PcapError::TsharkNotFound);
    }

    // Run tshark command to convert pcap to JSON
    let output = Command::new("tshark")
        .args([
            "-r", pcap_path.as_ref().to_str().unwrap(),
            "-T", "json",
            "-x",  // Include hex dump
            // Fields we want to capture
            "-e", "frame.time_epoch",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "eth.type",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ip.proto",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.seq",
            "-e", "tcp.ack",
            "-e", "tcp.flags",
            "-e", "tcp.window_size",
            "-e", "tcp.options",
            "-J", "tcp",  // Only TCP packets
        ])
        .output()?;

    if !output.status.success() {
        println!("Error running tshark: {}", String::from_utf8_lossy(&output.stderr).to_string());
        return Err(PcapError::ParseError(
            String::from_utf8_lossy(&output.stderr).to_string()
        ));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let packets: Vec<Value> = serde_json::from_str(&json_str)?;

    // Parse JSON into NetworkPacket structs
    let network_packets = packets.into_iter()
        .filter_map(|packet| parse_packet_json(packet).ok())
        .collect();

    Ok(network_packets)
}

fn parse_packet_json(json: Value) -> Result<NetworkPacket, PcapError> {
    let layers = json.get("_source")
        .and_then(|src| src.get("layers"))
        .ok_or_else(|| PcapError::ParseError("Invalid JSON structure".to_string()))?;

    // Parse timestamp - get first element from array
    let timestamp = layers.get("frame.time_epoch")
        .and_then(|t| t.as_array())
        .and_then(|arr| arr.first())
        .and_then(|t| t.as_str())
        .and_then(|t| t.parse::<f64>().ok())
        .map(|t| {
            let secs = t.trunc() as i64;
            let nsecs = (t.fract() * 1_000_000_000.0) as u32;
            DateTime::<Utc>::from_timestamp(secs, nsecs)
                .unwrap_or_default()
        })
        .ok_or_else(|| PcapError::ParseError("Invalid timestamp".to_string()))?;

    // Parse other layers
    let ethernet_layer = parse_ethernet_layer(layers)?;
    let ip_layer = parse_ip_layer(layers)?;
    let tcp_layer = parse_tcp_layer(layers)?;
    let application_layer = parse_application_layer(layers)?;

    Ok(NetworkPacket {
        timestamp,
        ethernet_layer,
        ip_layer,
        tcp_layer,
        application_layer,
    })
}

fn parse_ethernet_layer(layers: &Value) -> Result<EthernetFrame, PcapError> {
    Ok(EthernetFrame {
        source_mac: parse_mac_address(layers.get("eth.src")
            .and_then(|mac| mac.as_array())
            .and_then(|arr| arr.first())
            .and_then(|mac| mac.as_str())
            .ok_or_else(|| PcapError::ParseError("Invalid source MAC".to_string()))?),
        destination_mac: parse_mac_address(layers.get("eth.dst")
            .and_then(|mac| mac.as_array())
            .and_then(|arr| arr.first())
            .and_then(|mac| mac.as_str())
            .ok_or_else(|| PcapError::ParseError("Invalid destination MAC".to_string()))?),
        ethertype: layers.get("eth.type")
            .and_then(|t| t.as_array())
            .and_then(|arr| arr.first())
            .and_then(|t| t.as_str())
            .and_then(|t| u16::from_str_radix(t, 16).ok())
            .unwrap_or(0x0800),
        frame_check_sequence: 0,
    })
}

fn parse_ip_layer(layers: &Value) -> Result<IPv4Packet, PcapError> {
    Ok(IPv4Packet {
        version: 4,
        ihl: 5,
        dscp: 0,
        ecn: 0,
        total_length: 0,
        identification: 0,
        flags: IPv4Flags {
            reserved: false,
            dont_fragment: false,
            more_fragments: false,
        },
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        header_checksum: 0,
        source_ip: parse_ip_address(layers.get("ip.src")
            .and_then(|ip| ip.as_array())
            .and_then(|arr| arr.first())
            .and_then(|ip| ip.as_str())
            .ok_or_else(|| PcapError::ParseError("Invalid source IP".to_string()))?),
        destination_ip: parse_ip_address(layers.get("ip.dst")
            .and_then(|ip| ip.as_array())
            .and_then(|arr| arr.first())
            .and_then(|ip| ip.as_str())
            .ok_or_else(|| PcapError::ParseError("Invalid destination IP".to_string()))?),
        options: Vec::new(),
    })
}

fn parse_tcp_layer(layers: &Value) -> Result<TCPSegment, PcapError> {
    let flags = parse_tcp_flags(layers.get("tcp.flags")
        .and_then(|f| f.as_array())
        .and_then(|arr| arr.first())
        .and_then(|f| f.as_str())
        .unwrap_or("0x000"));

    Ok(TCPSegment {
        source_port: layers.get("tcp.srcport")
            .and_then(|p| p.as_array())
            .and_then(|arr| arr.first())
            .and_then(|p| p.as_str())
            .and_then(|p| p.parse().ok())
            .unwrap_or(0),
        destination_port: layers.get("tcp.dstport")
            .and_then(|p| p.as_array())
            .and_then(|arr| arr.first())
            .and_then(|p| p.as_str())
            .and_then(|p| p.parse().ok())
            .unwrap_or(0),
        sequence_number: layers.get("tcp.seq")
            .and_then(|s| s.as_array())
            .and_then(|arr| arr.first())
            .and_then(|s| s.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        acknowledgment_number: layers.get("tcp.ack")
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.first())
            .and_then(|a| a.as_str())
            .and_then(|a| a.parse().ok())
            .unwrap_or(0),
        data_offset: 5,
        flags,
        window_size: layers.get("tcp.window_size")
            .and_then(|w| w.as_array())
            .and_then(|arr| arr.first())
            .and_then(|w| w.as_str())
            .and_then(|w| w.parse().ok())
            .unwrap_or(0),
        checksum: 0,
        urgent_pointer: 0,
        options: Vec::new(),
    })
}

/// Helper function to parse MAC address string into bytes
fn parse_mac_address(mac_str: &str) -> [u8; 6] {
    let mut mac = [0u8; 6];
    let parts: Vec<&str> = mac_str.split(':').collect();
    for (i, part) in parts.iter().enumerate() {
        if i < 6 {
            mac[i] = u8::from_str_radix(part, 16).unwrap_or(0);
        }
    }
    mac
}

/// Helper function to parse IP address string into bytes
fn parse_ip_address(ip_str: &str) -> [u8; 4] {
    let mut ip = [0u8; 4];
    let parts: Vec<&str> = ip_str.split('.').collect();
    for (i, part) in parts.iter().enumerate() {
        if i < 4 {
            ip[i] = part.parse().unwrap_or(0);
        }
    }
    ip
}

/// Helper function to parse TCP flags
fn parse_tcp_flags(flags_str: &str) -> TCPFlags {
    let flags_value = u16::from_str_radix(&flags_str.trim_start_matches("0x"), 16).unwrap_or(0);
    
    TCPFlags {
        fin: flags_value & 0x001 != 0,
        syn: flags_value & 0x002 != 0,
        rst: flags_value & 0x004 != 0,
        psh: flags_value & 0x008 != 0,
        ack: flags_value & 0x010 != 0,
        urg: flags_value & 0x020 != 0,
        ece: flags_value & 0x040 != 0,
        cwr: flags_value & 0x080 != 0,
    }
}

/// Check if tshark is installed
fn is_tshark_installed() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .is_ok()
}