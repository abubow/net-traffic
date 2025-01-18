use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkPacket {
    pub timestamp: DateTime<Utc>,
    pub ethernet_layer: EthernetFrame,
    pub ip_layer: IPv4Packet,
    pub tcp_layer: TCPSegment,
    pub application_layer: ApplicationData,
}

/// Ethernet (Layer 2) Frame
#[derive(Debug, Serialize, Deserialize)]
pub struct EthernetFrame {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub ethertype: u16,  // 0x0800 for IPv4
    pub frame_check_sequence: u32,
}

/// IPv4 (Layer 3) Packet
#[derive(Debug, Serialize, Deserialize)]
pub struct IPv4Packet {
    pub version: u8,          // 4 for IPv4
    pub ihl: u8,             // Internet Header Length
    pub dscp: u8,            // Differentiated Services Code Point
    pub ecn: u8,             // Explicit Congestion Notification
    pub total_length: u16,
    pub identification: u16,
    pub flags: IPv4Flags,
    pub fragment_offset: u16,
    pub ttl: u8,             // Time To Live
    pub protocol: u8,        // 6 for TCP
    pub header_checksum: u16,
    pub source_ip: [u8; 4],
    pub destination_ip: [u8; 4],
    pub options: Vec<u8>,    // Optional IPv4 options
}

/// IPv4 Flags
#[derive(Debug, Serialize, Deserialize)]
pub struct IPv4Flags {
    pub reserved: bool,      // Must be zero
    pub dont_fragment: bool,
    pub more_fragments: bool,
}

/// TCP (Layer 4) Segment
#[derive(Debug, Serialize, Deserialize)]
pub struct TCPSegment {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,     // Header length in 32-bit words
    pub flags: TCPFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<TCPOption>,
}

/// TCP Flags
#[derive(Debug, Serialize, Deserialize)]
pub struct TCPFlags {
    pub fin: bool,          // Finish
    pub syn: bool,          // Synchronize
    pub rst: bool,          // Reset
    pub psh: bool,          // Push
    pub ack: bool,          // Acknowledgment
    pub urg: bool,          // Urgent
    pub ece: bool,          // ECN-Echo
    pub cwr: bool,          // Congestion Window Reduced
}

/// TCP Option
#[derive(Debug, Serialize, Deserialize)]
pub struct TCPOption {
    pub kind: u8,
    pub length: u8,
    pub data: Vec<u8>,
}

/// Application Layer Data
#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationData {
    pub protocol: ApplicationProtocol,
    pub payload: Vec<u8>,
}

/// Supported Application Protocols
#[derive(Debug, Serialize, Deserialize)]
pub enum ApplicationProtocol {
    HTTP,
    HTTPS,
    FTP,
    SSH,
    SMTP,
    DNS,
    Custom(String),
}

/// Implementation for NetworkPacket
impl NetworkPacket {
    /// Calculate the total size of the packet in bytes
    pub fn total_size(&self) -> usize {
        14 + // Ethernet header (without FCS)
        20 + self.ip_layer.options.len() + // IPv4 header
        20 + self.tcp_layer.options.iter().map(|opt| opt.length as usize).sum::<usize>() + // TCP header
        self.application_layer.payload.len() // Application data
    }
    
    /// Check if packet is part of a TCP handshake
    pub fn is_handshake(&self) -> bool {
        self.tcp_layer.flags.syn || self.tcp_layer.flags.fin
    }
    
    /// Get the application protocol as a string
    pub fn get_protocol_string(&self) -> String {
        match &self.application_layer.protocol {
            ApplicationProtocol::HTTP => "HTTP".to_string(),
            ApplicationProtocol::HTTPS => "HTTPS".to_string(),
            ApplicationProtocol::FTP => "FTP".to_string(),
            ApplicationProtocol::SSH => "SSH".to_string(),
            ApplicationProtocol::SMTP => "SMTP".to_string(),
            ApplicationProtocol::DNS => "DNS".to_string(),
            ApplicationProtocol::Custom(proto) => proto.clone(),
        }
    }
}