use std::collections::HashMap;
use serde::Serialize;
use chrono::DateTime;
use chrono::Utc;
use crate::NetworkPacket;

/// Represents a TCP session
#[derive(Debug, Serialize)]
pub struct TCPSession {
    source_port: u16,
    destination_port: u16,
    source_ip: [u8; 4],
    destination_ip: [u8; 4],
    start_timestamp: DateTime<Utc>,
    end_timestamp: Option<DateTime<Utc>>,
    packets: Vec<NetworkPacket>,
}

pub fn find_tcp_sessions(packets: &[NetworkPacket]) -> Vec<TCPSession> {
    let mut sessions: HashMap<(u16, u16, [u8; 4], [u8; 4]), (DateTime<Utc>, Option<DateTime<Utc>>, Vec<NetworkPacket>)> = HashMap::new();

    for packet in packets {
        if packet.tcp_layer.flags.syn {
            // Start of a new session
            let key = (
                packet.tcp_layer.source_port,
                packet.tcp_layer.destination_port,
                packet.ip_layer.source_ip,
                packet.ip_layer.destination_ip,
            );
            sessions
                .entry(key)
                .or_insert((packet.timestamp, None, vec![]))
                .2
                .push(packet.clone());
        }

        if packet.tcp_layer.flags.fin {
            // End of an existing session
            let key = (
                packet.tcp_layer.destination_port,
                packet.tcp_layer.source_port,
                packet.ip_layer.destination_ip,
                packet.ip_layer.source_ip,
            );

            if let Some(session) = sessions.get_mut(&key) {
                session.1 = Some(packet.timestamp);
                session.2.push(packet.clone());
            }
        }

        // Track packets for ongoing sessions
        for session in sessions.values_mut() {
            session.2.push(packet.clone());
        }
    }

    // Convert to vector format
    sessions
        .into_iter()
        .map(|(key, (start, end, packets))| TCPSession {
            source_port: key.0,
            destination_port: key.1,
            source_ip: key.2,
            destination_ip: key.3,
            start_timestamp: start,
            end_timestamp: end,
            packets,
        })
        .collect()
}