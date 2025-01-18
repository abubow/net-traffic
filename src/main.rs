mod packet;
mod parser;
mod sessions;

use std::path::Path;
// for writing to files
use std::fs::File;
use std::io::prelude::*;
use serde_json::Value;
use serde_json::json;

#[allow(unused_imports)]
use packet::*;
use parser::parse_pcap;
use sessions::find_tcp_sessions;
fn main() {
    let path = Path::new("src/example/pcap/rsasnakeoil2.pcap");
    let res = match parse_pcap(path) {
        Ok(res) => res,
        Err(e) => {
            println!("{:#?}", e);
            return;
        }
    };
    println!("Got {} packets", res.len());

    // write to file
    let mut file = File::create("src/example/pcap/packets.json").unwrap();
    file.write_all(json!(res).to_string().as_bytes()).unwrap();

    let sessions = find_tcp_sessions(&res);
    println!("Got {} sessions", sessions.len());

    // Write sessions to file
    let mut file = File::create("src/example/pcap/tcp_sessions.json").unwrap();
    file.write_all(json!(sessions).to_string().as_bytes()).unwrap();

    println!("TCP sessions saved to tcp_sessions.json");
}
