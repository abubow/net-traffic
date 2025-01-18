mod packet;
mod parser;

use std::path::Path;
// for writing to files
use std::fs::File;
use std::io::prelude::*;
use serde_json::Value;
use serde_json::json;

#[allow(unused_imports)]
use packet::*;
use parser::parse_pcap;
fn main() {
    let path = Path::new("src/example/pcap/VLAN6.pcap");
    let res = match parse_pcap(path) {
        Ok(res) => res,
        Err(e) => {
            println!("{:#?}", e);
            return;
        }
    };
    println!("Got {} packets", res.len());

    // write to file
    let mut file = File::create("src/example/pcap/output.json").unwrap();
    file.write_all(json!(res).to_string().as_bytes()).unwrap();
}
