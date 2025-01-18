mod packet;
mod parser;

use std::path::Path;
use packet::*;
use parser::parse_pcap;
fn main() {
    let path = Path::new("src/example/pcap/wps.pcap");
    let res = match parse_pcap(path) {
        Ok(res) => res,
        Err(e) => {
            println!("{:#?}", e);
            return;
        }
    };
    println!("{:#?}", res);
}
