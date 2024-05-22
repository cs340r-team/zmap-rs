use log::info;

use crate::net::pcap::*;

pub fn run() {
    let mut capture = PacketCapture::new("enp0s1").with_filter("tcp port 9000");

    loop {
        let packet = capture.next_packet();
        println!("{packet:?}");

        // Check other conditions here, see src/recv.c in the original project
    }
}
