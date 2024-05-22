use log::info;

use crate::net::pcap::*;

// This is an example callback function that will be called for each packet
// We will need to create a function similar to this one
pub extern "C" fn log_packet_handler(
    _usr: *mut c_uchar,
    h: *const pcap_pkthdr,
    bytes: *const c_uchar,
) {
    if h.is_null() || bytes.is_null() {
        return;
    }

    let ts = unsafe { (*h).ts };
    let caplen = unsafe { (*h).caplen };
    let len = unsafe { (*h).len };

    info!(
        "Captured packet, time: {}, caplen: {}, len: {}",
        ts.tv_sec, caplen, len
    );
}

pub fn run() {
    let mut capture = PacketCapture::new("enp0s1");
    capture.set_filter("tcp port 9000");
    loop {
        let packet = capture.next_packet();
        println!("{packet:?}");

        // Check other conditions here, see src/recv.c in the original project
    }
}
