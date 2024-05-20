#![allow(
    unused,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    special_module_name
)]

use net::{get_interface_index, socket::RawEthSocket, MacAddress};

mod crypto;
mod lib;
mod net;
// mod probe_modules;
mod recv;

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .format_target(false)
        .init();

    // Spawn a thread to run the packet capture,
    // more complex logic will be added around this
    // let recv_thread = std::thread::spawn(|| {
    //     recv::run();
    // });
    // recv_thread.join().unwrap();

    let socket = RawEthSocket::new();
    let gateway_mac = MacAddress::from_str("e2:f9:f6:db:38:4a").unwrap();
    let interface_index = get_interface_index("enp0s1").unwrap(); // Our default interface

    let buf = [
        0xef, 0xf9, 0xf6, 0xdb, 0x38, 0x4a, // destination
        0xde, 0xf0, 0xf1, 0xaa, 0xb9, 0x4b, // source
        0x22, 0xf0, // transport protocol
        0xfc, 0x06, 0x00, 0x2c, 0x00, 0x00, // payload
    ];

    socket.sendto(&buf, interface_index, &gateway_mac).unwrap()
}
