#![allow(
    unused,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    special_module_name
)]

use std::net::Ipv4Addr;

use net::{get_interface_index, socket::RawEthSocket, MacAddress};
use probe_modules::module_tcp_synscan::synscan_make_packet;
use state::Config;

mod crypto;
mod lib;
mod net;
mod probe_modules;
mod recv;
mod state;

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

    let config = Config::default();

    let socket = RawEthSocket::new();
    let interface_index = get_interface_index("enp0s1").unwrap(); // Our default interface

    let source_mac = MacAddress::from_str("aa:41:72:51:54:42").unwrap();
    let gateway_mac = MacAddress::from_str("e2:f9:f6:db:38:4a").unwrap();

    let source_ip = Ipv4Addr::new(192, 168, 0, 2);

    let packet = synscan_make_packet(
        &source_mac,
        &gateway_mac,
        source_ip,
        Ipv4Addr::new(192, 168, 0, 5),
        &[1, 2, 3, 4],
        1,
        &config,
    );

    socket
        .sendto(&packet, interface_index, &gateway_mac)
        .expect("Could not send packet");

    let packet = synscan_make_packet(
        &source_mac,
        &gateway_mac,
        source_ip,
        Ipv4Addr::new(192, 168, 0, 10),
        &[91, 92, 93, 94],
        2,
        &config,
    );

    socket
        .sendto(&packet, interface_index, &gateway_mac)
        .expect("Could not send packet");
}
