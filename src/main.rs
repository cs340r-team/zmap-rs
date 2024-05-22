#![allow(
    unused,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    special_module_name
)]

use std::time::Instant;

use recv::Receiver;
use state::Context;

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

    let context = Context::new();

    // Spawn a thread to run the packet capture
    let context_clone = context.clone();
    let recv_thread = std::thread::spawn(move || {
        let receiver = Receiver::new("enp0s1".into(), "tcp port 9000".into(), context_clone);
        receiver.run();
    });

    // Dummy sender
    let context_clone = context.clone();
    let send_thread = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let mut zsend = context_clone.sender_stats.lock().unwrap();
        zsend.complete = true;
        zsend.finish = Instant::now();
    });

    recv_thread.join().unwrap();
    send_thread.join().unwrap();

    println!("recv_stats: {:?}", context.receiver_stats.lock().unwrap());

    // let socket = RawEthSocket::new();
    // let interface_index = get_interface_index("enp0s1").unwrap(); // Our default interface

    // let source_mac = MacAddress::from_str("aa:41:72:51:54:42").unwrap();
    // let gateway_mac = MacAddress::from_str("e2:f9:f6:db:38:4a").unwrap();

    // let source_ip = Ipv4Addr::new(192, 168, 0, 2);

    // let packet = synscan_make_packet(
    //     &source_mac,
    //     &gateway_mac,
    //     source_ip,
    //     Ipv4Addr::new(192, 168, 0, 5),
    //     &[1, 2, 3, 4],
    //     1,
    //     &config,
    // );

    // socket
    //     .sendto(&packet, interface_index, &gateway_mac)
    //     .expect("Could not send packet");

    // let packet = synscan_make_packet(
    //     &source_mac,
    //     &gateway_mac,
    //     source_ip,
    //     Ipv4Addr::new(192, 168, 0, 10),
    //     &[91, 92, 93, 94],
    //     2,
    //     &config,
    // );

    // socket
    //     .sendto(&packet, interface_index, &gateway_mac)
    //     .expect("Could not send packet");
}
