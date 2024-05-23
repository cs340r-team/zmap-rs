#![allow(
    unused,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    special_module_name
)]

use log::{debug, info};
use recv::Receiver;
use state::Context;

use crate::send::Sender;

mod crypto;
mod lib;
mod net;
mod probe_modules;
mod recv;
mod send;
mod state;

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .format_target(false)
        .init();

    let mut ctx = Context::new();
    ctx.config.iface = "enp0s1".into();

    // Spawn a thread to run the packet capture
    let ctx_clone = ctx.clone();
    let recv_thread = std::thread::spawn(move || {
        let receiver = Receiver::new("tcp port 9000".into(), ctx_clone);
        receiver.run();
    });

    loop {
        if ctx.receiver_stats.lock().unwrap().ready {
            debug!("Receiver thread ready");
            break;
        }
    }

    let ctx_clone = ctx.clone();
    let sender = Sender::new(ctx_clone);
    let mut send_threads = vec![];
    for i in 0..ctx.config.senders {
        let mut sender_clone = sender.clone();
        let send_thread = std::thread::spawn(move || {
            sender_clone.run();
        });
        send_threads.push(send_thread);
    }

    // Wait for completion
    for send_thread in send_threads {
        send_thread.join().expect("Unable to join sender thread");
    }

    debug!("Senders finished");
    recv_thread.join().expect("Unable to join receiver thread");

    // TODO: print summary statistics
    println!("recv_stats: {:?}", ctx.receiver_stats.lock().unwrap());

    info!("zmap-rs completed");

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
