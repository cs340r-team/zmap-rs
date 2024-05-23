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

use crate::{probe_modules::module_tcp_synscan::PCAP_FILTER, send::Sender};

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

    let ctx = Context::new();

    // Spawn a thread to run the packet capture
    let ctx_clone = ctx.clone();
    let recv_thread = std::thread::spawn(move || {
        let receiver = Receiver::new(PCAP_FILTER, ctx_clone);
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
    for _ in 0..ctx.config.senders {
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
}
