#![allow(
    unused,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    special_module_name
)]

use lib::blacklist::Blacklist;
use log::{debug, info};
use monitor::Monitor;
use probe_modules::module_tcp_synscan::PCAP_FILTER;
use recv::Receiver;
use send::Sender;
use state::Context;

mod crypto;
mod lib;
mod monitor;
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

    let blacklist = Blacklist::new(None, Some("./conf/blocklist.conf"));

    // Spawn a thread to run the packet capture
    let ctx_clone = ctx.clone();
    let recv_thread = std::thread::spawn(move || {
        let receiver = Receiver::new(PCAP_FILTER, ctx_clone);
        receiver.run();
    });

    loop {
        if ctx.receiver_state.lock().unwrap().ready {
            debug!("Receiver thread ready");
            break;
        }
    }

    let ctx_clone = ctx.clone();
    let sender = Sender::new(ctx_clone, blacklist);

    let mut send_threads = vec![];
    for _ in 0..ctx.config.senders {
        let mut sender_clone = sender.clone();
        let send_thread = std::thread::spawn(move || {
            sender_clone.run();
        });
        send_threads.push(send_thread);
    }

    let ctx_clone = ctx.clone();
    let monitor_thread = std::thread::spawn(move || {
        let mut monitor = Monitor::new(ctx_clone);
        monitor.run();
    });

    // Wait for completion
    for send_thread in send_threads {
        send_thread.join().expect("Unable to join sender thread");
    }

    recv_thread.join().expect("Unable to join receiver thread");
    monitor_thread
        .join()
        .expect("Unable to join monitor thread");

    // TODO: print summary statistics
    println!("recv_stats: {:?}", ctx.receiver_state.lock().unwrap());

    info!("zmap-rs completed");
}
