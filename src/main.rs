#![allow(
    // unused,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    special_module_name
)]

use affinity::{get_core_num, set_thread_affinity};
use lib::blacklist::Blacklist;
use log::{debug, info};
use monitor::Monitor;
use probe_modules::module_tcp_synscan::PCAP_FILTER;
use recv::Receiver;
use send::Sender;

use crate::{config::create_context, probe_modules::module_tcp_synscan::NaviveProbeGenerator};

mod config;
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

    let ctx = create_context();
    let blacklist = Blacklist::new(
        ctx.config.whitelist_file.clone(),
        ctx.config.blacklist_file.clone(),
    );

    let num_cores = get_core_num();

    // Spawn a packet capture thread
    let ctx_clone = ctx.clone();
    let recv_thread = std::thread::spawn(move || {
        set_thread_affinity([0]).unwrap();
        let receiver = Receiver::new(PCAP_FILTER, ctx_clone);
        receiver.run();
    });
    loop {
        if ctx.receiver_state.lock().unwrap().ready {
            debug!("Receiver thread ready");
            break;
        }
    }

    // Create sender threads
    let ctx_clone = ctx.clone();
    let sender = Sender::new(ctx_clone, blacklist);
    let mut send_threads = vec![];
    let mut core = 1;
    for _ in 0..ctx.config.sender_threads {
        let mut sender_clone = sender.clone();
        let send_thread = std::thread::spawn(move || {
            set_thread_affinity([core % num_cores]).unwrap();
            let mut probe_generator = NaviveProbeGenerator::new();
            sender_clone.run(&mut probe_generator);
        });
        send_threads.push(send_thread);
        core += 1;
    }

    // Create monitor thread
    let ctx_clone = ctx.clone();
    let monitor_thread = std::thread::spawn(move || {
        let core = (1 + ctx.config.sender_threads as usize) % num_cores;
        set_thread_affinity([core]).unwrap();
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
