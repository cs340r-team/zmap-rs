#![allow(
    unused,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    special_module_name
)]

use std::sync::{Arc, Mutex};

use affinity::{get_core_num, set_thread_affinity};
use config::Context;
use lib::blacklist::Blacklist;
use log::{debug, info};
use monitor::Monitor;
use probe_modules::module_tcp_synscan::PCAP_FILTER;
use recv::Receiver;
use send::Sender;

use crate::config::create_context;
use crate::crypto::Cyclic;

mod config;
mod crypto;
mod lib;
mod monitor;
mod net;
mod probe_modules;
mod recv;
mod send;
mod state;

fn dump_summary(ctx: &Context) {
    let zsend = ctx.sender_state.lock().unwrap();
    let zsend_sent = zsend.sent;
    let zsend_sendto_failures = zsend.sendto_failures;
    let zsend_blacklisted = zsend.blacklisted;
    let zsend_first_scanned = zsend.first_scanned;
    drop(zsend);

    let zrecv = ctx.receiver_state.lock().unwrap();
    let zrecv_success_total = zrecv.success_total;
    let zrecv_success_unique = zrecv.success_unique;
    let zrecv_cooldown_total = zrecv.cooldown_total;
    let zrecv_cooldown_unique = zrecv.cooldown_unique;
    let zrecv_failure_total = zrecv.failure_total;
    drop(zrecv);

    let hitrate = ((zrecv_success_unique as f64) * 100.0) / (zsend_sent as f64);

    println!("target-port {}", ctx.config.target_port);
    println!("source-port-range-begin {}", ctx.config.source_port_first);
    println!("source-port-range-end {}", ctx.config.source_port_last);
    println!("source-addr-range-begin {}", ctx.config.source_ip_first);
    println!("source-addr-range-end {}", ctx.config.source_ip_last);
    println!("maximum-targets {}", ctx.config.max_targets);
    println!("maximum-runtime {}", ctx.config.max_runtime);
    println!("maximum-results {}", ctx.config.max_results);
    println!("permutation-seed {}", ctx.config.seed);
    println!("cooldown-period {:?}", ctx.config.cooldown_secs);
    println!("send-interface {}", ctx.config.interface);
    println!("rate (packets per second) {}", ctx.config.rate);
    println!("bandwidth {}", ctx.config.bandwidth);
    println!("sent {}", zsend_sent);
    println!("blacklisted {}", zsend_blacklisted);
    println!("first-scanned {}", zsend_first_scanned);
    println!("hit-rate {:.6}%", hitrate);
    println!("success-total {}", zrecv_success_total);
    println!("success-unique {}", zrecv_success_unique);
    println!("success-cooldown-total {}", zrecv_cooldown_total);
    println!("success-cooldown-unique {}", zrecv_cooldown_unique);
    println!("failure-total {}", zrecv_failure_total);
    println!("sendto-failures {}", zsend_sendto_failures);
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .format_target(false)
        .init();

    let ctx = create_context();

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
    let mut send_threads = vec![];
    let mut core = 1;
    let cyclic = Arc::new(Mutex::new(Cyclic::new()));
    for _ in 0..ctx.config.sender_threads {
        let ctx = ctx.clone();
        let cyclic = cyclic.clone();

        let send_thread = std::thread::spawn(move || {
            set_thread_affinity([core % num_cores]).unwrap();

            let blacklist = Blacklist::new(
                ctx.config.whitelist_file.clone(),
                ctx.config.blacklist_file.clone(),
            );

            let mut sender = Sender::new(ctx, cyclic, blacklist);
            sender.run();
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

    dump_summary(&ctx);
    info!("zmap-rs completed");
}
