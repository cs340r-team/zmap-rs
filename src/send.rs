use std::time::Instant;

use log::{debug, info, warn};

use crate::config::Context;
use crate::crypto::Cyclic;
use crate::lib::blacklist::Blacklist;
use crate::lib::validate;
use crate::net::socket::RawEthSocket;
use crate::net::{get_interface_index, get_interface_mac};
use crate::probe_modules::module_tcp_synscan::synscan_print_packet;
use crate::probe_modules::probe_modules::ProbeGenerator;

#[derive(Clone)]
pub struct Sender {
    ctx: Context,
    cyclic: Cyclic,
    blacklist: Blacklist,
}

impl Sender {
    pub fn new(ctx: Context, blacklist: Blacklist) -> Self {
        // Create a generator and starting position
        let mut cyclic = Cyclic::new();

        let mut zsend = ctx.sender_state.lock().unwrap();

        // Advance past any blacklisted addresses
        zsend.first_scanned = cyclic.current_ip();
        while !blacklist.is_allowed(zsend.first_scanned) {
            zsend.blacklisted += 1;
            zsend.first_scanned = cyclic.next_ip();
        }

        let allowed = blacklist.count_allowed();
        if allowed == (1u64 << 32) {
            zsend.targets = u32::MAX;
        } else {
            zsend.targets = allowed as u32;
        }

        if zsend.targets > ctx.config.max_targets {
            zsend.targets = ctx.config.max_targets;
        }

        assert!(
            ctx.config.source_ip_first == ctx.config.source_ip_last,
            "zmap-rs only supports sending from a single IP for now"
        );

        debug!(
            "Sender will send from 1 address on {} source ports",
            ctx.config.source_port_last - ctx.config.source_port_first + 1
        );

        if ctx.config.dryrun {
            info!("Sender in dryrun mode -- won't actually send packets");
        }

        zsend.start = Instant::now();
        drop(zsend);

        Self {
            ctx,
            cyclic,
            blacklist,
        }
    }

    pub fn run(&mut self, probe_module: &mut dyn ProbeGenerator) {
        debug!("Sender thread started and running");
        let zsend = self.ctx.sender_state.lock().unwrap();

        let socket = RawEthSocket::new();
        let interface_index = get_interface_index(&self.ctx.config.interface).unwrap();
        let source_mac = get_interface_mac(&self.ctx.config.interface).unwrap();
        let gateway_mac = self.ctx.config.gw_mac;

        // We don't currently cache packets, so this is a no-op
        probe_module.thread_initialize(&source_mac, &gateway_mac);
        drop(zsend);

        let mut count: u32 = 0;
        let mut last_count = count;
        let mut last_time = Instant::now();
        let mut delay: f64 = 0.0;
        let mut interval: u32 = 0;

        if self.ctx.config.rate > 0 {
            // Estimate initial rate
            delay = 10000.0;
            for _ in 0..delay as u32 {
                std::hint::spin_loop();
            }

            let duration = (Instant::now() - last_time).as_secs_f64();
            delay *=
                (1.0 / duration / (self.ctx.config.rate / self.ctx.config.sender_threads) as f64);

            interval = ((self.ctx.config.rate / self.ctx.config.sender_threads) / 20) as u32;
            last_time = Instant::now();
        }

        loop {
            if delay > 0.0 {
                count += 1;
                for _ in 0..delay as u32 {
                    std::hint::spin_loop();
                }

                if interval == 0 || (count % interval == 0) {
                    let t = Instant::now();
                    let duration = (t - last_time).as_secs_f64();
                    delay *= (count - last_count) as f64
                        / duration
                        / (self.ctx.config.rate / self.ctx.config.sender_threads) as f64;

                    if delay < 1.0 {
                        delay = 1.0;
                    }

                    last_count = count;
                    last_time = t;
                }
            }

            // Generate next ip from cyclic group and update global state
            let mut zsend = self.ctx.sender_state.lock().unwrap();
            if zsend.complete {
                break;
            }

            if zsend.sent >= self.ctx.config.max_targets {
                zsend.complete = true;
                zsend.finish = Instant::now();
                break;
            }

            if self.ctx.config.max_runtime > 0
                && self.ctx.config.max_runtime <= (Instant::now() - zsend.start).as_secs() as u32
            {
                zsend.complete = true;
                zsend.finish = Instant::now();
                break;
            }

            let mut destination_ip = self.cyclic.next_ip();
            while !self.blacklist.is_allowed(destination_ip) {
                destination_ip = self.cyclic.next_ip();
                zsend.blacklisted += 1;
            }

            if destination_ip == zsend.first_scanned {
                zsend.complete = true;
                zsend.finish = Instant::now();
            }

            zsend.sent += 1;
            drop(zsend);

            for i in 0..self.ctx.config.probes {
                let source_ip = self.ctx.config.source_ip_first;
                let validation = validate::gen(&self.ctx.validate_ctx, &source_ip, &destination_ip);
                let validation = [
                    u32::from_be_bytes(validation[0..4].try_into().unwrap()),
                    u32::from_be_bytes(validation[4..8].try_into().unwrap()),
                ];

                let packet = probe_module.make_packet(
                    &source_ip,
                    &destination_ip,
                    &validation,
                    i,
                    self.ctx.config.source_port_first,
                    self.ctx.config.source_port_last,
                    self.ctx.config.target_port,
                );

                if self.ctx.config.dryrun {
                    if !self.ctx.config.quiet {
                        synscan_print_packet(packet);
                    }
                } else {
                    let res = socket.sendto(packet, interface_index, &gateway_mac);
                    if let Err(e) = res {
                        warn!("Sender sendto failed for {destination_ip}. Reason: {}", e);
                        self.ctx.sender_state.lock().unwrap().sendto_failures += 1;
                    }
                }
            }
        }

        debug!("Sender finished");
    }
}
