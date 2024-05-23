use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use log::{debug, warn};

use crate::{crypto::AesCtx, lib::validate, probe_modules::module_tcp_synscan};

#[derive(Clone, Debug)]
pub struct Config {
    pub log_level: log::LevelFilter,
    pub source_port_first: u16,
    pub source_port_last: u16,
    pub output_filename: String,
    pub blacklist_filename: String,
    pub whitelist_filename: String,
    pub target_port: u16,
    pub max_targets: u32,
    pub max_runtime: u32,
    pub max_results: u32,
    pub iface: String,
    pub rate: i32,
    pub bandwidth: u64,
    pub cooldown_secs: Duration,
    pub senders: i32,
    pub packet_streams: u32,
    pub use_seed: bool,
    pub seed: u32,
    pub gw_mac: String,
    pub dryrun: bool,
    pub quiet: bool,
    pub summary: bool,
    pub source_ip_first: Ipv4Addr,
    pub source_ip_last: Ipv4Addr,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            log_level: log::LevelFilter::Debug,
            source_port_first: 32768,
            source_port_last: 61000,
            output_filename: Default::default(),
            blacklist_filename: Default::default(),
            whitelist_filename: Default::default(),
            target_port: 0,
            max_targets: u32::MAX,
            max_runtime: 0,
            max_results: 0,
            iface: Default::default(),
            rate: 0,
            bandwidth: 0,
            cooldown_secs: Duration::new(8, 0),
            senders: 1,
            packet_streams: 1,
            use_seed: false,
            seed: 0,
            gw_mac: Default::default(),
            dryrun: true,
            quiet: false,
            summary: false,
            source_ip_first: Ipv4Addr::new(0, 0, 0, 0),
            source_ip_last: Ipv4Addr::new(0, 0, 0, 0),
        }
    }
}

#[derive(Debug)]
pub struct SenderStats {
    pub complete: bool,
    pub start: Instant,
    pub finish: Instant,
    pub sent: u32,
    pub blacklisted: u32,
    pub first_scanned: Ipv4Addr,
    pub targets: u32,
    pub sendto_failures: u32,
}

impl Default for SenderStats {
    fn default() -> Self {
        Self {
            complete: false,
            start: Instant::now(),
            finish: Instant::now(),
            sent: 0,
            blacklisted: 0,
            first_scanned: Ipv4Addr::new(0, 0, 0, 0),
            targets: 0,
            sendto_failures: 0,
        }
    }
}

#[derive(Debug)]
pub struct ReceiverStats {
    pub ready: bool,
    pub complete: bool,
    pub success_unique: u32,
    pub success_total: u32,
    pub cooldown_unique: u32,
    pub cooldown_total: u32,
    pub failure_total: u32,
    pub start: Instant,
    pub finish: Instant,
    pub pcap_recv: u32,
    pub pcap_drop: u32,
    pub pcap_ifdrop: u32,
}

impl Default for ReceiverStats {
    fn default() -> Self {
        Self {
            ready: false,
            complete: false,
            success_unique: 0,
            success_total: 0,
            cooldown_unique: 0,
            cooldown_total: 0,
            failure_total: 0,
            start: Instant::now(),
            finish: Instant::now(),
            pcap_recv: 0,
            pcap_drop: 0,
            pcap_ifdrop: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Context {
    pub config: Config,
    pub validate_ctx: AesCtx,
    pub sender_stats: Arc<Mutex<SenderStats>>,
    pub receiver_stats: Arc<Mutex<ReceiverStats>>,
}

impl Context {
    pub fn new() -> Self {
        let mut config = Config::default();
        if (config.max_results == 0) {
            config.max_results = u32::MAX;
        }

        config.target_port = 443;
        config.rate = 1;
        config.output_filename = String::from("test-recv.log");

        // From send.c (sender rate config)
        if config.bandwidth > 0 {
            let mut packet_len = module_tcp_synscan::PACKET_LENGTH;
            packet_len *= 8;
            packet_len += 8 * 24; // 7 byte MAC preamble, 1 byte Start frame,
                                  // 4 byte CRC, 12 byte inter-frame gap
            if packet_len < 84 * 8 {
                packet_len = 84 * 8;
            }

            if config.bandwidth / packet_len > 0xFFFFFFFF {
                config.rate = 0;
            } else {
                config.rate = (config.bandwidth / packet_len) as i32;
                if config.rate == 0 {
                    warn!(
                        "Sender bandwidth {} bit/s is slower that 1 pkt/s, setting rate to 1 pkt/s",
                        config.bandwidth
                    );
                    config.rate = 1;
                }
            }
            debug!(
                "Sender using bandwidth {} bit/s, rate set to {} pkt/s",
                config.bandwidth, config.rate
            );
        }

        // TODO: other configuration setup

        // TODO: get source interface IP address
        // TODO: get gateway mac address

        let validate_ctx = validate::new_context();
        let sender_stats = Arc::new(Mutex::new(SenderStats::default()));
        let receiver_stats = Arc::new(Mutex::new(ReceiverStats::default()));

        Self {
            config,
            validate_ctx,
            sender_stats,
            receiver_stats,
        }
    }
}
