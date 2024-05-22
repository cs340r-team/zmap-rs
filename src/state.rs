use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::{crypto::AesCtx, lib::validate};

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
            dryrun: false,
            quiet: false,
            summary: false,
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
    pub first_scanned: u32,
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
            first_scanned: 0,
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

        // TODO: other configuration setup

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
