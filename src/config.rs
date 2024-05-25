use std::{
    net::Ipv4Addr,
    num::ParseIntError,
    sync::{Arc, Mutex},
    time::Duration,
};

use clap::Parser;
use eui48::MacAddress;
use log::{debug, warn};

use crate::{
    crypto::AesCtx,
    lib::validate,
    net::{get_default_gw_mac, get_default_interface, get_interface_ip},
    probe_modules::module_tcp_synscan,
    state::{ReceiverState, SenderState},
};

fn parse_duration(arg: &str) -> Result<Duration, ParseIntError> {
    Ok(std::time::Duration::from_secs(arg.parse()?))
}

fn parse_bandwidth(arg: &str) -> Result<u64, ParseIntError> {
    let arg_split = arg.split_at(arg.len() - 1);
    let mut bandwidth: u64 = arg_split.0.parse()?;

    if arg_split.1 == "G" || arg_split.1 == "g" {
        bandwidth *= 1_000_000_000;
    } else if arg_split.1 == "M" || arg_split.1 == "m" {
        bandwidth *= 1_000_000;
    } else if arg_split.1 == "K" || arg_split.1 == "k" {
        bandwidth *= 1_000;
    } else {
        bandwidth = 0;
        warn!("Unknown bandwidth suffix (supported suffixes are G, M and K)");
    }

    Ok(bandwidth)
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Config {
    /// TCP port number to scan (for SYN scans)
    #[arg(short = 'p', long, default_value_t = 443)]
    pub target_port: u16,

    /// Output file
    #[arg(short, long, default_value_t = String::from("recv.log"))]
    pub output_file: String,

    /// File of subnets to exclude, in CIDR notation
    #[arg(short, long)]
    pub blacklist_file: Option<String>,

    /// File of subnets to constrain scan to, in CIDR notation
    #[arg(short, long)]
    pub whitelist_file: Option<String>,

    /// Cap number of targets to probe
    #[arg(short = 'n', long, default_value_t = u32::MAX)]
    pub max_targets: u32,

    /// Cap number of results to return
    #[arg(short = 'R', long, default_value_t = u32::MAX)]
    pub max_results: u32,

    /// Cap length of time for sending packets
    #[arg(short = 't', long, default_value_t = 0)]
    pub max_runtime: u32,

    /// Set send rate in packets/sec
    #[arg(short, long, default_value_t = 0)]
    pub rate: i32,

    /// Set send rate in bits/second (supports suffixes G, M and K)
    #[arg(short = 'B', long, value_parser = parse_bandwidth, default_value = "0K")]
    pub bandwidth: u64,

    /// How long to continue receiving after sending last probe
    #[arg(short, long, value_parser = parse_duration, default_value = "8")]
    pub cooldown_secs: Duration,

    /// Seed used to select address permutation
    #[arg(short = 'e', long, default_value_t = 0)]
    pub seed: u32,

    /// Threads used to send packets
    #[arg(short = 'T', long, default_value_t = 1)]
    pub sender_threads: i32,

    /// Number of probes to send to each IP
    #[arg(short = 'P', long, default_value_t = 1)]
    pub probes: u32,

    /// Don't actually send packets
    #[arg(short, long)]
    pub dryrun: bool,

    /// First source port for scan packets
    #[arg(long, default_value_t = 32768)]
    pub source_port_first: u16,

    /// Last source port for scan packets
    #[arg(long, default_value_t = 61000)]
    pub source_port_last: u16,

    /// First source address for scan packets
    #[arg(long, default_value = "0.0.0.0")]
    pub source_ip_first: Ipv4Addr,

    /// Last source address for scan packets
    #[arg(long, default_value = "0.0.0.0")]
    pub source_ip_last: Ipv4Addr,

    /// Specify network interface to use
    #[arg(short, long, default_value = "")]
    pub interface: String,

    /// Specify gateway MAC address
    #[arg(short = 'G', long, default_value = "00:00:00:00:00:00")]
    pub gw_mac: MacAddress,

    /// In dryrun mode, suppress printing packets on send
    #[arg(short, long)]
    pub quiet: bool,

    /// Whether to use naive probe generator
    #[arg(short = 'N', long)]
    pub naive_probes: bool,
}

#[derive(Clone, Debug)]
pub struct Context {
    pub config: Config,
    pub validate_ctx: AesCtx,
    pub sender_state: Arc<Mutex<SenderState>>,
    pub receiver_state: Arc<Mutex<ReceiverState>>,
}

impl Context {
    pub fn new(config: Config) -> Self {
        let validate_ctx = validate::new_context();
        let sender_stats = Arc::new(Mutex::new(SenderState::default()));
        let receiver_stats = Arc::new(Mutex::new(ReceiverState::default()));
        Self {
            config,
            validate_ctx,
            sender_state: sender_stats,
            receiver_state: receiver_stats,
        }
    }
}

pub fn create_context() -> Context {
    let mut config = Config::parse();

    if config.interface.is_empty() {
        config.interface = get_default_interface().unwrap();
    }

    if config.source_ip_first == Ipv4Addr::new(0, 0, 0, 0) {
        let ip = get_interface_ip(&config.interface).unwrap();
        config.source_ip_first = ip;
        config.source_ip_last = ip;
    }

    if config.gw_mac == MacAddress::parse_str("00:00:00:00:00:00").unwrap() {
        config.gw_mac = get_default_gw_mac().unwrap();
    }

    // From send.c (sender rate config)
    if config.bandwidth > 0 {
        // Packet length will be 84 bytes or 672 bits
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

    Context::new(config)
}
