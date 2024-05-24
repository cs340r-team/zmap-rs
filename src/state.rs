use std::{net::Ipv4Addr, time::Instant};

#[derive(Debug)]
pub struct SenderState {
    pub complete: bool,
    pub start: Instant,
    pub finish: Instant,
    pub sent: u32,
    pub blacklisted: u32,
    pub first_scanned: Ipv4Addr,
    pub targets: u32,
    pub sendto_failures: u32,
}

impl Default for SenderState {
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
pub struct ReceiverState {
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

impl Default for ReceiverState {
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
