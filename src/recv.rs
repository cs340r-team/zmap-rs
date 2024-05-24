use std::{cell::RefCell, fs::File, io::Write, net::Ipv4Addr, time::Instant};

use etherparse::{NetSlice, SlicedPacket, TcpHeaderSlice, TransportSlice};
use log::debug;

use crate::lib::validate;
use crate::net::pcap::*;
use crate::probe_modules::module_tcp_synscan::{
    synscan_classify_packet, synscan_print_packet, synscan_validate_packet,
};
use crate::state::Context;

pub struct Receiver {
    ctx: Context,
    pcap: PacketCapture,
    seen_ips: RefCell<Vec<u64>>, // TODO: writeup
    output_file: RefCell<File>,
}

impl Receiver {
    const SEEN_IPS_SIZE: usize = 0x4000000;

    pub fn new(filter: &str, ctx: Context) -> Self {
        let pcap = PacketCapture::new(&ctx.config.iface).with_filter(filter);
        let seen_ips = RefCell::new(vec![0; Self::SEEN_IPS_SIZE]);
        let output_file = RefCell::new(File::create(&ctx.config.output_filename).unwrap());
        Self {
            ctx,
            pcap,
            seen_ips,
            output_file,
        }
    }

    pub fn run(&self) {
        debug!("Receiver thread started");

        // Signal to main thread that receiver thread is ready to go
        let mut zrecv = self.ctx.receiver_stats.lock().unwrap();
        zrecv.ready = true;
        zrecv.start = Instant::now();
        drop(zrecv);

        loop {
            if let Some(packet) = self.pcap.next_packet() {
                self.process_packet(&packet);
                self.update_pcap_stats();
            }

            let zrecv = self.ctx.receiver_stats.lock().unwrap();
            if self.ctx.config.max_results > 0
                && zrecv.success_unique >= self.ctx.config.max_results
            {
                self.ctx.sender_stats.lock().unwrap().complete = true;
                break;
            }
            drop(zrecv);

            let zsend = self.ctx.sender_stats.lock().unwrap();
            if zsend.complete && Instant::now() - zsend.finish > self.ctx.config.cooldown_secs {
                break;
            }
            drop(zsend);
        }

        let mut zrecv = self.ctx.receiver_stats.lock().unwrap();
        zrecv.finish = Instant::now();
        zrecv.complete = true;
        drop(zrecv);

        self.update_pcap_stats();
        debug!("Receiver finished");
    }

    fn update_pcap_stats(&self) {
        let pcap_stats = self.pcap.stats();
        let mut zrecv = self.ctx.receiver_stats.lock().unwrap();
        zrecv.pcap_recv = pcap_stats.ps_recv;
        zrecv.pcap_drop = pcap_stats.ps_drop;
        zrecv.pcap_ifdrop = pcap_stats.ps_ifdrop;
    }

    fn process_packet(&self, packet: &Packet) {
        if self.ctx.receiver_stats.lock().unwrap().success_unique >= self.ctx.config.max_results {
            return;
        }

        let sliced_packet =
            SlicedPacket::from_ethernet(packet.data).expect("Could not parse Ethernet packet");
        let ip_header = match &sliced_packet.net {
            Some(NetSlice::Ipv4(slice)) => slice.header(),
            _ => {
                debug!("Could not unpack network slice");
                return;
            }
        };
        let tcp_header = match &sliced_packet.transport {
            Some(TransportSlice::Tcp(slice)) => {
                TcpHeaderSlice::from_slice(slice.slice()).expect("Could not create TcpHeaderSlice")
            }
            _ => {
                debug!("Could not unpack transport slice");
                return;
            }
        };

        let src_ip = ip_header.source_addr();
        let dst_ip = ip_header.destination_addr();
        let validation = validate::gen(&self.ctx.validate_ctx, &dst_ip, &src_ip);
        let validation = [
            u32::from_be_bytes(validation[0..4].try_into().unwrap()),
            u32::from_be_bytes(validation[4..8].try_into().unwrap()),
        ];

        if !synscan_validate_packet(&ip_header, &tcp_header, &validation, &self.ctx.config) {
            debug!("Validation for probe reply failed");
            return;
        }

        let mut zrecv = self.ctx.receiver_stats.lock().unwrap();
        if synscan_classify_packet(&tcp_header) {
            zrecv.success_total += 1;

            let is_repeat = self.check_ip(src_ip);
            if !is_repeat {
                zrecv.success_unique += 1;
                self.set_ip(src_ip);

                // Simple file output - add to writeup about cleaner implementation
                writeln!(self.output_file.borrow_mut(), "{}", src_ip.to_string()).unwrap();
            }

            if self.ctx.sender_stats.lock().unwrap().complete {
                zrecv.cooldown_total += 1;
                if !is_repeat {
                    zrecv.cooldown_unique += 1;
                }
            }
        } else {
            zrecv.failure_total += 1;
        }
    }

    fn check_ip(&self, ip: Ipv4Addr) -> bool {
        let ip: u32 = ip.into();
        return ((self.seen_ips.borrow()[(ip >> 6) as usize] >> (ip & 0x3F)) & 1) != 0;
    }

    fn set_ip(&self, ip: Ipv4Addr) {
        let ip: u32 = ip.into();
        self.seen_ips.borrow_mut()[(ip >> 6) as usize] |= 1u64 << (ip & 0x3F);
    }
}
