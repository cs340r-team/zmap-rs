use std::net::Ipv4Addr;

use etherparse::{
    IpHeaders, IpNumber, LinkSlice, NetSlice, PacketBuilder, SlicedPacket, TcpHeaderSlice,
    TransportSlice,
};
use eui48::MacAddress;
use log::debug;

use crate::{config::Config, probe_modules::packet::make_tcp_header};

use super::{
    packet::{make_ip_header, MAX_PACKET_SIZE},
    probe_modules::ProbeGenerator,
};

pub const PACKET_LENGTH: u64 = 54;
pub const PCAP_FILTER: &str = "tcp && tcp[13] & 4 != 0 || tcp[13] == 18";

pub struct NaviveProbeGenerator {
    source_mac: MacAddress,
    gateway_mac: MacAddress,
    buffer: Vec<u8>,
}

impl NaviveProbeGenerator {
    pub fn new() -> Self {
        Self {
            source_mac: Default::default(),
            gateway_mac: Default::default(),
            buffer: Vec::with_capacity(MAX_PACKET_SIZE),
        }
    }
}

impl ProbeGenerator for NaviveProbeGenerator {
    // This is a no-op as we build the packet from scratch each time
    fn thread_initialize(&mut self, source_mac: &MacAddress, gateway_mac: &MacAddress) {
        self.source_mac = *source_mac;
        self.gateway_mac = *gateway_mac;
    }

    fn make_packet(
        &mut self,
        source_ip: &Ipv4Addr,
        destination_ip: &Ipv4Addr,
        validation: &[u32],
        probe_num: u32,
        source_port_first: u16,
        source_port_last: u16,
        target_port: u16,
    ) -> &[u8] {
        // Calculate source port
        let num_ports = (source_port_last - source_port_first + 1) as u32;
        let src_port = source_port_first + ((validation[1] + probe_num) % num_ports) as u16;

        let mut ip_header = make_ip_header(IpNumber::TCP);
        ip_header.source = source_ip.octets();
        ip_header.destination = destination_ip.octets();

        let mut tcp_header = make_tcp_header(target_port);
        tcp_header.source_port = src_port;
        tcp_header.sequence_number = validation[0];

        let builder =
            PacketBuilder::ethernet2(self.source_mac.to_array(), self.gateway_mac.to_array())
                .ip(IpHeaders::Ipv4(ip_header, Default::default()))
                .tcp_header(tcp_header);

        self.buffer.clear();

        // This will automatically set all length fields, checksums and identifiers (ethertype & protocol)
        // before writing the packet out to "result"
        builder.write(&mut self.buffer, &[]).unwrap();
        &self.buffer
    }
}

// Return false if dst port is outside the expected valid range
fn check_dst_port(port: u16, validation: &[u32], config: &Config) -> bool {
    if port > config.source_port_last || port < config.source_port_first {
        return false;
    }

    let num_ports = (config.source_port_last - config.source_port_first + 1) as u32;
    let to_validate = (port - config.source_port_first) as u32;
    let min = validation[1] % num_ports;
    let max = (validation[1] + config.probes - 1) % num_ports;

    return ((max - min) % num_ports) >= ((to_validate - min) % num_ports);
}

pub fn synscan_validate_packet(packet: &[u8], validation: &[u32], config: &Config) -> bool {
    let packet_slice =
        SlicedPacket::from_ethernet(packet).expect("Could not parse Ethernet packet");
    let ip_header = match &packet_slice.net {
        Some(NetSlice::Ipv4(slice)) => slice.header(),
        _ => {
            debug!("Could not unpack network slice");
            return false;
        }
    };

    if ip_header.protocol() != IpNumber::TCP {
        return false;
    }

    let tcp_header = match &packet_slice.transport {
        Some(TransportSlice::Tcp(slice)) => {
            TcpHeaderSlice::from_slice(slice.slice()).expect("Could not create TcpHeaderSlice")
        }
        _ => {
            debug!("Could not unpack transport slice");
            return false;
        }
    };

    if config.target_port != tcp_header.source_port() {
        return false;
    }

    if !check_dst_port(tcp_header.destination_port(), validation, config) {
        return false;
    }

    if tcp_header.acknowledgment_number() != validation[0] + 1 {
        return false;
    }

    return true;
}

// Success is defined by a SYN-ACK, not a RST
pub fn synscan_classify_packet(packet: &[u8]) -> bool {
    let packet_slice =
        SlicedPacket::from_ethernet(packet).expect("Could not parse Ethernet packet");

    let tcp_header = match &packet_slice.transport {
        Some(TransportSlice::Tcp(slice)) => {
            TcpHeaderSlice::from_slice(slice.slice()).expect("Could not create TcpHeaderSlice")
        }
        _ => {
            debug!("Could not unpack transport slice");
            return false;
        }
    };

    !tcp_header.rst()
}

pub fn synscan_print_packet(packet: &[u8]) {
    let sliced_packet =
        SlicedPacket::from_ethernet(&packet).expect("Could not parse Ethernet packet");

    let eth_header = match &sliced_packet.link {
        Some(LinkSlice::Ethernet2(slice)) => slice,
        _ => {
            debug!("Could not unpack link slice");
            return;
        }
    };

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

    let eth_source = eth_header.source();
    let eth_destination = eth_header.destination();
    println!(
        "eth {{ shost: {:<02x}:{:<02x}:{:<02x}:{:<02x}:{:<02x}:{:<02x} | dhost: {:<02x}:{:<02x}:{:<02x}:{:<02x}:{:<02x}:{:<02x} }}",
        eth_source[0],
        eth_source[1],
        eth_source[2],
        eth_source[3],
        eth_source[4],
        eth_source[5],
        eth_destination[0],
        eth_destination[1],
        eth_destination[2],
        eth_destination[3],
        eth_destination[4],
        eth_destination[5],
    );

    println!(
        "ip {{ saddr: {} | daddr: {} | checksum: {} }}",
        ip_header.source_addr(),
        ip_header.destination_addr(),
        ip_header.header_checksum()
    );

    println!(
        "tcp {{ sport: {} | dport: {} | seq: {} | ack: {} ({}) | syn: {} | rst: {} | checksum: {} }}",
        tcp_header.source_port(),
        tcp_header.destination_port(),
        tcp_header.sequence_number(),
        tcp_header.acknowledgment_number(),
        tcp_header.ack(),
        tcp_header.syn(),
        tcp_header.rst(),
        tcp_header.checksum(),
    );

    println!("------------------------------------------------------");
}
