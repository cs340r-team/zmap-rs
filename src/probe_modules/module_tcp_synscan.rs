use std::net::Ipv4Addr;

use etherparse::{
    IpHeaders, IpNumber, LinkSlice, NetSlice, PacketBuilder, SlicedPacket, TcpHeaderSlice,
    TransportSlice,
};
use eui48::MacAddress;
use log::debug;

use crate::config::Config;
use crate::probe_modules::packet::{
    ip_checksum, make_eth_header, make_ip_header, make_tcp_header, tcp_checksum, MAX_PACKET_SIZE,
};
use crate::probe_modules::probe_modules::ProbeGenerator;

pub const PACKET_LENGTH: u64 = 54;
pub const PCAP_FILTER: &str = "tcp && tcp[13] & 4 != 0 || tcp[13] == 18";

pub struct NaiveProbeGenerator {
    source_mac: MacAddress,
    gateway_mac: MacAddress,
    source_ip: Ipv4Addr,
    source_port_first: u16,
    source_port_last: u16,
    target_port: u16,
    buffer: Vec<u8>,
}

impl Default for NaiveProbeGenerator {
    fn default() -> Self {
        NaiveProbeGenerator {
            source_mac: Default::default(),
            gateway_mac: Default::default(),
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            source_port_first: 0,
            source_port_last: 0,
            target_port: 0,
            buffer: Vec::with_capacity(MAX_PACKET_SIZE),
        }
    }
}

/// This is a simple probe generator that serializes the packet each time make_packet is called
impl ProbeGenerator for NaiveProbeGenerator {
    // This is a no-op as we build the packet from scratch each time
    fn thread_initialize(
        &mut self,
        source_mac: &MacAddress,
        gateway_mac: &MacAddress,
        source_ip: &Ipv4Addr,
        source_port_first: u16,
        source_port_last: u16,
        target_port: u16,
    ) {
        self.source_mac = *source_mac;
        self.gateway_mac = *gateway_mac;
        self.source_ip = *source_ip;
        self.source_port_first = source_port_first;
        self.source_port_last = source_port_last;
        self.target_port = target_port;
    }

    fn make_packet(
        &mut self,
        destination_ip: &Ipv4Addr,
        validation: &[u32],
        probe_num: u32,
    ) -> &[u8] {
        // Calculate source port
        let num_ports = (self.source_port_last - self.source_port_first + 1) as u32;
        let src_port = self.source_port_first + ((validation[1] + probe_num) % num_ports) as u16;

        let mut ip_header = make_ip_header(IpNumber::TCP);
        ip_header.source = self.source_ip.octets();
        ip_header.destination = destination_ip.octets();

        let mut tcp_header = make_tcp_header(self.target_port);
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

/// This is a precomputed probe generator that sets up most of the packet in advance as there are fields
/// that do not change between probes.
///
/// The only fields that need to be set in make_packet are the IPv4 header checksum and destination
/// address, and the TCP source port, sequence number, and checksum.
pub struct PrecomputedProbeGenerator {
    source_ip: Ipv4Addr,
    source_port_first: u16,
    source_port_last: u16,
    target_port: u16,
    buffer: Vec<u8>,
}

impl Default for PrecomputedProbeGenerator {
    fn default() -> Self {
        PrecomputedProbeGenerator {
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            source_port_first: 0,
            source_port_last: 0,
            target_port: 0,
            buffer: Vec::with_capacity(MAX_PACKET_SIZE),
        }
    }
}

impl ProbeGenerator for PrecomputedProbeGenerator {
    fn thread_initialize(
        &mut self,
        source_mac: &MacAddress,
        gateway_mac: &MacAddress,
        source_ip: &Ipv4Addr,
        source_port_first: u16,
        source_port_last: u16,
        target_port: u16,
    ) {
        self.source_ip = *source_ip;
        self.source_port_first = source_port_first;
        self.source_port_last = source_port_last;
        self.target_port = target_port;

        make_eth_header(source_mac, gateway_mac)
            .write(&mut self.buffer)
            .unwrap();

        let mut ip_header = make_ip_header(IpNumber::TCP);
        ip_header.source = source_ip.octets();
        ip_header.total_len = 40; // 14 Ethernet header + 20 IP header + 20 TCP header
        ip_header.write_raw(&mut self.buffer).unwrap();

        let tcp_header = make_tcp_header(target_port);
        tcp_header.write(&mut self.buffer).unwrap();
    }

    // We just need to the IP header checksum, destination address, and TCP source port, sequence number, and checksum
    fn make_packet(
        &mut self,
        destination_ip: &Ipv4Addr,
        validation: &[u32],
        probe_num: u32,
    ) -> &[u8] {
        // Set the destination IP address
        self.buffer[30..34].copy_from_slice(&destination_ip.octets());

        // Calculate and set source port
        let num_ports = (self.source_port_last - self.source_port_first + 1) as u32;
        let src_port = self.source_port_first + ((validation[1] + probe_num) % num_ports) as u16;
        self.buffer[34..36].copy_from_slice(&src_port.to_be_bytes());

        // Set the sequence number
        self.buffer[38..42].copy_from_slice(&validation[0].to_be_bytes());

        // Calculate and set IP header checksum
        self.buffer[24..26].copy_from_slice(&0u16.to_be_bytes()); // Zero out
        let ip_checksum = ip_checksum(&self.buffer[14..34]);
        self.buffer[24..26].copy_from_slice(&ip_checksum.to_be_bytes());

        // Calculate and set TCP checksum
        self.buffer[50..52].copy_from_slice(&0u16.to_be_bytes()); // Zero out
        let tcp_checksum = tcp_checksum(
            &self.buffer[34..],
            20,
            self.source_ip.into(),
            (*destination_ip).into(),
        );
        self.buffer[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());
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
