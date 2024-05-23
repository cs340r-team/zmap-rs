use std::net::Ipv4Addr;

use etherparse::{
    IpHeaders, IpNumber, Ipv4HeaderSlice, LinkSlice, NetSlice, PacketBuilder, SlicedPacket,
    TcpHeaderSlice, TransportSlice,
};
use eui48::MacAddress;
use log::debug;

use crate::{probe_modules::packet::make_tcp_header, state::Config};

use super::packet::{make_ip_header, MAX_PACKET_SIZE};

pub const PACKET_LENGTH: u64 = 54;
pub const PCAP_FILTER: &str = "tcp && tcp[13] & 4 != 0 || tcp[13] == 18";

pub fn synscan_init_perthread(source_mac: &MacAddress, gateway_mac: &MacAddress) -> Vec<u8> {
    return vec![0; MAX_PACKET_SIZE];
}

// pub fn synscan_make_packet(
//     source_mac: &MacAddress,
//     gateway_mac: &MacAddress,
//     source_ip: Ipv4Addr,
//     destination_ip: Ipv4Addr,
//     validation: &[u32],
//     probe_num: i32,
//     config: &Config,
// ) -> Result<Vec<u8>, std::io::Error> {
//     let mut buf =
//         Vec::<u8>::with_capacity(Ethernet2Header::LEN + Ipv4Header::MAX_LEN + TcpHeader::MAX_LEN);

//     let ethernet_header = make_eth_header(source_mac, gateway_mac)
//         .write(&mut buf)
//         .expect("Could not write Ethernet header to buffer");

//     let mut ip_header = Ipv4Header::new(
//         0,
//         MAXTTL,
//         IpNumber::TCP,
//         source_ip.octets(),
//         destination_ip.octets(),
//     )
//     .unwrap();

//     ip_header
//         .write(&mut buf)
//         .expect("Could not write IPv4 header to buffer");

//     // Calculate source port
//     let src_port =
//         config.source_port_first + ((validation[1] + probe_num as u32) % NUM_PORTS) as u16;
//     let tcp_seq = validation[0];

//     let mut tcp_header = make_tcp_header(config.target_port);
//     tcp_header.source_port = src_port;
//     tcp_header.sequence_number = tcp_seq;
//     tcp_header.checksum = tcp_header.calc_checksum_ipv4(&ip_header, &[]).unwrap();

//     tcp_header
//         .write(&mut buf)
//         .expect("Could not write TCP header to buffer");

//     Ok(buf)
// }

// pub fn synscan_init_perthread2(source_mac: &MacAddress, gateway_mac: &MacAddress) -> () {}

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
        "tcp {{ sport: {} | dport: {} | seq: {} | checksum: {} }}",
        tcp_header.source_port(),
        tcp_header.destination_port(),
        tcp_header.sequence_number(),
        tcp_header.checksum()
    );

    println!("------------------------------------------------------");
}

pub fn synscan_make_packet(
    source_mac: &MacAddress,
    gateway_mac: &MacAddress,
    source_ip: &Ipv4Addr,
    destination_ip: &Ipv4Addr,
    validation: &[u32],
    probe_num: u32,
    config: &Config,
) -> Vec<u8> {
    // Calculate source port
    let num_ports = (config.source_port_last - config.source_port_first + 1) as u32;
    let src_port = config.source_port_first + ((validation[1] + probe_num) % num_ports) as u16;

    let tcp_seq = validation[0];

    let mut ip_header = make_ip_header(IpNumber::TCP);
    ip_header.source = source_ip.octets();
    ip_header.destination = destination_ip.octets();

    let mut tcp_header = make_tcp_header(config.target_port);
    tcp_header.source_port = src_port;
    tcp_header.sequence_number = tcp_seq;

    let builder = PacketBuilder::ethernet2(source_mac.to_array(), gateway_mac.to_array())
        .ip(IpHeaders::Ipv4(ip_header, Default::default()))
        .tcp_header(tcp_header);

    let mut result = Vec::<u8>::with_capacity(builder.size(0));

    // This will automatically set all length fields, checksums and identifiers (ethertype & protocol)
    // before writing the packet out to "result"
    builder.write(&mut result, &[]).unwrap();
    result
}

pub fn synscan_classify_packet(tcp_header: &TcpHeaderSlice) -> bool {
    !tcp_header.rst() // Success is defined by a SYN-ACK, not a RST
}

pub fn check_dst_port(port: u16, validation: &[u32], config: &Config) -> bool {
    if port > config.source_port_last || port < config.source_port_first {
        return false;
    }

    let num_ports = (config.source_port_last - config.source_port_first + 1) as u32;
    let to_validate = (port - config.source_port_first) as u32;
    let min = validation[1] % num_ports;
    let max = (validation[1] + config.packet_streams - 1) % num_ports;

    return ((max - min) % num_ports) >= ((to_validate - min) % num_ports);
}

pub fn synscan_validate_packet(
    ip_header: &Ipv4HeaderSlice, // Changed from Ipv4Header for zero-copy
    tcp_header: &TcpHeaderSlice,
    validation: &[u32],
    config: &Config,
) -> bool {
    if ip_header.protocol() != IpNumber::TCP {
        return false;
    }

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
