use std::net::Ipv4Addr;

use etherparse::{
    Ethernet2Header, IpFragOffset, IpHeaders, IpNumber, Ipv4Dscp, Ipv4Header, PacketBuilder,
    PacketBuilderStep, TcpHeader,
};
use libc::MAXTTL;

use crate::{net::MacAddress, probe_modules::packet::make_tcp_header, state::Config};

use super::packet::{make_eth_header, make_ip_header};

const NUM_PORTS: u32 = 1;

// pub fn synscan_init_perthread(
//     source_mac: &MacAddress,
//     gateway_mac: &MacAddress,
// ) -> Result<Vec<u8>, std::io::Error> {
//     return Ok(buf);
// }

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

pub fn synscan_make_packet(
    source_mac: &MacAddress,
    gateway_mac: &MacAddress,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    validation: &[u32],
    probe_num: i32,
    config: &Config,
) -> Vec<u8> {
    // Calculate source port
    let src_port =
        config.source_port_first + ((validation[1] + probe_num as u32) % NUM_PORTS) as u16;
    let tcp_seq = validation[0];

    let mut ip_header = make_ip_header(IpNumber::TCP);
    ip_header.source = source_ip.octets();
    ip_header.destination = destination_ip.octets();

    let mut tcp_header = make_tcp_header(config.target_port);
    tcp_header.source_port = src_port;
    tcp_header.sequence_number = tcp_seq;

    let builder = PacketBuilder::ethernet2(source_mac.octets(), gateway_mac.octets())
        .ip(IpHeaders::Ipv4(ip_header, Default::default()))
        .tcp_header(tcp_header);

    let mut result = Vec::<u8>::with_capacity(builder.size(0));

    // This will automatically set all length fields, checksums and identifiers (ethertype & protocol)
    // before writing the packet out to "result"
    builder.write(&mut result, &[]).unwrap();
    result
}

pub fn synscan_classify_packet(tcp_header: &TcpHeader) -> bool {
    !tcp_header.rst // Success is defined by a SYN-ACK, not a RST
}

pub fn check_dst_port(port: u16, validation: &[u32], config: &Config) -> bool {
    if (port > config.source_port_last || port < config.source_port_first) {
        return false;
    }

    let to_validate = (port - config.source_port_first) as u32;
    let min = validation[1] % NUM_PORTS;
    let max = (validation[1] + config.packet_streams - 1) % NUM_PORTS;

    return (((max - min) % NUM_PORTS) >= ((to_validate - min) % NUM_PORTS));
}

pub fn synscan_validate_packet(
    ip_header: &Ipv4Header,
    tcp_header: &TcpHeader,
    validation: &[u32],
    config: &Config,
) -> bool {
    if (ip_header.protocol != IpNumber::TCP) {
        return false;
    }

    if (config.target_port != tcp_header.source_port) {
        return false;
    }

    if (!check_dst_port(tcp_header.destination_port, validation, config)) {
        return false;
    }

    if (tcp_header.acknowledgment_number != validation[0] + 1) {
        return false;
    }

    return true;
}
