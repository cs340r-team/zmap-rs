use etherparse::{
    EtherType, Ethernet2Header, IpFragOffset, IpNumber, Ipv4Dscp, Ipv4Header, TcpHeader,
};
use eui48::MacAddress;
use libc::{c_uchar, c_uint, c_ushort, ETH_ALEN, ETH_P_IP, IPPROTO_TCP, MAXTTL};

pub const ETH_HDR_SIZE: usize = std::mem::size_of::<ethhdr>();
pub const IP_HDR_SIZE: usize = std::mem::size_of::<iphdr>();
pub const TCP_HDR_SIZE: usize = std::mem::size_of::<tcphdr>();

pub const MAX_PACKET_SIZE: usize = 4096;

#[repr(C)]
pub struct ethhdr {
    pub h_dest: [c_uchar; 6],
    pub h_source: [c_uchar; 6],
    pub h_proto: c_ushort,
}

#[repr(C)]
pub struct iphdr {
    pub version_ihl: c_uchar,
    pub tos: c_uchar,
    pub tot_len: c_ushort,
    pub id: c_ushort,
    pub frag_off: c_ushort,
    pub ttl: c_uchar,
    pub protocol: c_uchar,
    pub checksum: c_ushort,
    pub saddr: c_uint,
    pub daddr: c_uint,
}

#[repr(C)]
pub struct tcphdr {
    pub source: c_ushort,
    pub dest: c_ushort,
    pub seq: c_uint,
    pub ack_seq: c_uint,
    pub data_off: c_uchar,
    pub flags: c_uchar,
    pub window: c_ushort,
    pub checksum: c_ushort,
    pub urg_ptr: c_ushort,
}

pub fn make_eth_header(source: &MacAddress, destination: &MacAddress) -> Ethernet2Header {
    let mut header: Ethernet2Header = Default::default();
    header.source = source.to_array();
    header.destination = destination.to_array();
    header.ether_type = EtherType::IPV4;
    return header;
}

pub fn make_ip_header(protocol: IpNumber) -> Ipv4Header {
    let mut header: Ipv4Header = Default::default();
    // IHL and version are taken care of for us
    header.dscp = Ipv4Dscp::ZERO;
    header.identification = 54321;
    header.fragment_offset = IpFragOffset::ZERO;
    header.time_to_live = MAXTTL;
    header.protocol = protocol;
    header.header_checksum = 0;
    return header;
}

pub fn make_tcp_header(port: u16) -> TcpHeader {
    let mut header: TcpHeader = Default::default();
    header.sequence_number = 0;
    header.acknowledgment_number = 0;
    header.ece = false;
    header.cwr = false;
    header.syn = true;
    header.window_size = u16::MAX;
    header.checksum = 0;
    header.urgent_pointer = 0;
    header.destination_port = port;
    return header;
}

pub fn ip_checksum(ip_header: &[u8]) -> u16 {
    let mut sum = 0u64;
    for i in (0..ip_header.len()).step_by(2) {
        sum += u16::from_be_bytes([ip_header[i], ip_header[i + 1]]) as u64;
    }

    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return !sum as u16;
}

pub fn tcp_checksum(tcp_header: &[u8], tcp_len: u16, src_ip: u32, dst_ip: u32) -> u16 {
    let mut sum = 0u64;

    // Pseudo header
    sum += (src_ip >> 16) as u64 + (src_ip & 0xFFFF) as u64;
    sum += (dst_ip >> 16) as u64 + (dst_ip & 0xFFFF) as u64;
    sum += tcp_len as u64;
    sum += 6u16 as u64;

    for i in (0..tcp_header.len()).step_by(2) {
        sum += u16::from_be_bytes([tcp_header[i], tcp_header[i + 1]]) as u64;
    }

    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return !sum as u16;
}

#[cfg(test)]
mod tests {
    use etherparse::{IpHeaders, PacketBuilder, TcpOptions};

    use super::*;
    use crate::config::Config;

    const MAC_SRC: [u8; 6] = [0xaa, 0x41, 0x72, 0x51, 0x54, 0x42];
    const MAC_DEST: [u8; 6] = [0xf6, 0xd4, 0x88, 0x07, 0x37, 0x64];
    const IP_SRC: [u8; 4] = [192, 168, 68, 3];
    const IP_DEST: [u8; 4] = [46, 216, 152, 50];

    #[test]
    fn test_ip_checksum() {
        let mut ip_header = make_ip_header(IpNumber::TCP);
        ip_header.source = IP_SRC;
        ip_header.destination = IP_DEST;

        let mut tcp_header = make_tcp_header(443);
        tcp_header.source_port = 47782;
        tcp_header.sequence_number = 2324566490;

        let builder = PacketBuilder::ethernet2(MAC_SRC, MAC_DEST)
            .ip(IpHeaders::Ipv4(ip_header, Default::default()))
            .tcp_header(tcp_header);

        let mut result = Vec::<u8>::with_capacity(builder.size(0));
        builder.write(&mut result, &[]).unwrap();

        let ip_header_without_checksum = [&result[14..24], &result[26..34]].concat();
        let expected_checksum = ip_checksum(&ip_header_without_checksum);
        let actual_checksum = u16::from_be_bytes([result[24], result[25]]);

        assert_eq!(actual_checksum, expected_checksum);
    }

    #[test]
    fn test_tcp_checksum() {
        let mut ip_header = make_ip_header(IpNumber::TCP);
        ip_header.source = IP_SRC;
        ip_header.destination = IP_DEST;

        let mut tcp_header = make_tcp_header(443);
        tcp_header.source_port = 47782;
        tcp_header.sequence_number = 2324566490;

        let builder = PacketBuilder::ethernet2(MAC_SRC, MAC_DEST)
            .ip(IpHeaders::Ipv4(ip_header, Default::default()))
            .tcp_header(tcp_header);

        let mut result = Vec::<u8>::with_capacity(builder.size(0));
        builder.write(&mut result, &[]).unwrap();

        let expected_checksum = u16::from_be_bytes([result[50], result[51]]);
        let tcp_header_without_checksum = &result[34..50];
        let actual_checksum = tcp_checksum(
            tcp_header_without_checksum,
            20,
            u32::from_be_bytes(IP_SRC),
            u32::from_be_bytes(IP_DEST),
        );

        assert_eq!(expected_checksum, actual_checksum);
    }
}
