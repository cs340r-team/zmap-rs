use etherparse::{
    EtherType, Ethernet2Header, IpFragOffset, IpNumber, Ipv4Dscp, Ipv4Header, TcpHeader,
};
use libc::MAXTTL;
use rand::random;

use eui48::MacAddress;

pub const MAX_PACKET_SIZE: usize = 4096;

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
    header.sequence_number = random();
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
