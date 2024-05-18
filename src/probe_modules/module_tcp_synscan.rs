// add packet.rs
use std::net::Ipv4Addr;

pub fn synscan_init_perthread(
    buf: &mut [u8],
    src: &MacAddr,
    gw: &MacAddr,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    dest_port: u16,
) -> Result() {
    buf.fill(0);

    // create Ethernet header
    let eth_header = Ethernet2Header {
        destination: gw.octets(),
        source: src.octets(),
        ether_type: etherparse::EtherTypes::Ipv4 as u16,
    };

    // create IP header
    let ip_header = Ipv4Header::new(
        Ipv4Header::MIN_LEN + TcpHeader::MIN_LEN,
        64,
        etherparse::IpTrafficClass::Tcp,
        src_ip.octets(),
        dest_ip.octets(),
    );

    // create TCP header
    let tcp_header = TcpHeader::new(
        0, // Source port will be filled later
        dest_port, 0, // Sequence number
        0, // Window size
    );

    // build the packet

    let pkt = PacketBuilder::ethernet2(eth_header.source, eth_header.destination)
        .ipv4(ip_header.source, ip_header.destination, ip_header.ttl)
        .tcp(
            tcp_header.source_port,
            tcp_header.destination_port,
            tcp_header.sequence_number,
            tcp_header.window_size,
        );
    // write the packet to the buffer
    pkt.write(buf, &[])?;
    //pkt.write(&mut buf[..pkt.size()])?;

    Ok(())
}

// //add packet.rs
// use crate::packet::{
//     make_eth_header, make_ip_header, make_tcp_header, EthHdr, IpHdr, MacAddr, TcpHdr,
// };

// struct ModuleTcpSynscan {
//     name: String,
//     packet_length: u32,
//     pcap_filter: String,
//     pcap_snaplen: u32,
//     port_args: u32,
//     thread_initialize: fn(),
//     make_packet: fn(),
//     print_packet: fn(),
//     classify_packet: fn(),
//     validate_packet: fn(),
//     close: fn(),
//     responses: Vec<String>,
// }

// impl ModuleTcpSynscan {
//     fn new() -> Self {
//         Self {
//             name: "tcp_synscan".to_string(),
//             packet_length: 54,
//             pcap_filter: "tcp && tcp[13] & 4 != 0 || tcp[13] == 18".to_string(),
//             pcap_snaplen: 96,
//             port_args: 1,
//             thread_initialize: synscan_init_perthread,
//             make_packet: synscan_make_packet,
//             print_packet: synscan_print_packet,
//             classify_packet: synscan_classify_packet,
//             validate_packet: synscan_validate_packet,
//             close: None,
//             responses: vec![],
//         }
//     }
// }

// // int synscan_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
// //     uint32_t *validation, int probe_num)
// // {
// // struct ethhdr *eth_header = (struct ethhdr *)buf;
// // struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
// // struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
// // uint16_t src_port = zconf.source_port_first
// //                 + ((validation[1] + probe_num) % num_ports);
// // uint32_t tcp_seq = validation[0];

// // ip_header->saddr = src_ip;
// // ip_header->daddr = dst_ip;

// // tcp_header->source = htons(src_port);
// // tcp_header->seq = tcp_seq;
// // tcp_header->check = 0;
// // tcp_header->check = tcp_checksum(sizeof(struct tcphdr),
// //         ip_header->saddr, ip_header->daddr, tcp_header);

// // ip_header->check = 0;
// // ip_header->check = ip_checksum((unsigned short *) ip_header);

// // return EXIT_SUCCESS;
// // }

// fn synscan_make_packet(
//     buf: &mut [u8],
//     src_ip: u32,
//     dst_ip: u32,
//     validation: &mut [u32],
//     probe_num: i32,
// ) -> i32 {
//     let eth_header = unsafe { &mut *(buf.as_mut_ptr() as *mut EthHdr) };
//     let ip_header =
//         unsafe { &mut *(buf.as_mut_ptr().add(std::mem::size_of::<EthHdr>()) as *mut IpHdr) };
//     let tcp_header = unsafe {
//         &mut *(buf
//             .as_mut_ptr()
//             .add(std::mem::size_of::<EthHdr>() + std::mem::size_of::<IpHdr>())
//             as *mut TcpHdr)
//     };
//     let src_port = zconf.source_port_first + ((validation[1] + probe_num) % num_ports);
//     let tcp_seq = validation[0];

//     ip_header.saddr = src_ip;
//     ip_header.daddr = dst_ip;

//     tcp_header.source = htons(src_port);
//     tcp_header.seq = tcp_seq;
//     tcp_header.check = 0;
//     tcp_header.check = tcp_checksum(
//         std::mem::size_of::<TcpHdr>(),
//         ip_header.saddr,
//         ip_header.daddr,
//         tcp_header,
//     );

//     ip_header.check = 0;
//     ip_header.check = ip_checksum(ip_header);

//     return EXIT_SUCCESS;
// }
