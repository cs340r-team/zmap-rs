fn make_eth_header(ethh: &mut EthHdr, src: &MacAddr, dst: &MacAddr) {
    ethh.h_source.copy_from_slice(src);
    ethh.h_dest.copy_from_slice(dst);
    ethh.h_proto = htons(ETH_P_IP);
}

fn make_ip_header(iph: &mut IpHdr, protocol: u8, len: u16) {
    iph.ihl = 5; // Internet Header Length
    iph.version = 4; // IPv4
    iph.tos = 0; // Type of Service
    iph.tot_len = len;
    iph.id = htons(54321); // identification number
    iph.frag_off = 0; // fragmentation falg
    iph.ttl = MAXTTL; // time to live (TTL)
    iph.protocol = protocol; // upper layer protocol => TCP
                             // we set the checksum = 0 for now because that's
                             // what it needs to be when we run the IP checksum
    iph.check = 0;
}

fn make_tcp_header(tcp_header: &mut TcpHdr, dest_port: u16) {
    tcp_header.seq = random();
    tcp_header.ack_seq = 0;
    tcp_header.res2 = 0;
    tcp_header.doff = 5; // data offset
    tcp_header.syn = 1;
    tcp_header.window = htons(65535); // largest possible window
    tcp_header.check = 0;
    tcp_header.urg_ptr = 0;
    tcp_header.dest = htons(dest_port);
}

fn make_udp_header(udp_header: &mut UdpHdr, dest_port: u16, len: u16) {
    udp_header.dest = htons(dest_port);
    udp_header.len = htons(len);
    // checksum ignored in IPv4 if 0
    udp_header.check = 0;
}
