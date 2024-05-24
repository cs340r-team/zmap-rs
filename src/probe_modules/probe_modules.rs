use std::net::Ipv4Addr;

use eui48::MacAddress;

pub trait ProbeGenerator {
    fn thread_initialize(&mut self, source_mac: &MacAddress, gateway_mac: &MacAddress);
    fn make_packet(
        &mut self,
        source_ip: &Ipv4Addr,
        destination_ip: &Ipv4Addr,
        validation: &[u32],
        probe_num: u32,
        source_port_first: u16,
        source_port_last: u16,
        target_port: u16,
    ) -> &[u8];
}
