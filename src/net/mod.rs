pub mod pcap;
pub mod socket;

use std::{fs, num::ParseIntError, process::Command};

use eui48::{MacAddress, ParseError};

pub fn get_interface_index(ifname: &str) -> Result<i32, ParseIntError> {
    let path = format!("/sys/class/net/{}/ifindex", ifname);
    fs::read_to_string(path)
        .expect("Unable to read file path")
        .trim()
        .parse()
}

pub fn get_default_gateway_mac() -> Result<MacAddress, ParseError> {
    let gw_mac_out = Command::new("sh")
        .arg("-c")
        .arg("arp -n | grep $(ip route show | grep default | awk '{print $3}') | awk '{print $3}'")
        .output()
        .expect("Could not obtain default gateway's MAC address");
    let gw_mac_str = std::str::from_utf8(&gw_mac_out.stdout).unwrap().trim();
    MacAddress::parse_str(gw_mac_str)
}
