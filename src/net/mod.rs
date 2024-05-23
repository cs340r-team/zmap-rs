pub mod pcap;
pub mod socket;

use std::{
    fs,
    net::{AddrParseError, Ipv4Addr},
    num::ParseIntError,
    process::Command,
    str::FromStr,
};

use eui48::{MacAddress, ParseError};

pub fn get_interface_index(ifname: &str) -> Result<i32, ParseIntError> {
    let path = format!("/sys/class/net/{}/ifindex", ifname);
    fs::read_to_string(path)
        .expect("Unable to read file path")
        .trim()
        .parse()
}

pub fn get_interface_ip(ifname: &str) -> Result<Ipv4Addr, AddrParseError> {
    let cmd = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ifconfig {ifname} | grep \"inet \" | awk '{{print $2}}'"
        ))
        .output()
        .expect(&format!("Could not obtain {ifname}'s IP address"));
    let ip_str = std::str::from_utf8(&cmd.stdout).unwrap().trim();
    Ipv4Addr::from_str(ip_str)
}

pub fn get_interface_mac(ifname: &str) -> Result<MacAddress, ParseError> {
    let cmd_out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ifconfig {ifname} | grep ether | awk '{{print $2}}'"
        ))
        .output()
        .expect(&format!("Could not obtain {ifname}'s IP address"));
    let mac_str = std::str::from_utf8(&cmd_out.stdout).unwrap().trim();
    MacAddress::parse_str(mac_str)
}

pub fn get_default_gw_mac() -> Result<MacAddress, ParseError> {
    let gw_mac_out = Command::new("sh")
        .arg("-c")
        .arg("arp -n | grep $(ip route show | grep default | awk '{print $3}') | awk '{print $3}'")
        .output()
        .expect("Could not obtain default gateway's MAC address");
    let gw_mac_str = std::str::from_utf8(&gw_mac_out.stdout).unwrap().trim();
    MacAddress::parse_str(gw_mac_str)
}
