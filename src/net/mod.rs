pub mod mac;
pub mod pcap;
pub mod socket;

use std::{fs, num::ParseIntError};

pub use mac::MacAddress;

pub fn get_interface_index(name: &str) -> Result<i32, ParseIntError> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    fs::read_to_string(path)
        .expect("Unable to read file path")
        .trim()
        .parse()
}
