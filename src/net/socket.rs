use libc::{c_void, sendto, sockaddr, sockaddr_ll, AF_PACKET, ETH_P_ALL, SOCK_RAW};
use socket2::Socket;
use std::os::unix::io::AsRawFd;

// Simple wrapper around a sockaddr_ll struct
pub struct MacAddress {
    inner: sockaddr_ll,
}

impl MacAddress {
    const IFHWADDRLEN: usize = 6;

    pub fn from_str(s: &str) -> Self {
        let mut sockaddr = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: Self::IFHWADDRLEN as u8,
            sll_addr: [0; 8],
        };

        let bytes: Vec<u8> = s
            .split(':')
            .map(|byte| u8::from_str_radix(byte, 16).expect("Could not convert hex to u8"))
            .collect();

        assert_eq!(bytes.len(), Self::IFHWADDRLEN, "Invalid MAC address length");
        sockaddr.sll_addr[..Self::IFHWADDRLEN].copy_from_slice(&bytes);

        Self { inner: sockaddr }
    }
}

pub struct RawEthSocket {
    inner: Socket,
}

impl RawEthSocket {
    pub fn new() -> Self {
        let proto = ETH_P_ALL.to_be();
        let socket = Socket::new(AF_PACKET.into(), SOCK_RAW.into(), Some(proto.into()))
            .expect("Failed to create raw socket, are you running as root?");
        Self { inner: socket }
    }

    // https://man7.org/linux/man-pages/man7/packet.7.html
    pub fn sendto(&self, buf: &[u8], address: &MacAddress) -> Result<(), std::io::Error> {
        let res = unsafe {
            sendto(
                self.inner.as_raw_fd(),
                buf.as_ptr() as *const c_void,
                buf.len(),
                0,
                &address.inner as *const sockaddr_ll as *const sockaddr,
                std::mem::size_of::<sockaddr_ll>() as u32,
            )
        };

        if res < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
