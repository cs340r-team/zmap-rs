use libc::{c_void, sendto, sockaddr, sockaddr_ll, AF_PACKET, ETH_P_ALL, SOCK_RAW};
use socket2::Socket;
use std::os::unix::io::AsRawFd;

use super::MacAddress;

pub struct RawEthSocket {
    inner: Socket,
}

impl RawEthSocket {
    const PROTO: i32 = ETH_P_ALL.to_be();

    pub fn new() -> Self {
        let socket = Socket::new(AF_PACKET.into(), SOCK_RAW.into(), Some(Self::PROTO.into()))
            .expect("Failed to create raw socket, are you running as root?");
        Self { inner: socket }
    }

    pub fn sendto(
        &self,
        buf: &[u8],
        interface_index: i32,
        address: &MacAddress,
    ) -> Result<(), std::io::Error> {
        let mut sockaddr = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: (Self::PROTO as u16).to_be(),
            sll_ifindex: interface_index,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0; 8],
        };
        sockaddr.sll_addr[..6].copy_from_slice(address.as_bytes());

        let result = unsafe {
            sendto(
                self.inner.as_raw_fd(),
                buf.as_ptr() as *const c_void,
                buf.len(),
                0,
                &sockaddr as *const sockaddr_ll as *const sockaddr,
                std::mem::size_of::<sockaddr_ll>() as u32,
            )
        };

        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
