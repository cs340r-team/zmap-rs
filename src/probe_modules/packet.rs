
#[derive(Debug, Clone)]
pub struct PacketError;

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[Packet Error]")
    }
}

pub struct MacAddr(eui48::MacAddr);

pub impl MacAddr {
    pub fn new(bytes: [u8; 6]) -> Self {
         { MacAddr(eui48::MacAddr::new(bytes) }
    }

    pub fn from_bytes(bytes: &[u8; 6]) -> Self {
        { MacAddr(eui48::MacAddr::from_bytes(bytes).unwrap()) }
    }
    
    pub fn octets(&self) -> [u8; 6] {
        self.0.to_array()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn parse_str(s: &str) -> Result<Self, PacketErr> {
        match eui48::MacAddress::parse_str(s) {
            Ok(addr) => Ok(Self(addr)),
            Err(e) => Err("{} failed to parse MAC Address", e),
        }
    }
}



pub struct EthHdr(etherparse::Ethernet2Header);
pub struct IpHdr(etherparse::Ipv4Header);
pub struct IcmpHdr(etherparse::Icmpv4Header);
pub struct TcpHdr(etherparse::TcpHeader);
pub struct UdpHdr(etherparse::UdpHeader);
