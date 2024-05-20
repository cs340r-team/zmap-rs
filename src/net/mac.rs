use eui48::ParseError;

pub struct MacAddress(eui48::MacAddress);

impl MacAddress {
    pub fn new(bytes: [u8; 6]) -> Self {
        MacAddress(eui48::MacAddress::new(bytes))
    }

    pub fn from_bytes(bytes: &[u8; 6]) -> Self {
        MacAddress(eui48::MacAddress::from_bytes(bytes).unwrap())
    }

    pub fn octets(&self) -> [u8; 6] {
        self.0.to_array()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn from_str(s: &str) -> Result<Self, ParseError> {
        match eui48::MacAddress::parse_str(s) {
            Ok(addr) => Ok(Self(addr)),
            Err(e) => Err(e),
        }
    }
}
