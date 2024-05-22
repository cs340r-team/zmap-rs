// References:
// https://www.tcpdump.org/manpages/pcap_compile.3pcap.html
// https://www.tcpdump.org/manpages/pcap_setfilter.3pcap.html
// https://man7.org/linux/man-pages/man3/pcap_loop.3pcap.html
use core::slice;

use chrono::DateTime;
pub use libc::{c_char, c_int, c_uchar, c_uint, c_ushort, timeval};
use log::info;

// Callback function to handle individual packets
pub type pcap_handler =
    extern "C" fn(usr: *mut c_uchar, h: *const pcap_pkthdr, bytes: *const c_uchar) -> ();

// Opaque pcap handle
// Reference: https://doc.rust-lang.org/nomicon/ffi.html
#[repr(C)]
struct pcap_t {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(C)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: c_uint,
    pub len: c_uint,
}

#[repr(C)]
struct bpf_program {
    bf_len: c_uint,
    bf_insns: *mut bpf_insn,
}

#[repr(C)]
struct bpf_insn {
    code: c_ushort,
    jt: c_uchar,
    jf: c_uchar,
    k: c_uint,
}

extern "C" {
    // Open a device for capturing
    fn pcap_open_live(
        device: *const c_char,
        snaplen: c_int,
        promisc: c_int,
        to_ms: c_int,
        errbuf: *mut c_char,
    ) -> *mut pcap_t;

    // Compile a filter expression
    fn pcap_compile(
        p: *mut pcap_t,
        fp: *mut bpf_program,
        string: *const c_char,
        optimize: c_int,
        netmask: c_uint,
    ) -> c_int;

    // Set the filter with the bpf program created by pcap_compile
    fn pcap_setfilter(p: *mut pcap_t, fp: *mut bpf_program) -> c_int;

    // Processes packets from a live capture until count packets are processed
    fn pcap_dispatch(
        p: *mut pcap_t,
        count: c_int,
        callback: pcap_handler,
        user: *mut c_uchar,
    ) -> c_int;

    // Reads the next packet and returns a success/failure indication
    fn pcap_next_ex(
        p: *mut pcap_t,
        pkt_header: *mut *mut pcap_pkthdr,
        pkt_data: *mut *const c_uchar,
    ) -> c_int;

    // int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header,
    // const u_char **pkt_data);

    fn pcap_close(p: *mut pcap_t);
}

pub struct PacketCapture {
    handle: *mut pcap_t,
}

impl PacketCapture {
    const PCAP_ERRBUF_SIZE: usize = 256;
    const PCAP_SNAPLEN: c_int = 8192;
    const PCAP_PROMISC: c_int = 1;
    const PCAP_TIMEOUT: c_int = 1000;
    const PCAP_OPTIMIZE: c_int = 1;

    pub fn new(interface: &str) -> Self {
        // Try to open the device
        let iface_cstr = std::ffi::CString::new(interface).unwrap();
        let mut errbuf = [0; Self::PCAP_ERRBUF_SIZE];
        let p = unsafe {
            pcap_open_live(
                iface_cstr.as_ptr(),
                Self::PCAP_SNAPLEN,
                Self::PCAP_PROMISC,
                Self::PCAP_TIMEOUT,
                errbuf.as_mut_ptr(),
            )
        };
        if p.is_null() {
            let err_str = unsafe { std::ffi::CStr::from_ptr(errbuf.as_ptr()) };
            panic!("pcap_open_live failed: {}", err_str.to_str().unwrap());
        }

        info!("Successfully opened device for interface {interface}");
        Self { handle: p }
    }

    pub fn with_filter(self, filter: &str) -> Self {
        // Compile the filter
        let mut bpf = bpf_program {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };
        let filter_cstr = std::ffi::CString::new(filter).unwrap();
        let res = unsafe {
            pcap_compile(
                self.handle,
                &mut bpf,
                filter_cstr.as_ptr(),
                Self::PCAP_OPTIMIZE,
                0,
            )
        };
        if res < 0 {
            panic!("pcap_compile failed to compile filter");
        }

        // Install the filter
        let res = unsafe { pcap_setfilter(self.handle, &mut bpf) };
        if res < 0 {
            panic!("pcap_setfilter failed to install filter");
        }

        self
    }

    pub fn dispatch(&self, callback: pcap_handler) -> i32 {
        // pcap_dispatch should be better than pcap_next_ex in terms of performance
        return unsafe { pcap_dispatch(self.handle, 0, callback, std::ptr::null_mut()) };
    }

    pub fn next_packet(&self) -> Packet {
        let mut pkt_header: *mut pcap_pkthdr = std::ptr::null_mut();
        let mut pkt_data: *const c_uchar = std::ptr::null_mut();
        let res = unsafe { pcap_next_ex(self.handle, &mut pkt_header, &mut pkt_data) };

        // pcap_next_ex() returns 1 if the packet was read without problems
        // 0 if packets are being read from a live capture and the packet buffer timeout expired
        if res <= 0 {
            panic!("pcap_next_ex failed to read next packet");
        }

        let caplen = unsafe { (*pkt_header).caplen }.try_into().unwrap();
        let header = unsafe { &*pkt_header };
        let data = unsafe { slice::from_raw_parts(pkt_data, caplen) };

        Packet::new(header, data)
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        unsafe { pcap_close(self.handle) };
    }
}

// For use with next_packet (zero-copy)
//
// pcap_next() reads the next packet (by calling pcap_dispatch() with a cnt of 1) and
// returns a u_char pointer to the data in that packet. The packet data is not to be
// freed by the caller, and is not guaranteed to be valid after the next call to
// pcap_next_ex(), pcap_next(), pcap_loop(), or pcap_dispatch(); if the code needs
// it to remain valid, it must make a copy of it. The pcap_pkthdr structure pointed
// to by h is filled in with the appropriate values for the packet.
pub struct Packet<'a> {
    pub header: &'a pcap_pkthdr,
    pub data: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn new(header: &'a pcap_pkthdr, data: &'a [u8]) -> Self {
        Self { header, data }
    }
}

impl<'a> std::fmt::Debug for Packet<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ts = unsafe { (*self.header).ts };
        let datetime = DateTime::from_timestamp(ts.tv_sec, ts.tv_usec as u32 * 1000)
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S");
        let caplen = unsafe { (*self.header).caplen };
        let len = unsafe { (*self.header).len };

        write!(
            f,
            "Packet {{ time: {}, captured length: {}, actual length: {}, data: {:?} }}",
            datetime, caplen, len, self.data
        )
    }
}
