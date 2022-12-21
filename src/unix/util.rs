/// Utility structs Unix specific.
/// Redefine some libc structures which are not available on MacOS.


#[cfg(target_os = "macos")]
use libc::{c_char, c_int, c_short, c_uchar, c_uint, c_void, size_t, sockaddr};

#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ifreq_buffer {
    pub length: size_t,
    pub buffer: *mut c_void,
}

#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(C)]
pub union anonymous_ifr_ifru {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_buffer: ifreq_buffer,
    pub ifru_flags: [c_short; 2],
    pub ifru_index: c_short,
    pub ifru_jid: c_int,
    pub ifru_metric: c_int,
    pub ifru_mtu: c_int,
    pub ifru_phys: c_int,
    pub ifru_media: c_int,
    pub ifru_data: *mut c_char,
    pub ifru_cap: [c_int; 2],
    pub ifru_fib: c_uint,
    pub ifru_vlan_pcp: c_uchar,
}

#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [c_char; 16],
    pub ifr_ifru: anonymous_ifr_ifru,
}