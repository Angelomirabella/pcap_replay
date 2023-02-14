//! Retrieve information on the system network interfaces.

use std::io::{Error, ErrorKind, Result};
use std::ffi::CStr;

#[cfg(target_os = "linux")]
use std::ffi::CString;

use std::ops::Drop;

use libc::{close, c_int, freeifaddrs, getifaddrs, ifaddrs, write};

#[cfg(target_os = "macos")]
use libc::{BIOCSETIF, BIOCSHDRCMPLT, O_RDWR, ioctl, open};

#[cfg(target_os = "macos")]
use crate::unix::util::ifreq;

#[cfg(target_os = "linux")]
use libc::{AF_PACKET, SOCK_RAW, ETH_P_ALL, bind, if_nametoindex, sockaddr, sockaddr_ll, socket};

/// Network Interface.
pub struct Interface {
    // Name of the interface.
    pub name: String,
    // Socket fd (when in use).
    fd: Option<c_int>
}

impl Interface {
    /// Retrieve an interface from a ifaddrs struct.
    unsafe fn from_ifaddrs(interface: *mut ifaddrs) -> Interface {
        let ifaddr = &*interface;
        let name = CStr::from_ptr(ifaddr.ifa_name).to_string_lossy().into_owned();

        Interface { name, fd:None }
    }

    /// Open a socket (macos).
    #[cfg(target_os = "macos")]
    fn create_socket(&mut self) -> Result<()> {
        for i in 0..=99 {
            let bpf: c_int;
            let buf: String = format!("/dev/bpf{}", i);

            unsafe {
                bpf = open(buf.as_ptr().cast(), O_RDWR);
            }

            if bpf != -1 {
                self.fd = Some(bpf);
                break;
            }
        }

        // If the file descriptor is None we failed to find an available bpf device.
        if self.fd.is_none() {
            return Err(Error::new(ErrorKind::Other, "Failed to find an \
                                                            available bpf device."));
        }

        Ok(())
    }

    /// Open a socket (linux).
    #[cfg(target_os = "linux")]
    fn create_socket(&mut self) -> Result<()> {
        unsafe {
            match socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be()) {
                -1 => Err(Error::new(ErrorKind::Other,
                            format!("Failed to open socket with error {}.",
                            std::io::Error::last_os_error().raw_os_error().unwrap()))),
                fd => {
                    self.fd = Some(fd);
                    Ok(())
                }
            }
        }
    }

    // Bind socket to interface (macos).
    #[cfg(target_os = "macos")]
    fn bind_socket(&mut self) -> Result<()> {
        unsafe {
            // Bind to interface.
            let mut bound_if: ifreq = std::mem::zeroed();
            std::ptr::copy_nonoverlapping(self.name.as_ptr(),
                                            bound_if.ifr_name.as_mut_ptr().cast(),
                                            self.name.len());

            if ioctl(self.fd.unwrap(), BIOCSETIF, &bound_if) > 0 {
                return Err(Error::new(ErrorKind::Other, "Failed to bind to network \
                                                                    interface."));
            }

            // Spoof link layer.
            if ioctl(self.fd.unwrap(), BIOCSHDRCMPLT, &1) == -1 {
                return Err(Error::new(ErrorKind::Other, "Failed to set \
                                                                    BIOCSHDRCMPLT flag."));
            }
        }

        Ok(())
    }

    // Bind socket to interface (linux).
    #[cfg(target_os = "linux")]
    fn bind_socket(&mut self) -> Result<()> {
        unsafe {
            let mut bind_address: sockaddr_ll = std::mem::zeroed();
            let if_name = CString::new(self.name.as_str()).unwrap();

            match if_nametoindex(if_name.as_ptr()) {
                0 => return Err(Error::new(ErrorKind::Other,
                         format!("Failed to convert interface name to index with error: {}.",
                         std::io::Error::last_os_error().raw_os_error().unwrap()))),
                index => bind_address.sll_ifindex = index as c_int
            }

            bind_address.sll_family = AF_PACKET as u16;
            bind_address.sll_protocol = ETH_P_ALL.to_be() as u16;

            let bind_address_ptr = std::mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut bind_address);
            match bind(self.fd.unwrap(), bind_address_ptr, std::mem::size_of::<sockaddr_ll>() as u32) {
                0 => Ok(()),
                _ => Err(Error::new(ErrorKind::Other,
                                      format!("Failed to bind socket with error: {}.",
                                      std::io::Error::last_os_error().raw_os_error().unwrap())))
            }
        }
    }

    /// Inject a packet in the interface.
    pub fn inject_packet(&mut self, data: &[u8]) -> Result<usize> {
        if self.fd.is_none() {
            // Create socket.
            self.create_socket()?;

            // Bind socket.
            self.bind_socket()?;
        }

        // Write the data to the socket.
        let res :isize;
        unsafe {
            res = write(self.fd.unwrap(), data.as_ptr().cast(), data.len());
            if res < 0 {
                return Err(Error::new(ErrorKind::Other, "Failed to send all the data to \
                                                                    the network interface."));
            }
        }

        Ok(res as usize)
    }
}

/// Implement Drop to automatically close the socket.
impl Drop for Interface {
    fn drop(&mut self) {
        if self.fd.is_some() {
            unsafe {
                close(self.fd.unwrap());
            }
            self.fd = None;
        }
    }
}

/// Retrieve all the device network interfaces.
pub fn get_interfaces() -> Result<Vec<Interface>> {
    let mut ifaddrs: *mut ifaddrs= std::ptr::null_mut();
    let ifaddrs_ptr: *mut *mut ifaddrs = &mut ifaddrs;
    let mut res: Vec<Interface> = Vec::new();

    unsafe {
        let err = getifaddrs(ifaddrs_ptr);

        if err != 0 || ifaddrs.is_null() {
            // Error.
            return Err(Error::new(ErrorKind::Other,
                                  format!("getifaddrs failed with error code {}", err)));
        }

        // Parse the network interfaces.
        let mut interface = ifaddrs;
        while !interface.is_null() {
            if !(*interface).ifa_addr.is_null() {
                res.push(Interface::from_ifaddrs(interface));
            }

            interface = (*interface).ifa_next;
        }

        freeifaddrs(ifaddrs);
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::unix::interface::get_interfaces;

    #[test]
    fn test_get_interfaces() {
        assert!(!get_interfaces().unwrap().is_empty());
    }
}
