//! Retrieve information on the system network interfaces.

use std::io::{Error, ErrorKind, Result};
use std::ffi::CStr;
use std::ops::Drop;

use libc::{BIOCSETIF, BIOCSHDRCMPLT, close, c_int, freeifaddrs, getifaddrs, ifaddrs, ioctl, open,
           O_RDWR, write};

use crate::macos::util::ifreq;

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

    /// Inject a packet in the interface.
    pub fn inject_packet(&mut self, data: &[u8]) -> Result<usize> {
        if self.fd.is_none() {
            // Initialize socket.
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

            unsafe {
                // Bind to interface.
                let mut bound_if: ifreq = std::mem::zeroed();
                std::ptr::copy_nonoverlapping(self.name.as_ptr(),
                                              bound_if.ifr_name.as_mut_ptr().cast(),
                                              self.name.len());

                if ioctl( self.fd.unwrap(), BIOCSETIF, &bound_if) > 0 {
                    return Err(Error::new(ErrorKind::Other, "Failed to bind to network \
                                                                        interface."));
                }

                // Spoof link layer.
                if ioctl(self.fd.unwrap(), BIOCSHDRCMPLT, &1) == -1 {
                    return Err(Error::new(ErrorKind::Other, "Failed to set \
                                                                        BIOCSHDRCMPLT flag."));
                }
            }
        }

        // Write the data to the socket.
        unsafe {
            if write(self.fd.unwrap(), data.as_ptr().cast(),
                  data.len()) != data.len().try_into().unwrap() {
                return Err(Error::new(ErrorKind::Other, "Failed to send all the data to \
                                                                    the network interface."));
            }
        }

        Ok(data.len())
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
            res.push(Interface::from_ifaddrs(interface));
            interface = (*interface).ifa_next;
        }

        freeifaddrs(ifaddrs);
    }

    Ok(res)
}

/// Retrieve a network interface given its name.
pub fn get_interface(name: &String) -> Option<Interface> {
    get_interfaces().unwrap().into_iter().filter(| i| i.name == *name).next()
}

#[cfg(test)]
mod tests {
    use crate::macos::interface::get_interfaces;

    #[test]
    fn test_get_interfaces() {
        assert_eq!(get_interfaces().unwrap().len() > 0, true);
    }
}
