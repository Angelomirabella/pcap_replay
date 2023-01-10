//! Retrieve information on the system network interfaces.

use std::io::{Error, ErrorKind, Result};

use winapi::{
    shared::{
        ntdef::PULONG,
        ifdef::{IF_INDEX, IfOperStatusUp},
        winerror::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
        ws2def::AF_UNSPEC,
        minwindef::FALSE,
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::INVALID_HANDLE_VALUE,
        iptypes::PIP_ADAPTER_ADDRESSES,
        iphlpapi::GetAdaptersAddresses,
        winnt::HANDLE
    },
};

use winsockraw_sys;

use crate::windows::util;


/// Network Interface.
pub struct Interface {
    // Interface name (friendly name).
    pub name: String,
    // Interface index.
    pub index: IF_INDEX,
    // Corresponding WinSockRaw socket.
    socket_handle: HANDLE,
}

impl Interface {
    /// Retrieve an interface from a PIP_ADAPTER_ADDRESSES.
    unsafe fn from_ip_adapter_addresses(adapter_address: PIP_ADAPTER_ADDRESSES) -> Interface {
        let adapter_address = &*adapter_address;
        let name = util::pwchar_to_string(adapter_address.FriendlyName);

        Interface { name, index: adapter_address.u.s().IfIndex, socket_handle: INVALID_HANDLE_VALUE }
    }

    /// Inject a packet in the interface.
    pub fn inject_packet(&mut self, data: &[u8]) -> Result<usize> {
        if self.socket_handle == INVALID_HANDLE_VALUE {
            unsafe {
                // Create socket.
                self.socket_handle = winsockraw_sys::SocketRawOpen();
                if self.socket_handle == INVALID_HANDLE_VALUE {
                    return Err(Error::new(ErrorKind::Other, "Failed to open raw socket."));
                }

                // Bind to interface.
                if winsockraw_sys::SocketRawBind(self.socket_handle, self.index) == FALSE {
                    return Err(Error::new(ErrorKind::Other, "Failed to bind raw socket to interface."));
                }
            }
        }

        unsafe {
            let bytes_sent = winsockraw_sys::SocketRawSend(self.socket_handle, data.as_ptr() as *mut i8, data.len() as u32);
            if bytes_sent != data.len().try_into().unwrap() {
                return Err(Error::new(
                            ErrorKind::Other,
                            format!("Failed to send data to the network interface with error: {}", GetLastError())));
            }
        }

        Ok(data.len())
    }
}

/// Implement Drop to automatically close the socket.
impl Drop for Interface {
    fn drop(&mut self) {
        if self.socket_handle != INVALID_HANDLE_VALUE {
            unsafe {
                winsockraw_sys::SocketRawClose(self.socket_handle);
            }
            self.socket_handle = INVALID_HANDLE_VALUE;
        }
    }
}

/// Retrieve all the device network interfaces.
pub fn get_interfaces() -> Result<Vec<Interface>> {
    // Default recommended buffer size is 15KB from
    // https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
    // It actually works with 16KB.
    let mut sizepointer: u32 = 16384;
    let mut adapter_addresses: Vec<u8> = Vec::new();
    let mut res: Vec<Interface> = Vec::new();
    let mut err = ERROR_BUFFER_OVERFLOW;

    while err == ERROR_BUFFER_OVERFLOW {
        adapter_addresses.resize(sizepointer as usize, 0);

        unsafe {
            err = GetAdaptersAddresses(AF_UNSPEC as u32,
                                       0,
                                       std::ptr::null_mut(),
                                       adapter_addresses.as_mut_ptr() as PIP_ADAPTER_ADDRESSES,
                                       &mut sizepointer as PULONG);
        }
    }

    if err != ERROR_SUCCESS {
        return Err(Error::new(ErrorKind::Other,
                              format!("GetAdaptersAddresses failed with error code {}", err)));
    }

    // Parse the network interfaces.
    let mut adapter_address = adapter_addresses.as_mut_ptr() as PIP_ADAPTER_ADDRESSES;
    while !adapter_address.is_null() {
        unsafe {
            if (*adapter_address).OperStatus == IfOperStatusUp  {
                res.push(Interface::from_ip_adapter_addresses(adapter_address));
            }

            adapter_address = (*adapter_address).Next;
        }
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::windows::interface::get_interfaces;

    #[test]
    fn test_get_interfaces() {
        assert_eq!(get_interfaces().unwrap().len() > 0, true);
    }
}
