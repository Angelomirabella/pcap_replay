//! Retrieve information on the system network interfaces.

use std::io::{Error, ErrorKind, Result};
use std::os::windows::raw::SOCKET;

use winapi::shared::ntdef::PULONG;
use winapi::shared::winerror::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use winapi::shared::ws2def::AF_UNSPEC;
use winapi::um::iptypes::PIP_ADAPTER_ADDRESSES;
use winapi::um::iphlpapi::GetAdaptersAddresses;

use socket2::SockAddr;

use crate::windows::util;


/// Network Adapter.
pub struct NetworkInterface {
    // Name of the adapter (friendly name).
    pub name: String,
    // Adapter address.
    pub address: SockAddr,
    // Corresponding SOCKET (if opened).
    pub fd: SOCKET,
}

impl NetworkInterface {
    /// Retrieve an interface from a PIP_ADAPTER_ADDRESSES.
    unsafe fn from_ip_adapter_addresses(adapter: PIP_ADAPTER_ADDRESSES) -> NetworkInterface {
        let adapter = &*adapter;
        let name = util::pwchar_to_string(adapter.FriendlyName);

        // Map SOCKET_ADDRESS to SockAddr.
        let sock_address = &(*(adapter.FirstUnicastAddress)).Address;
        let (_, address) = SockAddr::init(|storage, length| {
            let dst: *mut u8 = storage.cast();
            dst.copy_from_nonoverlapping(sock_address.lpSockaddr.cast(),
                                         sock_address.iSockaddrLength as usize);
            *length = sock_address.iSockaddrLength;
            Ok(())
        }).unwrap();

        NetworkInterface { name, address, fd: 0 }
    }
}

/// Retrieve all the device network interfaces.
pub fn get_interfaces() -> Result<Vec<NetworkInterface>> {
    // Default recommended buffer size is 15KB from
    // https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
    // It actually works with 16KB.
    let mut sizepointer: u32 = 16384;
    let mut adapters: Vec<u8> = Vec::new();
    let mut res: Vec<NetworkInterface> = Vec::new();
    let mut err = ERROR_BUFFER_OVERFLOW;

    while err == ERROR_BUFFER_OVERFLOW {
        adapters.resize(sizepointer as usize, 0);

        unsafe {
            err = GetAdaptersAddresses(AF_UNSPEC as u32,
                                       0,
                                       std::ptr::null_mut(),
                                       adapters.as_mut_ptr() as PIP_ADAPTER_ADDRESSES,
                                       &mut sizepointer as PULONG);
        }
    }

    if err != ERROR_SUCCESS {
        return Err(Error::new(ErrorKind::Other,
                              format!("GetAdaptersAddresses failed with error code {}", err)));
    }

    // Parse the network interfaces.
    let mut adapter = adapters.as_mut_ptr() as PIP_ADAPTER_ADDRESSES;
    while !adapter.is_null() {
        unsafe {
            if !(*adapter).FirstUnicastAddress.is_null()  {
                res.push(NetworkInterface::from_ip_adapter_addresses(adapter));
            }

            adapter = (*adapter).Next;
        }
    }

    Ok(res)
}

/// Retrieve a network interface given its name.
pub fn get_interface(name: &str) -> Option<NetworkInterface> {
    let adapters = get_interfaces().unwrap();

    adapters.into_iter()
        .filter(| i: &NetworkInterface| i.name == *name)
        .min_by_key(| i | i.address.family())
}

#[cfg(test)]
mod tests {
    use crate::windows::interface::get_interfaces;

    #[test]
    fn test_get_interfaces() {
        assert_eq!(get_interfaces().unwrap().len() > 0, true);
    }
}
