//! Retrieve information on the system network interfaces.

use std::io::{Error, ErrorKind, Result};

#[cfg(target_os = "windows")]
use {
    winapi::shared::ntdef::PULONG,
    winapi::shared::winerror::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
    winapi::shared::ws2def::AF_UNSPEC,
    winapi::um::iptypes::PIP_ADAPTER_ADDRESSES,
    winapi::um::iphlpapi::GetAdaptersAddresses
};
use socket2::SockAddr;


use crate::util;


pub struct Interface {
    // Name of the interface (friendly name for Windows).
    pub name: String,
    // Interface address, None if an interface is not available.
    pub address: Option<SockAddr>
}

impl Interface {
    #[cfg(windows)]
    /// Retrieve an interface from a PIP_ADAPTER_ADDRESSES.
    unsafe fn from_ip_adapter_addresses(adapter: PIP_ADAPTER_ADDRESSES) -> Interface {
        let adapter = &*adapter;
        let name = util::pwchar_to_string(adapter.FriendlyName);

        if adapter.FirstUnicastAddress.is_null() {
            return Interface{ name, address: None };
        }

        // Map SOCKET_ADDRESS to SockAddr.
        let sock_address = &(*(adapter.FirstUnicastAddress)).Address;
        let (_, address) = SockAddr::init(|storage, length| {
                let dst: *mut u8 = storage.cast();
                dst.copy_from_nonoverlapping(sock_address.lpSockaddr.cast(),
                                                 sock_address.iSockaddrLength as usize);
                *length = sock_address.iSockaddrLength;
                Ok(())
        }).unwrap();

        Interface{ name, address: Some(address) }
    }
}


#[cfg(windows)]
/// Retrieve all the device network interfaces (Windows).
fn _get_interfaces_win() -> Result<Vec<Interface>> {
    // Default recommended buffer size is 15KB from
    // https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
    // It actually works with 16KB.
    let mut sizepointer: u32 = 16384;
    let mut adapters: Vec<u8> = Vec::new();
    let mut res: Vec<Interface> = Vec::new();
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
            res.push(Interface::from_ip_adapter_addresses(adapter));
            adapter = (*adapter).Next;
        }
    }

    Ok(res)
}

#[cfg(unix)]
/// Retrieve all the device network interfaces (Unix).
fn _get_interfaces_unix() -> Result<Vec<Interface>> {

    Ok(Vec::new())
}

/// Retrieve all the device network interfaces.
/// Wrapper around the corresponding platform specific methods.
pub fn get_interfaces() -> Result<Vec<Interface>> {
    #[cfg(windows)]
    {
        _get_interfaces_win()
    }

    #[cfg(unix)]
    {
        _get_interfaces_unix()
    }

    #[cfg(not(windows))]
    #[cfg(not(unix))]
    {
        unimplemented!("Unsupported target OS");
    }
}
