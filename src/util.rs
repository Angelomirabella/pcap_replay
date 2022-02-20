//! Collection of utility methods.

#[cfg(windows)]
use winapi::shared::ntdef::PWCHAR;

use crate::interface;

use std::collections::HashSet;

/// Print the command help.
pub fn show_usage() {
    println!("pcap_replay [options] <pcap_file>\n\n\
              --listnics:\t\t List available network interfaces and exit.");
}

#[cfg(windows)]
/// Convert a PWSTR (UTF-16) to String.
/// Implement it as utility method since we cannot implement traits for type we do not own.
pub fn pwchar_to_string(source: PWCHAR) -> String {
    let mut end = source;

    unsafe {
        while *end != 0 {
            end = end.add(1);
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(source,
                                                            end.offset_from(source) as _))
    }
}

/// List the available interfaces.
pub fn listnics() {
    let interfaces = interface::get_interfaces().unwrap();

    println!("Available interfaces:");
    println!();

    // Remove duplicates that might be there because of multiple addresses.
    let names: HashSet<String> = interfaces.into_iter().map(|i| i.name).collect();
    names.into_iter().for_each(|name| println!("{}", name));
}