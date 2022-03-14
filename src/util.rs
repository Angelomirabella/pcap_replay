//! Collection of utility methods.

use std::collections::HashSet;

#[cfg(windows)]
use crate::windows::interface;

#[cfg(unix)]
use crate::unix::interface;


/// List the available interfaces.
pub fn listnics() {
    let interfaces = interface::get_interfaces().unwrap();

    println!("Available interfaces:");
    println!();

    // Remove duplicates that might be there because of multiple addresses.
    let names: HashSet<String> = interfaces.into_iter().map(|i| i.name).collect();
    names.into_iter().for_each(|name| println!("{}", name));
}