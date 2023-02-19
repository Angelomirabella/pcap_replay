//! Collection of utility methods.

#[cfg(windows)]
use crate::windows::interface::{self, Interface};

#[cfg(not(windows))]
use crate::unix::interface::{self, Interface};

use std::collections::HashSet;

/// Retrieve a network interface given its name.
pub fn get_interface(name: &str) -> Option<Interface> {
    interface::get_interfaces()
        .unwrap()
        .into_iter()
        .find(|i| i.name == *name)
}

/// List the available interfaces.
pub fn listnics() {
    let interfaces: HashSet<String> = interface::get_interfaces()
        .unwrap()
        .into_iter()
        .map(|i| i.name.clone())
        .collect();

    println!("Available interfaces:");
    println!();

    interfaces.into_iter().for_each(|name| println!("{}", name));
}
