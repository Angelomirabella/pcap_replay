//! Collection of utility methods.

#[cfg(windows)]
use crate::windows::interface;

#[cfg(not(windows))]
use crate::unix::interface;

use std::collections::HashSet;


/// List the available interfaces.
pub fn listnics() {
    let interfaces: HashSet<String> = interface::get_interfaces().unwrap().into_iter().map(|i| i.name.clone()).collect();

    println!("Available interfaces:");
    println!();

    interfaces.into_iter().for_each(|name| println!("{}", name));
}