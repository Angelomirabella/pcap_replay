//! Collection of utility methods.

#[cfg(windows)]
use crate::windows::interface;

#[cfg(target_os = "macos")]
use crate::macos::interface;


/// List the available interfaces.
pub fn listnics() {
    let interfaces = interface::get_interfaces().unwrap();

    println!("Available interfaces:");
    println!();

    interfaces.into_iter().for_each(|i| println!("{}", i.name));
}