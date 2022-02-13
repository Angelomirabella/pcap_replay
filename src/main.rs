//! Replay network traffic stored in PCAP/PCAPNG files.
//!
//! Reimplementation of the popular tool "tcpreplay".

mod interface;
mod util;

use std::env;


fn main() {
    if env::args().count() == 1 {
        util::show_usage();
        return
    }

    /* Parse command line arguments. */
    for arg in env::args().skip(1) {
        match &*arg {
            "--listnics" => {
                util::listnics();
                return;
            },
            "-h" | "--help" | _ => {
                util::show_usage();
                return;
            }
        }
    }
}
