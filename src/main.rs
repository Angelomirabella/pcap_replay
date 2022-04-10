//! Replay network traffic stored in PCAP/PCAPNG files.

#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

mod replay;
mod util;

use clap::{CommandFactory, Parser};


/// Reimplementation of the popular tool "tcpreplay".
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None, arg_required_else_help = true)]
pub struct Args {
    /// Input network interface.
    #[clap(long, short)]
    pub intf1: Option<String>,

    /// List the available network interfaces.
    #[clap(long)]
    pub listnics: bool,

    /// List of PCAPs to process.
    pub pcaps: Vec<String>,
}


fn main() {
    let args = Args::parse();
    let mut exit = false;

    if args.listnics {
        util::listnics();
        return;
    }

    if args.intf1.is_none() {
        eprintln!("Option intf1 is required");
        exit = true;
    }

    if args.pcaps.len() == 0 {
        eprintln!("At least one pcap file is required");
        exit = true;
    }

    if exit {
        Args::command().print_help().unwrap();
        return;
    }

    let replayer = replay::Replayer::from_args(&args);
    replayer.replay();
}
