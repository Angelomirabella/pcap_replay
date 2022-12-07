//! Replay PCAP file(s).

use super::Args;

use std::fs::File;

use pcap_parser::*;

#[cfg(target_os = "macos")]
use crate::macos::interface::{self, Interface};

#[cfg(windows)]
use crate::windows::interface::{self, Interface};

/// Replayer object in charge of the main processing logic.
pub struct Replayer<'a> {
    /// Main input network interface.
    intf1: &'a String,

    /// Pcaps to replay.
    pcaps: &'a Vec<String>
}

impl<'a> Replayer<'a> {
    /// Construct a Replayer object from the command line arguments.
    pub fn from_args(args: &Args) -> Replayer {
        Replayer {intf1: args.intf1.as_ref().unwrap(),
                  pcaps: args.pcaps.as_ref()
        }
    }

    /// Replay a single PCAP file.
    fn _replay_pcap(interface: &mut Interface, name: &String) {
        let file = File::open(name).unwrap();
        let mut pcap_cnt = 0;
        let mut reader = create_reader(65536, file).unwrap();
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(_hdr) => {
                            // Nothing to do, we are not interested in the PCAP header.
                        },
                        PcapBlockOwned::Legacy(b) => {
                            // Got data.
                            pcap_cnt += 1;
                            println!("Sending packet {}", pcap_cnt);
                            interface.inject_packet(b.data).unwrap();
                        },
                        PcapBlockOwned::NG(_) => unreachable!(),
                    }
                    reader.consume(offset);
                },
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete) => {
                    reader.refill().unwrap();
                },
                Err(e) => panic!("error while reading: {:?}", e),
            }
        }
    }

    /// Replay the pcap(s).
    pub fn replay(&self) {
        // Validate the interface.
        let mut interface = interface::get_interface(self.intf1)
                                           .expect("Invalid intf1 specified. Please list \
                                                         available interfaces with option \
                                                         \"--listnics\"");

        // Support only PCAP files in a first iteration.
        for pcap in self.pcaps {
            Replayer::<'a>::_replay_pcap(&mut interface, pcap);
        }
    }
}

