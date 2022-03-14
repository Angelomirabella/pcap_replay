//! Replay PCAP file(s).

// use super::Args;
//
// use std::fs::File;
//
// use pcap_parser::*;
// use pcap_parser::traits::PcapReaderIterator;
// use socket2::{Socket, Domain, Type, SockAddr};

// /// Replayer object in charge of the main processing logic.
// pub struct Replayer<'a> {
//     /// Main input network interface.
//     intf1: &'a String,
//
//     /// Pcaps to replay.
//     pcaps: &'a Vec<String>
// }
//
// impl<'a> Replayer<'a> {
//     /// Construct a Replayer object from the command line arguments.
//     pub fn from_args(args: &Args) -> Replayer {
//         Replayer {intf1: args.intf1.as_ref().unwrap(),
//                   pcaps: args.pcaps.as_ref()
//         }
//     }
//
//
//     /// Replay a single PCAP file.
//     fn _replay_pcap(interface: &Socket, addr: &SockAddr, name: &String) {
//         let file = File::open(name).unwrap();
//         let mut pcap_cnt = 0;
//         let mut reader = LegacyPcapReader::new(65536, file).unwrap();
//
//         loop {
//             match reader.next() {
//                 Ok((offset, block)) => {
//                     match block {
//                         PcapBlockOwned::LegacyHeader(_hdr) => {
//                             // Nothing to do, we are not interested in the PCAP header.
//                         },
//                         PcapBlockOwned::Legacy(b) => {
//                             // Got data.
//                             pcap_cnt += 1;
//                             let skip;
//
//                             #[cfg(unix)]
//                             {
//                                 skip = 0;
//                             }
//
//                             #[cfg(windows)]
//                             {
//                                 // Need to skip the Ethernet header because is not yet supported on
//                                 // Windows.
//                                 skip = 14;
//                             }
//                             println!{"Packet {} has data \n {:?}", pcap_cnt, b.data};
//                             interface.send_to(&b.data[skip..], addr).unwrap();
//                         },
//                         PcapBlockOwned::NG(_) => unreachable!(),
//                     }
//                     reader.consume(offset);
//                 },
//                 Err(PcapError::Eof) => break,
//                 Err(PcapError::Incomplete) => {
//                     reader.refill().unwrap();
//                 },
//                 Err(e) => panic!("error while reading: {:?}", e),
//             }
//         }
//     }
//
//     /// Replay the pcap(s).
//     pub fn replay(&self) {
//         // Validate the interface.
//         let interface = interface::get_interface(self.intf1)
//                                            .expect("Invalid intf1 specified. Please list \
//                                                          available interfaces with option \
//                                                          \"--listnics\"");
//
//         let addr = interface.address.as_socket().expect("Specified interface is \
//                                                                         not an AF_INET socket");
//         let domain;
//
//         #[cfg(unix)]
//         {
//             domain = Domain::PACKET;
//         }
//
//         #[cfg(windows)]
//         {
//             // Windows does not yet support raw sockets. Want to avoid dependency on winpcap headers
//             // so custom kernel module will be implemented soon(ish).
//             if addr.is_ipv4() {
//                 domain = Domain::IPV4;
//             } else if addr.is_ipv6() {
//                 domain = Domain::IPV6;
//             } else {
//                 unreachable!();
//             }
//         }
//
//         let socket = Socket::new(domain, Type::RAW, None)
//                                     .expect("Socket creation failed");
//         //socket.bind(&addr.into()).expect("Socket bind failed");
//
//         // Support only PCAP files in a first iteration.
//         for pcap in self.pcaps {
//             Replayer::<'a>::_replay_pcap(&socket, &interface.address, pcap);
//         }
//     }
// }
//
