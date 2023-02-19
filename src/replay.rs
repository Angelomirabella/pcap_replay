//! Replay PCAP file(s).

use super::Args;

use std::{
    fs::File,
    time::{SystemTime, UNIX_EPOCH},
};

use pcap_parser::*;

use crate::util;

#[cfg(windows)]
use crate::windows::interface::Interface;

#[cfg(not(windows))]
use crate::unix::interface::Interface;

/// Replayer object in charge of the main processing logic.
pub struct Replayer {
    /// Program arguments.
    args: Args,
    /// Abort program if packet/seconds limit is set.
    abort: bool,
    /// Sent bytes counter.
    byte_cnt: u64,
    /// Number of remaining packets to send when replaying in `oneatatime` mode.
    oneatatime_packets_cnt: u32,
    /// Sent packets counter.
    packet_cnt: u64,
    /// Sent truncated packets counter.
    packet_truncated_cnt: u64,
    /// Timestamp of the first packet sent.
    start_ts_us: u64,
}

impl Replayer {
    /// Construct a Replayer object from the command line arguments.
    pub fn from_args(args: Args) -> Replayer {
        Replayer {
            args,
            abort: false,
            byte_cnt: 0,
            oneatatime_packets_cnt: 0,
            packet_cnt: 0,
            packet_truncated_cnt: 0,
            start_ts_us: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64,
        }
    }

    /// Wait before sending the packet (if required).
    fn _wait(&mut self, last_pkt_ts_us: u64, curr_pkt_ts_us: u64, elapsed_ts_us: u64) {
        if last_pkt_ts_us == 0 {
            // First packet, don't need to wait.
            return;
        }

        // Calculate how long to sleep.
        let mut sleep_us: u64 = 0;
        match &self.args {
            Args { mbps, .. } if *mbps > 0.0 => {
                let delta_us =
                    (self.byte_cnt as f64 * 8.0 * 1000000.0 / (self.args.mbps * 1000000.0)) as u64;
                if delta_us > elapsed_ts_us {
                    sleep_us = delta_us - elapsed_ts_us;
                }
            }
            Args {
                oneatatime: true, ..
            } => {
                // Just wait on user's input.
                if self.oneatatime_packets_cnt == 0 {
                    println!(
                        "**** Next packet #{} out {}. How many packets do you wish to send?",
                        self.packet_cnt + 1,
                        self.args.intf1.as_ref().unwrap()
                    );
                    let mut input = String::new();
                    self.oneatatime_packets_cnt = std::io::stdin()
                        .read_line(&mut input)
                        .map_or_else(|_e| 1, |_v| input.trim().parse::<u32>().unwrap_or(1));
                }
                println!(
                    "Sending packet {} out: {}",
                    self.packet_cnt + 1,
                    self.args.intf1.as_ref().unwrap()
                );

                self.oneatatime_packets_cnt -= 1;
            }
            Args { pps, .. } if *pps > 0.0 => {
                let delta_us = (self.packet_cnt as f64 * 1000000.0 / self.args.pps) as u64;
                if delta_us > elapsed_ts_us {
                    sleep_us = delta_us - elapsed_ts_us;
                }
            }
            Args { topspeed: true, .. } => {}
            _ => {
                // Rely on packets timestamps.
                sleep_us = ((curr_pkt_ts_us - last_pkt_ts_us) as f64 * self.args.x) as u64;
            }
        }

        // Adjust the sleep time to not exceed `maxsleep` and sleep.
        if u128::from(sleep_us) > u128::from(self.args.maxsleep) * 1000 {
            sleep_us = (u128::from(self.args.maxsleep) * 1000) as u64;
        }

        if sleep_us > 0 {
            std::thread::sleep(std::time::Duration::from_micros(sleep_us));
        }
    }

    /// Replay a single PCAP file.
    fn _replay_pcap(&mut self, interface: &mut Interface, pcap: &String) {
        let file = File::open(pcap).unwrap();
        let mut reader = create_reader(65536, file).unwrap();
        let mut last_pkt_ts_us: u64 = 0;

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::Legacy(b) => {
                            // Check if we need to abort because of too many packets sent / too
                            // much time elapsed.
                            let curr_ts_us = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_micros() as u64;
                            let elapsed_ts_us = curr_ts_us - self.start_ts_us;
                            if self.packet_cnt > self.args.limit
                                || u128::from(elapsed_ts_us)
                                    >= u128::from(self.args.duration) * 1000000
                            {
                                self.abort = true;
                                return;
                            }

                            // Wait, if required.
                            let curr_pkt_ts_us: u64 =
                                (b.ts_sec as u64 * 1000000) + b.ts_usec as u64;
                            self._wait(last_pkt_ts_us, curr_pkt_ts_us, elapsed_ts_us);

                            // Send data and update timestamp.
                            match interface.inject_packet(b.data) {
                                Err(e) => {
                                    println!("{}", e);
                                    self.abort = true;
                                    return;
                                }
                                Ok(len) => {
                                    if len < b.data.len() {
                                        self.packet_truncated_cnt += 1;
                                    } else {
                                        self.packet_cnt += 1;
                                    }

                                    self.byte_cnt += len as u64;
                                }
                            }

                            last_pkt_ts_us = curr_pkt_ts_us;
                        }
                        PcapBlockOwned::NG(_) => unreachable!(),
                        _ => {}
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete) => {
                    reader.refill().unwrap();
                }
                Err(e) => panic!("error while reading: {:?}", e),
            }
        }
    }

    /// Replay the pcap(s).
    pub fn replay(&mut self) {
        // Validate the interface.
        let mut interface = util::get_interface(self.args.intf1.as_ref().unwrap()).expect(
            "Invalid intf1 specified. Please list \
                                                         available interfaces with option \
                                                         \"--listnics\"",
        );

        // Support only PCAP files in a first iteration.
        for _ in 0..self.args.l {
            for pcap in &self.args.pcaps.clone() {
                self._replay_pcap(&mut interface, pcap);

                // Check if need to abort because we reached some thresholds.
                if self.abort {
                    break;
                }
            }

            // Check if need to abort because we reached some thresholds.
            if self.abort {
                break;
            }

            // Sleep between loops, if needed.
            if self.args.loopdelay_ms > 0 && self.args.l > 0 {
                std::thread::sleep(std::time::Duration::from_millis(self.args.loopdelay_ms));
            }
        }

        // Print exit stats.
        let end_ts_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let elapsed_s = (end_ts_us - self.start_ts_us) as f64 / 1000000.0;
        println!(
            "Actual: {} packets ({} bytes) sent in {:.6} seconds",
            self.packet_cnt, self.byte_cnt, elapsed_s
        );
        println!(
            "Rated: {:.1} Bps, {:.3} Mbps, {:.2} pps",
            self.byte_cnt as f64 / elapsed_s,
            self.byte_cnt as f64 * 8.0 / 1000000.0 / elapsed_s,
            self.packet_cnt as f64 / elapsed_s
        );
        println!(
            "Statistics for network device: {}",
            self.args.intf1.as_ref().unwrap()
        );
        println!(
            "\tSuccessful packets:\t{}\n\tFailed packets:\t\t{}\n\tTruncated packets:\t{}",
            self.packet_cnt, 0, self.packet_truncated_cnt
        );
    }
}
