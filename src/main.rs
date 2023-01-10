//! Replay network traffic stored in PCAP/PCAPNG files.

#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
mod unix;

mod replay;
mod util;

use clap::Parser;


/// Reimplementation of the popular tool "tcpreplay" (it may require administrator privileges).
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None, arg_required_else_help = true)]
pub struct Args {
    /// Limit the number of seconds to send.
    #[clap(default_value_t = u64::MAX, hide_default_value = true, long, value_name = "NUM",
           long_help = "Limit the number of seconds to send\n\t- it must be in the range:\n\t\
                        greater than or equal to 1")]
    pub duration: u64,

    /// Input network interface.
    #[clap(long, required = true, short)]
    pub intf1: Option<String>,

    /// List the available network interfaces.
    #[clap(conflicts_with_all = &["intf1", "pcaps"], long)]
    pub listnics: bool,

    /// Loop through the capture file X times.
    #[clap(default_value_t = 1, long = "loop", short, value_name = "NUM",
           long_help = "Loop through the capture file X times\n\t- it must be in the range:\n\t\
                        greater than or equal to 0")]
    pub l: u16,

    /// Limit the number of packets to send.
    #[clap(default_value_t = u64::MAX, hide_default_value = true, long, short = 'L',
           value_name = "NUM",
           long_help = "Limit the number of packets to send\n\t- it must be in the range:\n\t\
                        greater than or equal to 1")]
    pub limit: u64,

    /// Delay between loops in milliseconds.
    #[clap(default_value_t = 0, long, value_name = "NUM",
           long_help = "Delay between loops in milliseconds\n\t- requires the option 'loop'\n\t\
                        - it must be in the range:\n\tgreater than or equal to 0")]
    pub loopdelay_ms: u64,

    /// Sleep for no more then X milliseconds between packets.
    #[clap(default_value_t = u64::MAX, hide_default_value = true, long, value_name = "NUM")]
    pub maxsleep: u64,

    /// Replay packets at a given Mbps.
    #[clap(conflicts_with_all = &["oneatatime", "pps", "topspeed", "x"], default_value_t = 0.0,
           hide_default_value = true, long, short = 'M', value_name = "STR",
           long_help = "Replay packets at a given Mbps\n\t- prohibits these options:\n\t\
                        multiplier\n\toneatatime\n\tpps\n\ttopspeed")]
    pub mbps: f64,

    /// Replay one packet at a time for each user input.
    #[clap(conflicts_with_all = &["mbps", "pps", "topspeed", "x"], long, short,
           long_help = "Replay one packet at a time for each user input\n\t- prohibits these \
                        options:\n\tmbps\n\tmultiplier\n\tpps\n\ttopspeed")]
    pub oneatatime: bool,

    /// List of PCAPs to process.
    #[clap(required = true)]
    pub pcaps: Vec<String>,

    /// Print the PID of tcpreplay at startup.
    #[clap(long, short = 'P')]
    pub pid: bool,

    /// Replay packets at a given packets/sec.
    #[clap(conflicts_with_all = &["mbps", "oneatatime", "topspeed", "x"], default_value_t = 0.0,
           hide_default_value = true, long, short, value_name = "STR",
           long_help = "Replay packets at a given packets/sec\n\t- prohibits these options:\n\t\
                        multiplier\n\tmbps\n\toneatatime\n\ttopspeed")]
    pub pps: f64,

    /// Replay packets as fast as possible.
    #[clap(conflicts_with_all = &["mbps", "oneatatime", "pps", "x"], long, short,
           long_help = "Replay packets as fast as possible\n\t- prohibits these options:\n\t\
                        pps\n\tmbps\n\toneatatime\n\ttopspeed")]
    pub topspeed: bool,

    /// Modify replay speed to a given multiple.
    #[clap(conflicts_with_all = &["mbps", "oneatatime", "pps", "topspeed"], default_value_t = 1.0,
           long = "multiplier", short, value_name = "STR",
           long_help = "Modify replay speed to a given multiple\n\t- prohibits these options:\n\t\
                        pps\n\tmbps\n\toneatatime\n\ttopspeed")]
    pub x: f64
}


fn main() {
    let args = Args::parse();

    if args.pid {
        println!("PID: {}", std::process::id());
    }

    if args.listnics {
        util::listnics();
        return;
    }

    let mut replayer = replay::Replayer::from_args(args);
    replayer.replay();
}
