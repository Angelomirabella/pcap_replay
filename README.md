# pcap_replay
pcap_replay is a cross-platform reimplementation of tcpreplay in Rust.

It currently supports the most common tcpreplay options and it retains the same syntax.

## Usage
```
USAGE:
    pcap_replay [OPTIONS] --intf1 <INTF1> <PCAPS>...

ARGS:
    <PCAPS>...    List of PCAPs to process

OPTIONS:
        --duration <NUM>        Limit the number of seconds to send
    -h, --help                  Print help information
    -i, --intf1 <INTF1>         Input network interface
    -l, --loop <NUM>            Loop through the capture file X times [default: 1]
    -L, --limit <NUM>           Limit the number of packets to send
        --listnics              List the available network interfaces
        --loopdelay-ms <NUM>    Delay between loops in milliseconds [default: 0]
    -M, --mbps <STR>            Replay packets at a given Mbps
        --maxsleep <NUM>        Sleep for no more then X milliseconds between packets
    -o, --oneatatime            Replay one packet at a time for each user input
    -p, --pps <STR>             Replay packets at a given packets/sec
    -P, --pid                   Print the PID of tcpreplay at startup
    -t, --topspeed              Replay packets as fast as possible
    -V, --version               Print version information
    -x, --multiplier <STR>      Modify replay speed to a given multiple [default: 1]
```

## Future Work
Currently missing features:
 * Proper logging
 * Pcap preloading
 * Pcapng support
 * Dualfile support
 * Flow stats
 * IP replacement

## Windows Disclaimer
Windows support relies on [WinSockRaw](https://github.com/Angelomirabella/WinSockRaw) which is a sample WFP driver.
This driver is not currently signed by Microsoft so it requires enabling [test signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option).
