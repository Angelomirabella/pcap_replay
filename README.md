# pcap_replay
Reimplementation of tcpreplay in Rust.

## Usage

## Windows
Windows support relies on [WinSockRaw](https://github.com/Angelomirabella/WinSockRaw) which is a sample WFP driver.
This driver is not currently signed by Microsoft so it requires enabling [test signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option).
