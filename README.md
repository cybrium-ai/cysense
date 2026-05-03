# cysense

Passive network sensor — traffic capture, protocol dissection, anomaly
detection for IT / OT / IoMT environments. By [Cybrium AI](https://cybrium.ai).

## Install

### macOS / Linux

```
brew install cybrium-ai/cli/cysense
```

(Linux distributions with libpcap pre-installed include nearly every
modern distro; if not, `apt-get install libpcap0.8`.)

### Windows

cysense captures packets via libpcap. **Windows requires Npcap to be
installed on the host before running cysense.**

1. Download Npcap from <https://npcap.com> (free for personal /
   internal use).
2. Run the installer with the default options. *Important*: leave
   "WinPcap API-compatible Mode" enabled — that's what cysense
   links against.
3. Reboot if the installer asks (it usually does, due to the kernel
   driver).
4. Download `cysense-windows-amd64.exe` from the
   [latest release](https://github.com/cybrium-ai/cysense/releases/latest).

Without Npcap installed, cysense will fail at startup with a
`Packet.dll was not found` error. Other pcap-using tools on Windows
(Wireshark, nmap, ProcMon) require Npcap the same way; one install
satisfies all of them.

## Usage

```
cysense listen --interface eth0          # passive capture
cysense listen --interface eth0 --filter "tcp port 2575"  # HL7 only
cysense rot                              # hardware Root of Trust
cysense version                          # version + update check
cysense update                           # self-update
```

Run `cysense --help` for the full subcommand list.

## License

Apache-2.0. Note that Npcap (the runtime dependency on Windows) is
under its own licence — see <https://npcap.com/oem/redist.html>.
cysense binaries do not bundle Npcap; users install it themselves.
