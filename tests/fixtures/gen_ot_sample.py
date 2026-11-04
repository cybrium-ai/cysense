#!/usr/bin/env python3
"""Generate a tiny 2-packet pcap for cysense replay tests — no scapy needed.
Packet 1: Modbus/TCP (dst :502) engineering workstation -> PLC.
Packet 2: S7comm (dst :102) workstation -> S7 PLC.
Hand-built Ethernet/IPv4/TCP; checksums left zero (dissector keys on port+payload)."""
import struct, sys

def eth(dst, src, payload):
    return dst + src + b"\x08\x00" + payload

def ipv4(src, dst, l4):
    total = 20 + len(l4)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 6, 0, src, dst)
    return hdr + l4

def tcp(sport, dport, payload):
    hdr = struct.pack("!HHLLBBHHH", sport, dport, 1, 0, 0x50, 0x18, 8192, 0, 0)
    return hdr + payload

def mac(s):  return bytes(int(x, 16) for x in s.split(":"))
def ip(s):   return bytes(int(x) for x in s.split("."))

ws  = mac("00:11:22:33:44:55")
plc1 = mac("aa:bb:cc:dd:ee:01")
plc2 = mac("aa:bb:cc:dd:ee:02")

# Modbus PDU: txid(2) protoid(2=0x0000) len(2) unit(1) func(1) addr(2) qty(2)
modbus = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"
p1 = eth(plc1, ws, ipv4(ip("10.0.0.5"), ip("10.0.0.10"), tcp(50001, 502, modbus)))

# S7comm over TPKT: 0x03 0x00 <len> + COTP + S7 header
s7 = b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
p2 = eth(plc2, ws, ipv4(ip("10.0.0.5"), ip("10.0.0.20"), tcp(50002, 102, s7)))

out = sys.argv[1] if len(sys.argv) > 1 else "ot_sample.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))  # pcap global hdr (BE magic)
    for pkt in (p1, p2):
        f.write(struct.pack("!IIII", 1609459200, 0, len(pkt), len(pkt)))  # record hdr
        f.write(pkt)
print(f"wrote {out}: 2 packets")
