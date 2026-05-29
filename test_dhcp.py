#!/usr/bin/env python3
"""Test script for DHCP server - sends crafted packets to test all cases."""

import socket
import struct

SERVER = ("127.0.0.1", 67)

def send_packet(sock, data, description):
    print(f"--- Sending: {description} ({len(data)} bytes) ---")
    sock.sendto(data, SERVER)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Test 1: Packet too small (less than 240 bytes)
send_packet(sock, b"test", "Too small packet")

# Test 2: Correct size but invalid magic cookie
# 236 bytes header + 4 bytes wrong cookie
packet = b'\x01' + b'\x00' * 235 + b'\x00\x00\x00\x00'
send_packet(sock, packet, "Invalid magic cookie")

# Test 3: Correct cookie but op=2 (BOOTREPLY, not request)
packet = b'\x02' + b'\x00' * 235 + struct.pack('!I', 0x63825363)
send_packet(sock, packet, "BOOTREPLY (op=2), should be ignored")

# Test 4: Valid DHCP DISCOVER
packet = bytearray(548)  # full DHCP packet
packet[0] = 1            # op = BOOTREQUEST
packet[1] = 1            # htype = Ethernet
packet[2] = 6            # hlen = 6 (MAC)
packet[3] = 0            # hops
# xid = 0x12345678
struct.pack_into('!I', packet, 4, 0x12345678)
# chaddr = AA:BB:CC:DD:EE:FF
packet[28] = 0xAA
packet[29] = 0xBB
packet[30] = 0xCC
packet[31] = 0xDD
packet[32] = 0xEE
packet[33] = 0xFF
# magic cookie at offset 236
struct.pack_into('!I', packet, 236, 0x63825363)
# options start at offset 240
# Option 53 (MSG_TYPE), length 1, value 1 (DISCOVER)
packet[240] = 53
packet[241] = 1
packet[242] = 1
# Option 255 (END)
packet[243] = 255
send_packet(sock, bytes(packet), "Valid DHCP DISCOVER")

# Test 5: Valid packet but unknown message type (e.g. type 99)
packet[242] = 99  # change msg type to unknown
send_packet(sock, bytes(packet), "Unknown message type (99)")

sock.close()
print("\n--- All tests sent! Check server output. ---")
