#!/usr/bin/env python3
"""Test script for DHCP server - sends DISCOVER and listens for OFFER."""

import socket
import struct

SERVER = ("127.0.0.1", 67)

def send_packet(sock, data, description):
    print(f"--- Sending: {description} ({len(data)} bytes) ---")
    sock.sendto(data, SERVER)

def parse_offer(data):
    """Parse a DHCP OFFER response."""
    if len(data) < 240:
        print("  Response too small")
        return
    op = data[0]
    xid = struct.unpack_from('!I', data, 4)[0]
    yiaddr = socket.inet_ntoa(data[16:20])
    siaddr = socket.inet_ntoa(data[20:24])
    chaddr = ':'.join(f'{b:02x}' for b in data[28:34])
    cookie = struct.unpack_from('!I', data, 236)[0]

    print(f"  op={op} (2=REPLY), xid=0x{xid:08x}")
    print(f"  Offered IP (yiaddr): {yiaddr}")
    print(f"  Server IP (siaddr):  {siaddr}")
    print(f"  Client MAC (chaddr): {chaddr}")

    # Parse options
    if cookie == 0x63825363:
        i = 240
        while i < len(data):
            code = data[i]
            if code == 255:
                break
            if code == 0:
                i += 1
                continue
            length = data[i + 1]
            value = data[i + 2:i + 2 + length]
            if code == 53:
                types = {1:'DISCOVER',2:'OFFER',3:'REQUEST',4:'DECLINE',5:'ACK',6:'NAK',7:'RELEASE'}
                print(f"  Option 53 (Msg Type): {types.get(value[0], value[0])}")
            elif code == 54:
                print(f"  Option 54 (Server ID): {socket.inet_ntoa(value)}")
            elif code == 51:
                lease = struct.unpack('!I', value)[0]
                print(f"  Option 51 (Lease Time): {lease}s")
            elif code == 1:
                print(f"  Option 1  (Subnet Mask): {socket.inet_ntoa(value)}")
            elif code == 3:
                print(f"  Option 3  (Router): {socket.inet_ntoa(value)}")
            elif code == 6:
                print(f"  Option 6  (DNS): {socket.inet_ntoa(value)}")
            else:
                print(f"  Option {code}: {value.hex()}")
            i += 2 + length

# Create socket and bind to port 68 to receive OFFER
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind(("0.0.0.0", 68))
sock.settimeout(3)

# Build DHCP DISCOVER
packet = bytearray(548)
packet[0] = 1            # op = BOOTREQUEST
packet[1] = 1            # htype = Ethernet
packet[2] = 6            # hlen = 6 (MAC)
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
# Option 53 (MSG_TYPE), length 1, value 1 (DISCOVER)
packet[240] = 53
packet[241] = 1
packet[242] = 1
# Option 255 (END)
packet[243] = 255

send_packet(sock, bytes(packet), "Valid DHCP DISCOVER")

# Wait for OFFER
print("\n--- Waiting for DHCP OFFER... ---")
try:
    data, addr = sock.recvfrom(1024)
    print(f"--- Received response from {addr} ({len(data)} bytes) ---")
    parse_offer(data)
except socket.timeout:
    print("  No response (timeout after 3s)")

sock.close()
print("\n--- Done! ---")
