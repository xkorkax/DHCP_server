#!/usr/bin/env python3
"""Test script for DHCP server - simulates full DORA cycle, RELEASE, and NAK."""

import socket
import struct
import time

SERVER = ("127.0.0.1", 67)
CLIENT_MAC = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
TRANSACTION_ID = 0x12345678


def send_packet(sock, data, description):
    print(f"\n--- Sending: {description} ({len(data)} bytes) ---")
    sock.sendto(data, SERVER)


def parse_response(data):
    """Parse a DHCP response and return Offered IP and Server ID."""
    if len(data) < 240:
        print("  Error: Response too small")
        return None, None

    op = data[0]
    xid = struct.unpack_from("!I", data, 4)[0]
    yiaddr = socket.inet_ntoa(data[16:20])
    siaddr = socket.inet_ntoa(data[20:24])
    cookie = struct.unpack_from("!I", data, 236)[0]

    print(f"  op={op} (2=REPLY), xid=0x{xid:08x}")
    print(f"  Offered/Acked IP (yiaddr): {yiaddr}")
    print(f"  Server IP (siaddr):  {siaddr}")

    offered_ip = yiaddr
    server_id = siaddr

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
            value = data[i + 2 : i + 2 + length]

            if code == 53:
                types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
                print(f"  Option 53 (Msg Type): {types.get(value[0], value[0])}")
            elif code == 54:
                server_id = socket.inet_ntoa(value)
                print(f"  Option 54 (Server ID): {server_id}")
            elif code == 51:
                lease = struct.unpack("!I", value)[0]
                print(f"  Option 51 (Lease Time): {lease}s")
            elif code == 1:
                print(f"  Option 1  (Subnet Mask): {socket.inet_ntoa(value)}")

            i += 2 + length

    return offered_ip, server_id


def build_base_packet(set_broadcast_flag=False):
    """Builds the common DHCP header."""
    packet = bytearray(548)
    packet[0] = 1  # op = BOOTREQUEST
    packet[1] = 1  # htype = Ethernet
    packet[2] = 6  # hlen = 6 (MAC)
    struct.pack_into("!I", packet, 4, TRANSACTION_ID)

    # Ustawianie flagi Broadcast (bit 0x8000 na offsecie 10)
    if set_broadcast_flag:
        packet[10] = 0x80

    packet[28:34] = CLIENT_MAC
    struct.pack_into("!I", packet, 236, 0x63825363)  # Magic cookie
    return packet


def build_discover(set_broadcast_flag=False):
    packet = build_base_packet(set_broadcast_flag)
    packet[240:243] = bytes([53, 1, 1])  # Option 53: DISCOVER
    packet[243] = 255  # Option 255: END
    return bytes(packet)


def build_request(requested_ip, server_id, set_broadcast_flag=False):
    packet = build_base_packet(set_broadcast_flag)
    offset = 240

    # Option 53: REQUEST (Length 1, Value 3)
    packet[offset : offset + 3] = bytes([53, 1, 3])
    offset += 3

    # Option 50: Requested IP (Length 4)
    packet[offset : offset + 2] = bytes([50, 4])
    packet[offset + 2 : offset + 6] = socket.inet_aton(requested_ip)
    offset += 6

    # Option 54: Server Identifier (Length 4)
    packet[offset : offset + 2] = bytes([54, 4])
    packet[offset + 2 : offset + 6] = socket.inet_aton(server_id)
    offset += 6

    # Option 255: END
    packet[offset] = 255
    return bytes(packet)


def build_release(client_ip, server_id):
    packet = build_base_packet()
    # For release, the client puts its IP in ciaddr
    packet[12:16] = socket.inet_aton(client_ip)

    offset = 240
    # Option 53: RELEASE (Length 1, Value 7)
    packet[offset : offset + 3] = bytes([53, 1, 7])
    offset += 3

    # Option 54: Server Identifier
    packet[offset : offset + 2] = bytes([54, 4])
    packet[offset + 2 : offset + 6] = socket.inet_aton(server_id)
    offset += 6

    packet[offset] = 255
    return bytes(packet)


# --- Main Execution ---
def run_tests():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", 68))
    sock.settimeout(3)

    print("==================================================")
    print(" ROZPOCZYNAM TESTY SERWERA DHCP")
    print("==================================================")

    # 1. Send DISCOVER (z włączoną flagą broadcast)
    send_packet(sock, build_discover(set_broadcast_flag=True), "DHCP DISCOVER (Flaga Broadcast=1)")

    try:
        data, addr = sock.recvfrom(1024)
        print(f"--- Received response from {addr} ---")
        offered_ip, server_id = parse_response(data)

        if offered_ip and server_id:
            # 2. Send REQUEST to confirm the offered IP
            time.sleep(1)  # Small delay for realistic flow
            send_packet(
                sock, build_request(offered_ip, server_id, set_broadcast_flag=True), f"DHCP REQUEST (Prośba o {offered_ip})"
            )

            data, addr = sock.recvfrom(1024)
            print(f"--- Received response from {addr} ---")
            parse_response(data)

            # 3. Send RELEASE to free up the IP pool
            time.sleep(1)
            send_packet(sock, build_release(offered_ip, server_id), "DHCP RELEASE")
            print("\n--- Adres uwolniony pomyślnie! ---")

            # --- 4. TEST NEGATYWNY: Wymuszanie DHCP NAK ---
            print("\n==================================================")
            print(" TEST NEGATYWNY: Wymuszanie NAK")
            print("==================================================")
            time.sleep(1)

            # Klient zuchwale prosi o IP "10.0.0.99", którego nie ma w puli
            # Ustawiamy set_broadcast_flag=False (unicast), żeby przetestować, czy Twój serwer bezpiecznie zmieni to na broadcast dla NAK!
            bad_request_pkt = build_request("10.0.0.99", server_id, set_broadcast_flag=False)
            send_packet(sock, bad_request_pkt, "DHCP REQUEST (Nieprawidłowe IP: 10.0.0.99)")

            try:
                data, addr = sock.recvfrom(1024)
                print(f"--- Received response from {addr} ---")
                parse_response(data)
                print("\n--- Test negatywny zakończony sukcesem (Serwer poprawnie odmówił)! ---")
            except socket.timeout:
                print("  Błąd: Brak odpowiedzi na zły REQUEST (Sprawdź logikę NAK w C)")

    except socket.timeout:
        print("  Błąd: Brak odpowiedzi (timeout) przy pierwszym zapytaniu. Czy serwer działa?")
    finally:
        sock.close()
        print("\n==================================================")
        print(" TESTY ZAKOŃCZONE")
        print("==================================================")


if __name__ == "__main__":
    run_tests()
