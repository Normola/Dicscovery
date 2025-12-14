#!/usr/bin/env python3
"""Quick mDNS multicast test"""
import socket
import struct

# mDNS multicast address and port
MDNS_ADDRESS = '224.0.0.251'
MDNS_PORT = 5353

# Create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind to mDNS port
sock.bind(('', MDNS_PORT))

# Join multicast group on specific interface
interface_ip = '192.168.0.21'
mreq = struct.pack('4s4s', socket.inet_aton(MDNS_ADDRESS), socket.inet_aton(interface_ip))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print(f"Listening for mDNS traffic on {interface_ip}...")
print("Press Ctrl+C to stop\n")

try:
    sock.settimeout(5.0)
    count = 0
    while count < 20:  # Listen for ~100 seconds
        try:
            data, addr = sock.recvfrom(9000)
            count += 1
            print(f"[{count}] Received {len(data)} bytes from {addr[0]}")
        except socket.timeout:
            print(".", end="", flush=True)
except KeyboardInterrupt:
    print("\nStopped")
finally:
    sock.close()

print(f"\nTotal packets received: {count}")
if count == 0:
    print("\n❌ No mDNS traffic detected!")
    print("Possible issues:")
    print("  - Router has AP/Client Isolation enabled")
    print("  - Multicast filtering is blocking mDNS")
    print("  - No devices are broadcasting mDNS")
else:
    print(f"\n✅ mDNS traffic is working! Received {count} packets")
