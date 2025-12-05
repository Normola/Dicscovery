#!/usr/bin/env python3
"""
mDNS Broadcaster Tool

This tool allows you to send various types of mDNS messages onto the network:
- Query for hostnames and services
- Announce hostnames with IP addresses
- Browse for service types
- Probe for name conflicts
"""

import socket
import struct
import sys
import time
import argparse
from typing import List, Tuple

# mDNS Constants
MDNS_ADDR = '224.0.0.251'
MDNS_PORT = 5353

# DNS Record Types
TYPE_A = 1      # IPv4 address
TYPE_PTR = 12   # Pointer record
TYPE_TXT = 16   # Text record
TYPE_AAAA = 28  # IPv6 address
TYPE_SRV = 33   # Service record
TYPE_ANY = 255  # Any record type

# DNS Classes
CLASS_IN = 1
CLASS_IN_FLUSH = 0x8001  # Cache flush bit set


def encode_dns_name(name: str) -> bytes:
    """
    Encode a domain name into DNS wire format.
    Example: 'myhost.local' -> b'\\x06myhost\\x05local\\x00'
    """
    encoded = b''
    for label in name.split('.'):
        if label:
            encoded += bytes([len(label)]) + label.encode('utf-8')
    encoded += b'\x00'  # Null terminator
    return encoded


def create_dns_question(qname: str, qtype: int, qclass: int = CLASS_IN) -> bytes:
    """
    Create a DNS question section.
    """
    question = encode_dns_name(qname)
    question += struct.pack('!HH', qtype, qclass)
    return question


def create_dns_answer(name: str, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    """
    Create a DNS answer/resource record.
    """
    answer = encode_dns_name(name)
    answer += struct.pack('!HHI', rtype, rclass, ttl)
    answer += struct.pack('!H', len(rdata))
    answer += rdata
    return answer


def create_a_record_data(ip: str) -> bytes:
    """
    Create RDATA for an A (IPv4) record.
    """
    parts = [int(p) for p in ip.split('.')]
    return bytes(parts)


def create_srv_record_data(priority: int, weight: int, port: int, target: str) -> bytes:
    """
    Create RDATA for an SRV record.
    """
    rdata = struct.pack('!HHH', priority, weight, port)
    rdata += encode_dns_name(target)
    return rdata


def create_txt_record_data(txt_dict: dict) -> bytes:
    """
    Create RDATA for a TXT record from key-value pairs.
    """
    rdata = b''
    for key, value in txt_dict.items():
        txt_str = f"{key}={value}"
        txt_bytes = txt_str.encode('utf-8')
        rdata += bytes([len(txt_bytes)]) + txt_bytes
    return rdata if rdata else b'\x00'  # Empty TXT record has single zero byte


def create_dns_header(transaction_id: int = 0, flags: int = 0, 
                      qdcount: int = 0, ancount: int = 0,
                      nscount: int = 0, arcount: int = 0) -> bytes:
    """
    Create a DNS header.
    
    Flags format (16 bits):
    - QR (1 bit): 0=query, 1=response
    - Opcode (4 bits): 0=standard query
    - AA (1 bit): Authoritative answer
    - TC (1 bit): Truncated
    - RD (1 bit): Recursion desired
    - RA (1 bit): Recursion available
    - Z (3 bits): Reserved
    - RCODE (4 bits): Response code
    """
    return struct.pack('!HHHHHH', 
                      transaction_id, flags, 
                      qdcount, ancount, nscount, arcount)


def send_mdns_query(qname: str, qtype: int, unicast_response: bool = False):
    """
    Send an mDNS query to the network.
    """
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Set multicast TTL
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    
    # Build query packet
    qclass = CLASS_IN
    if unicast_response:
        qclass |= 0x8000  # Set QU (unicast response) bit
    
    header = create_dns_header(transaction_id=0, flags=0x0000, qdcount=1)
    question = create_dns_question(qname, qtype, qclass)
    packet = header + question
    
    # Send the query
    sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
    print(f"[SENT] mDNS Query: {qname} (Type: {qtype}, Unicast: {unicast_response})")
    
    sock.close()


def send_mdns_announcement(hostname: str, ip: str, ttl: int = 120):
    """
    Send an mDNS announcement (unsolicited response) for a hostname.
    """
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    
    # Build announcement packet (response with AA bit set)
    flags = 0x8400  # QR=1 (response), AA=1 (authoritative)
    header = create_dns_header(transaction_id=0, flags=flags, ancount=1)
    
    # Create A record
    a_record_data = create_a_record_data(ip)
    answer = create_dns_answer(hostname, TYPE_A, CLASS_IN_FLUSH, ttl, a_record_data)
    
    packet = header + answer
    
    # Send the announcement
    sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
    print(f"[SENT] mDNS Announcement: {hostname} -> {ip} (TTL: {ttl})")
    
    sock.close()


def send_mdns_probe(hostname: str, ip: str):
    """
    Send an mDNS probe query to check if a hostname is already taken.
    Probes are sent as queries with the proposed record in the Authority section.
    """
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    
    # Build probe packet
    header = create_dns_header(transaction_id=0, flags=0x0000, qdcount=1, nscount=1)
    question = create_dns_question(hostname, TYPE_ANY, CLASS_IN)
    
    # Authority section contains the proposed record
    a_record_data = create_a_record_data(ip)
    authority = create_dns_answer(hostname, TYPE_A, CLASS_IN, 120, a_record_data)
    
    packet = header + question + authority
    
    # Send probe (should be sent 3 times with 250ms intervals)
    for i in range(3):
        sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
        print(f"[SENT] mDNS Probe {i+1}/3: {hostname} (proposed IP: {ip})")
        if i < 2:
            time.sleep(0.25)
    
    sock.close()


def send_mdns_goodbye(hostname: str, ip: str):
    """
    Send an mDNS goodbye packet (TTL=0) to indicate service/host is going away.
    """
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    
    # Build goodbye packet (TTL=0)
    flags = 0x8400  # QR=1 (response), AA=1 (authoritative)
    header = create_dns_header(transaction_id=0, flags=flags, ancount=1)
    
    # Create A record with TTL=0
    a_record_data = create_a_record_data(ip)
    answer = create_dns_answer(hostname, TYPE_A, CLASS_IN, 0, a_record_data)
    
    packet = header + answer
    
    # Send goodbye
    sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
    print(f"[SENT] mDNS Goodbye: {hostname} (IP: {ip})")
    
    sock.close()


def send_service_query(service_type: str):
    """
    Send a DNS-SD service browsing query.
    Example: _http._tcp.local
    """
    send_mdns_query(service_type, TYPE_PTR)


def send_service_announcement(instance_name: str, service_type: str, 
                              hostname: str, port: int, ip: str, 
                              txt_records: dict = None, ttl: int = 120):
    """
    Send a DNS-SD service announcement with PTR, SRV, TXT, and A records.
    """
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    
    # Full service instance name
    full_service_name = f"{instance_name}.{service_type}"
    
    # Build announcement packet
    flags = 0x8400  # QR=1 (response), AA=1 (authoritative)
    header = create_dns_header(transaction_id=0, flags=flags, ancount=4)
    
    # PTR record: service_type -> full_service_name
    ptr_data = encode_dns_name(full_service_name)
    ptr_record = create_dns_answer(service_type, TYPE_PTR, CLASS_IN, ttl, ptr_data)
    
    # SRV record: full_service_name -> hostname:port
    srv_data = create_srv_record_data(0, 0, port, hostname)
    srv_record = create_dns_answer(full_service_name, TYPE_SRV, CLASS_IN_FLUSH, ttl, srv_data)
    
    # TXT record: metadata
    txt_data = create_txt_record_data(txt_records or {})
    txt_record = create_dns_answer(full_service_name, TYPE_TXT, CLASS_IN_FLUSH, ttl, txt_data)
    
    # A record: hostname -> IP
    a_data = create_a_record_data(ip)
    a_record = create_dns_answer(hostname, TYPE_A, CLASS_IN_FLUSH, ttl, a_data)
    
    packet = header + ptr_record + srv_record + txt_record + a_record
    
    # Send announcement
    sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
    print(f"[SENT] Service Announcement: {full_service_name} at {hostname}:{port} ({ip})")
    
    sock.close()


def main():
    parser = argparse.ArgumentParser(
        description='mDNS Broadcaster - Send various mDNS messages',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Query for a hostname:
    python mdns_broadcaster.py query mydevice.local
  
  Announce a hostname:
    python mdns_broadcaster.py announce myhost.local 192.168.1.100
  
  Browse for services:
    python mdns_broadcaster.py browse _http._tcp.local
  
  Probe for conflicts:
    python mdns_broadcaster.py probe testdevice.local 192.168.1.50
  
  Send goodbye:
    python mdns_broadcaster.py goodbye myhost.local 192.168.1.100
  
  Announce a service:
    python mdns_broadcaster.py service "My Web Server" _http._tcp.local myhost.local 8080 192.168.1.100
        ''')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Send an mDNS query')
    query_parser.add_argument('name', help='Hostname or service to query (e.g., mydevice.local)')
    query_parser.add_argument('--type', choices=['A', 'PTR', 'SRV', 'TXT', 'ANY'], 
                            default='A', help='Record type to query')
    query_parser.add_argument('--unicast', action='store_true', 
                            help='Request unicast response (QU bit)')
    
    # Announce command
    announce_parser = subparsers.add_parser('announce', help='Announce a hostname')
    announce_parser.add_argument('hostname', help='Hostname to announce (e.g., myhost.local)')
    announce_parser.add_argument('ip', help='IP address (e.g., 192.168.1.100)')
    announce_parser.add_argument('--ttl', type=int, default=120, help='TTL in seconds')
    
    # Browse command
    browse_parser = subparsers.add_parser('browse', help='Browse for services')
    browse_parser.add_argument('service', help='Service type (e.g., _http._tcp.local)')
    
    # Probe command
    probe_parser = subparsers.add_parser('probe', help='Probe for name conflicts')
    probe_parser.add_argument('hostname', help='Hostname to probe (e.g., myhost.local)')
    probe_parser.add_argument('ip', help='Proposed IP address')
    
    # Goodbye command
    goodbye_parser = subparsers.add_parser('goodbye', help='Send goodbye packet')
    goodbye_parser.add_argument('hostname', help='Hostname leaving the network')
    goodbye_parser.add_argument('ip', help='IP address')
    
    # Service command
    service_parser = subparsers.add_parser('service', help='Announce a service')
    service_parser.add_argument('instance', help='Service instance name')
    service_parser.add_argument('type', help='Service type (e.g., _http._tcp.local)')
    service_parser.add_argument('hostname', help='Host providing the service')
    service_parser.add_argument('port', type=int, help='Port number')
    service_parser.add_argument('ip', help='IP address')
    service_parser.add_argument('--txt', action='append', help='TXT record (key=value)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'query':
            type_map = {'A': TYPE_A, 'PTR': TYPE_PTR, 'SRV': TYPE_SRV, 
                       'TXT': TYPE_TXT, 'ANY': TYPE_ANY}
            send_mdns_query(args.name, type_map[args.type], args.unicast)
        
        elif args.command == 'announce':
            send_mdns_announcement(args.hostname, args.ip, args.ttl)
        
        elif args.command == 'browse':
            send_service_query(args.service)
        
        elif args.command == 'probe':
            send_mdns_probe(args.hostname, args.ip)
        
        elif args.command == 'goodbye':
            send_mdns_goodbye(args.hostname, args.ip)
        
        elif args.command == 'service':
            txt_dict = {}
            if args.txt:
                for txt in args.txt:
                    if '=' in txt:
                        key, value = txt.split('=', 1)
                        txt_dict[key] = value
            send_service_announcement(args.instance, args.type, args.hostname, 
                                    args.port, args.ip, txt_dict)
        
        print("\n✓ Packet sent successfully!")
        
    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
