#!/usr/bin/env python3
"""
DNS-SD Service Advertiser

This tool creates a long-running service that advertises itself via DNS-SD/mDNS
and responds to service discovery queries. It properly handles:
- Service registration and announcement
- Responding to PTR, SRV, TXT, and A record queries
- Periodic re-announcement
- Graceful shutdown with goodbye packets
"""

import socket
import struct
import sys
import time
import signal
import argparse
import threading
from typing import Dict, Optional


# mDNS Constants
MDNS_ADDR = '224.0.0.251'
MDNS_PORT = 5353

# DNS Record Types
TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_SRV = 33
TYPE_ANY = 255

# DNS Classes
CLASS_IN = 1
CLASS_IN_FLUSH = 0x8001


class DNSSDAdvertiser:
    """A DNS-SD service advertiser that responds to queries and sends announcements."""
    
    def __init__(self, instance_name: str, service_type: str, 
                 hostname: str, port: int, ip: str, 
                 txt_records: Optional[Dict[str, str]] = None):
        self.instance_name = instance_name
        self.service_type = service_type
        self.hostname = hostname
        self.port = port
        self.ip = ip
        self.txt_records = txt_records or {}
        self.full_service_name = f"{instance_name}.{service_type}"
        
        self.running = False
        self.sock = None
        
    def encode_dns_name(self, name: str) -> bytes:
        """Encode a domain name into DNS wire format."""
        encoded = b''
        for label in name.split('.'):
            if label:
                encoded += bytes([len(label)]) + label.encode('utf-8')
        encoded += b'\x00'
        return encoded
    
    def decode_dns_name(self, data: bytes, offset: int) -> tuple[str, int]:
        """
        Decode a DNS name from wire format, handling compression pointers.
        Returns (name, new_offset).
        """
        labels = []
        jumped = False
        jumps = 0
        max_jumps = 20
        original_offset = offset
        
        while True:
            if jumps > max_jumps:
                raise Exception("Too many compression jumps")
            
            if offset >= len(data):
                break
                
            length = data[offset]
            
            # Check for compression pointer (top 2 bits set)
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                # Pointer: next 14 bits are offset
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                offset = pointer
                jumped = True
                jumps += 1
                continue
            
            # End of name
            if length == 0:
                offset += 1
                break
            
            # Regular label
            offset += 1
            if offset + length > len(data):
                break
            label = data[offset:offset + length].decode('utf-8', errors='ignore')
            labels.append(label)
            offset += length
        
        return '.'.join(labels), original_offset if jumped else offset
    
    def parse_dns_question(self, data: bytes, offset: int) -> tuple[str, int, int, int]:
        """
        Parse a DNS question.
        Returns (qname, qtype, qclass, new_offset).
        """
        qname, offset = self.decode_dns_name(data, offset)
        if offset + 4 > len(data):
            return qname, 0, 0, offset
        qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
        return qname, qtype, qclass, offset + 4
    
    def create_dns_header(self, transaction_id: int, flags: int, 
                         qdcount: int = 0, ancount: int = 0,
                         nscount: int = 0, arcount: int = 0) -> bytes:
        """Create a DNS header."""
        return struct.pack('!HHHHHH', 
                          transaction_id, flags, 
                          qdcount, ancount, nscount, arcount)
    
    def create_dns_answer(self, name: str, rtype: int, rclass: int, 
                         ttl: int, rdata: bytes) -> bytes:
        """Create a DNS answer/resource record."""
        answer = self.encode_dns_name(name)
        answer += struct.pack('!HHI', rtype, rclass, ttl)
        answer += struct.pack('!H', len(rdata))
        answer += rdata
        return answer
    
    def create_a_record(self, ttl: int = 120) -> bytes:
        """Create an A record for the hostname."""
        parts = [int(p) for p in self.ip.split('.')]
        rdata = bytes(parts)
        return self.create_dns_answer(self.hostname, TYPE_A, CLASS_IN_FLUSH, ttl, rdata)
    
    def create_ptr_record(self, ttl: int = 120) -> bytes:
        """Create a PTR record for service browsing."""
        rdata = self.encode_dns_name(self.full_service_name)
        return self.create_dns_answer(self.service_type, TYPE_PTR, CLASS_IN, ttl, rdata)
    
    def create_srv_record(self, ttl: int = 120) -> bytes:
        """Create an SRV record for service location."""
        rdata = struct.pack('!HHH', 0, 0, self.port)
        rdata += self.encode_dns_name(self.hostname)
        return self.create_dns_answer(self.full_service_name, TYPE_SRV, CLASS_IN_FLUSH, ttl, rdata)
    
    def create_txt_record(self, ttl: int = 120) -> bytes:
        """Create a TXT record for service metadata."""
        rdata = b''
        for key, value in self.txt_records.items():
            txt_str = f"{key}={value}"
            txt_bytes = txt_str.encode('utf-8')
            rdata += bytes([len(txt_bytes)]) + txt_bytes
        if not rdata:
            rdata = b'\x00'
        return self.create_dns_answer(self.full_service_name, TYPE_TXT, CLASS_IN_FLUSH, ttl, rdata)
    
    def create_announcement(self, ttl: int = 120) -> bytes:
        """Create a full service announcement packet."""
        flags = 0x8400  # QR=1 (response), AA=1 (authoritative)
        header = self.create_dns_header(0, flags, ancount=4)
        
        packet = header
        packet += self.create_ptr_record(ttl)
        packet += self.create_srv_record(ttl)
        packet += self.create_txt_record(ttl)
        packet += self.create_a_record(ttl)
        
        return packet
    
    def send_announcement(self, ttl: int = 120):
        """Send a service announcement to the network."""
        packet = self.create_announcement(ttl)
        self.sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
        if ttl == 0:
            print(f"[SENT] Goodbye packet for {self.full_service_name}")
        else:
            print(f"[SENT] Announcement for {self.full_service_name} at {self.hostname}:{self.port}")
    
    def handle_query(self, data: bytes, addr: tuple):
        """Handle an incoming mDNS query."""
        try:
            # Parse header
            if len(data) < 12:
                return
            
            transaction_id, flags, qdcount, ancount, nscount, arcount = \
                struct.unpack('!HHHHHH', data[:12])
            
            # Only process queries (QR=0)
            if flags & 0x8000:
                return
            
            offset = 12
            responses = []
            
            # Parse questions
            for _ in range(qdcount):
                if offset >= len(data):
                    break
                
                qname, qtype, qclass, offset = self.parse_dns_question(data, offset)
                
                # Remove QU bit for comparison
                qclass_clean = qclass & 0x7FFF
                unicast_response = (qclass & 0x8000) != 0
                
                print(f"[RECV] Query from {addr[0]}: {qname} (Type: {qtype}, Class: {qclass_clean}, Unicast: {unicast_response})")
                
                # Check if this query is for our service
                should_respond = False
                
                if qtype == TYPE_PTR and qname == self.service_type:
                    should_respond = True
                    responses = [self.create_ptr_record()]
                
                elif qtype == TYPE_SRV and qname == self.full_service_name:
                    should_respond = True
                    responses = [self.create_srv_record()]
                
                elif qtype == TYPE_TXT and qname == self.full_service_name:
                    should_respond = True
                    responses = [self.create_txt_record()]
                
                elif qtype == TYPE_A and qname == self.hostname:
                    should_respond = True
                    responses = [self.create_a_record()]
                
                elif qtype == TYPE_ANY:
                    if qname == self.full_service_name:
                        should_respond = True
                        responses = [
                            self.create_srv_record(),
                            self.create_txt_record(),
                            self.create_a_record()
                        ]
                    elif qname == self.service_type:
                        should_respond = True
                        responses = [self.create_ptr_record()]
                    elif qname == self.hostname:
                        should_respond = True
                        responses = [self.create_a_record()]
                
                if should_respond:
                    # Build response packet
                    response_flags = 0x8400  # QR=1, AA=1
                    response_header = self.create_dns_header(0, response_flags, ancount=len(responses))
                    response_packet = response_header + b''.join(responses)
                    
                    # Send unicast or multicast based on QU bit
                    if unicast_response:
                        self.sock.sendto(response_packet, addr)
                        print(f"[SENT] Unicast response to {addr[0]}")
                    else:
                        self.sock.sendto(response_packet, (MDNS_ADDR, MDNS_PORT))
                        print(f"[SENT] Multicast response")
        
        except Exception as e:
            print(f"[ERROR] Error handling query: {e}")
    
    def listen_and_respond(self):
        """Listen for mDNS queries and respond to them."""
        print(f"[LISTENING] Waiting for queries on {MDNS_ADDR}:{MDNS_PORT}...")
        
        while self.running:
            try:
                self.sock.settimeout(1.0)
                data, addr = self.sock.recvfrom(9000)
                self.handle_query(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[ERROR] Error receiving data: {e}")
    
    def announce_periodically(self):
        """Send periodic announcements to maintain presence."""
        # Initial announcement
        time.sleep(1)
        self.send_announcement()
        
        # Re-announce at increasing intervals
        intervals = [1, 2, 4, 8, 16, 32]
        current_interval_idx = 0
        
        while self.running:
            interval = intervals[min(current_interval_idx, len(intervals) - 1)]
            time.sleep(interval)
            
            if self.running:
                self.send_announcement()
                if current_interval_idx < len(intervals) - 1:
                    current_interval_idx += 1
    
    def start(self):
        """Start the service advertiser."""
        try:
            # Create socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Allow multiple listeners on the same port (for Windows)
            if hasattr(socket, 'SO_REUSEPORT'):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            
            # Bind to mDNS port
            self.sock.bind(('', MDNS_PORT))
            
            # Join multicast group
            mreq = struct.pack('4sl', socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            # Set multicast TTL
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            
            self.running = True
            
            print(f"\n{'='*60}")
            print(f"DNS-SD Service Advertiser Started")
            print(f"{'='*60}")
            print(f"Service: {self.full_service_name}")
            print(f"Host: {self.hostname}")
            print(f"IP: {self.ip}")
            print(f"Port: {self.port}")
            if self.txt_records:
                print(f"TXT Records: {self.txt_records}")
            print(f"{'='*60}\n")
            
            # Start announcement thread
            announce_thread = threading.Thread(target=self.announce_periodically, daemon=True)
            announce_thread.start()
            
            # Listen and respond to queries
            self.listen_and_respond()
        
        except Exception as e:
            print(f"[ERROR] Failed to start advertiser: {e}")
            sys.exit(1)
    
    def stop(self):
        """Stop the service advertiser and send goodbye packets."""
        print("\n[STOPPING] Shutting down service...")
        self.running = False
        
        # Send goodbye packet (TTL=0)
        try:
            self.send_announcement(ttl=0)
            time.sleep(0.5)
        except:
            pass
        
        if self.sock:
            self.sock.close()
        
        print("[STOPPED] Service advertiser stopped.\n")


def main():
    parser = argparse.ArgumentParser(
        description='DNS-SD Service Advertiser - Advertise a service via mDNS/DNS-SD',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Advertise a web server:
    python dnssd_advertiser.py --service "My Web Server" --type _http._tcp.local --port 8080 --hostname myserver.local --ip 192.168.1.100
  
  Advertise SSH server with metadata:
    python dnssd_advertiser.py -s "Dev Server" -t _ssh._tcp.local -p 22 -H devbox.local -i 192.168.1.50 --txt version=1.0 --txt os=linux
  
  Advertise a custom service:
    python dnssd_advertiser.py -s "My API" -t _myapi._tcp.local -p 3000 -H api.local -i 192.168.1.200
        ''')
    
    parser.add_argument('-s', '--service', required=True, 
                       help='Service instance name (e.g., "My Web Server")')
    parser.add_argument('-t', '--type', required=True,
                       help='Service type (e.g., _http._tcp.local)')
    parser.add_argument('-p', '--port', type=int, required=True,
                       help='Port number')
    parser.add_argument('-H', '--hostname', required=True,
                       help='Hostname (e.g., myserver.local)')
    parser.add_argument('-i', '--ip', required=True,
                       help='IP address (e.g., 192.168.1.100)')
    parser.add_argument('--txt', action='append', 
                       help='TXT record (key=value). Can be specified multiple times.')
    
    args = parser.parse_args()
    
    # Parse TXT records
    txt_records = {}
    if args.txt:
        for txt in args.txt:
            if '=' in txt:
                key, value = txt.split('=', 1)
                txt_records[key] = value
    
    # Create advertiser
    advertiser = DNSSDAdvertiser(
        instance_name=args.service,
        service_type=args.type,
        hostname=args.hostname,
        port=args.port,
        ip=args.ip,
        txt_records=txt_records
    )
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        advertiser.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the advertiser
    advertiser.start()


if __name__ == '__main__':
    main()
