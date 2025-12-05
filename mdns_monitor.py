#!/usr/bin/env python3
"""
mDNS Monitor/Listener

This tool captures and displays mDNS traffic on the network, helping you:
- See all mDNS queries and responses
- Discover services being advertised
- Analyze DNS record types and data
- Learn how mDNS works in practice
"""

import socket
import struct
import sys
import signal
import argparse
from datetime import datetime
from typing import List, Tuple


# mDNS Constants
MDNS_ADDR = '224.0.0.251'
MDNS_PORT = 5353

# DNS Record Types
DNS_TYPES = {
    1: 'A',      # IPv4 address
    2: 'NS',     # Name server
    5: 'CNAME',  # Canonical name
    12: 'PTR',   # Pointer
    13: 'HINFO', # Host info
    15: 'MX',    # Mail exchange
    16: 'TXT',   # Text
    28: 'AAAA',  # IPv6 address
    33: 'SRV',   # Service
    47: 'NSEC',  # Next secure
    255: 'ANY',  # Any type
}

# DNS Classes
DNS_CLASSES = {
    1: 'IN',     # Internet
    255: 'ANY',  # Any class
}


class MDNSMonitor:
    """Monitor and decode mDNS traffic on the network."""
    
    def __init__(self, verbose: bool = False, filter_type: str = None):
        self.verbose = verbose
        self.filter_type = filter_type
        self.running = False
        self.sock = None
        self.packet_count = 0
    
    def decode_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """
        Decode a DNS name from wire format, handling compression.
        Returns (name, new_offset).
        """
        labels = []
        jumped = False
        jumps = 0
        max_jumps = 20
        original_offset = offset
        
        while True:
            if jumps > max_jumps or offset >= len(data):
                break
            
            length = data[offset]
            
            # Compression pointer
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
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
    
    def parse_question(self, data: bytes, offset: int) -> Tuple[dict, int]:
        """Parse a DNS question."""
        qname, offset = self.decode_name(data, offset)
        if offset + 4 > len(data):
            return None, offset
        
        qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
        offset += 4
        
        # Check for QU bit (unicast response requested)
        unicast = (qclass & 0x8000) != 0
        qclass = qclass & 0x7FFF
        
        return {
            'name': qname,
            'type': DNS_TYPES.get(qtype, f'TYPE{qtype}'),
            'type_num': qtype,
            'class': DNS_CLASSES.get(qclass, f'CLASS{qclass}'),
            'unicast': unicast
        }, offset
    
    def parse_rdata(self, data: bytes, offset: int, rtype: int, rdlength: int) -> Tuple[str, int]:
        """Parse resource record data based on type."""
        rdata_end = offset + rdlength
        
        if rdata_end > len(data):
            return "MALFORMED", offset + rdlength
        
        try:
            if rtype == 1:  # A record
                if rdlength == 4:
                    ip = '.'.join(str(b) for b in data[offset:offset + 4])
                    return ip, rdata_end
            
            elif rtype == 28:  # AAAA record
                if rdlength == 16:
                    parts = struct.unpack('!8H', data[offset:offset + 16])
                    ipv6 = ':'.join(f'{p:x}' for p in parts)
                    return ipv6, rdata_end
            
            elif rtype == 12:  # PTR record
                name, _ = self.decode_name(data, offset)
                return name, rdata_end
            
            elif rtype == 16:  # TXT record
                txt_parts = []
                pos = offset
                while pos < rdata_end:
                    length = data[pos]
                    pos += 1
                    if pos + length > rdata_end:
                        break
                    txt = data[pos:pos + length].decode('utf-8', errors='ignore')
                    txt_parts.append(txt)
                    pos += length
                return ' | '.join(txt_parts) if txt_parts else '(empty)', rdata_end
            
            elif rtype == 33:  # SRV record
                if rdlength >= 6:
                    priority, weight, port = struct.unpack('!HHH', data[offset:offset + 6])
                    target, _ = self.decode_name(data, offset + 6)
                    return f"{target}:{port} (priority={priority}, weight={weight})", rdata_end
            
            elif rtype == 47:  # NSEC record
                next_name, pos = self.decode_name(data, offset)
                # Type bitmap follows
                return f"Next: {next_name}", rdata_end
            
            else:
                # Unknown type - show as hex
                hex_data = data[offset:rdata_end].hex()
                if len(hex_data) > 40:
                    hex_data = hex_data[:40] + '...'
                return f"0x{hex_data}", rdata_end
        
        except Exception as e:
            return f"ERROR: {e}", rdata_end
        
        return "UNKNOWN", rdata_end
    
    def parse_record(self, data: bytes, offset: int) -> Tuple[dict, int]:
        """Parse a DNS resource record."""
        name, offset = self.decode_name(data, offset)
        if offset + 10 > len(data):
            return None, offset
        
        rtype, rclass, ttl = struct.unpack('!HHI', data[offset:offset + 8])
        rdlength = struct.unpack('!H', data[offset + 8:offset + 10])[0]
        offset += 10
        
        # Check for cache flush bit
        cache_flush = (rclass & 0x8000) != 0
        rclass = rclass & 0x7FFF
        
        rdata, offset = self.parse_rdata(data, offset, rtype, rdlength)
        
        return {
            'name': name,
            'type': DNS_TYPES.get(rtype, f'TYPE{rtype}'),
            'type_num': rtype,
            'class': DNS_CLASSES.get(rclass, f'CLASS{rclass}'),
            'ttl': ttl,
            'cache_flush': cache_flush,
            'rdata': rdata
        }, offset
    
    def parse_packet(self, data: bytes, addr: Tuple[str, int]):
        """Parse and display an mDNS packet."""
        try:
            if len(data) < 12:
                return
            
            # Parse header
            transaction_id, flags, qdcount, ancount, nscount, arcount = \
                struct.unpack('!HHHHHH', data[:12])
            
            is_query = (flags & 0x8000) == 0
            is_response = not is_query
            authoritative = (flags & 0x0400) != 0
            truncated = (flags & 0x0200) != 0
            rcode = flags & 0x000F
            
            # Apply filter
            if self.filter_type:
                if self.filter_type == 'query' and not is_query:
                    return
                if self.filter_type == 'response' and not is_response:
                    return
            
            self.packet_count += 1
            
            # Print packet header
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            packet_type = 'QUERY' if is_query else 'RESPONSE'
            
            print(f"\n{'='*70}")
            print(f"[{timestamp}] Packet #{self.packet_count} from {addr[0]}:{addr[1]} - {packet_type}")
            print(f"{'='*70}")
            
            if self.verbose:
                print(f"Transaction ID: 0x{transaction_id:04x}")
                print(f"Flags: 0x{flags:04x} (AA={authoritative}, TC={truncated}, RCODE={rcode})")
                print(f"Questions: {qdcount}, Answers: {ancount}, Authority: {nscount}, Additional: {arcount}")
            
            offset = 12
            
            # Parse questions
            if qdcount > 0:
                print(f"\n--- QUESTIONS ({qdcount}) ---")
                for i in range(qdcount):
                    question, offset = self.parse_question(data, offset)
                    if question:
                        unicast_flag = " [QU]" if question['unicast'] else ""
                        print(f"  {question['name']}")
                        print(f"    Type: {question['type']}, Class: {question['class']}{unicast_flag}")
            
            # Parse answers
            if ancount > 0:
                print(f"\n--- ANSWERS ({ancount}) ---")
                for i in range(ancount):
                    record, offset = self.parse_record(data, offset)
                    if record:
                        cache_flush_flag = " [FLUSH]" if record['cache_flush'] else ""
                        goodbye = " [GOODBYE]" if record['ttl'] == 0 else ""
                        print(f"  {record['name']}")
                        print(f"    Type: {record['type']}, TTL: {record['ttl']}s{cache_flush_flag}{goodbye}")
                        print(f"    Data: {record['rdata']}")
            
            # Parse authority records
            if nscount > 0:
                print(f"\n--- AUTHORITY ({nscount}) ---")
                for i in range(nscount):
                    record, offset = self.parse_record(data, offset)
                    if record:
                        print(f"  {record['name']}")
                        print(f"    Type: {record['type']}, TTL: {record['ttl']}s")
                        print(f"    Data: {record['rdata']}")
            
            # Parse additional records
            if arcount > 0 and self.verbose:
                print(f"\n--- ADDITIONAL ({arcount}) ---")
                for i in range(arcount):
                    record, offset = self.parse_record(data, offset)
                    if record:
                        print(f"  {record['name']}")
                        print(f"    Type: {record['type']}, TTL: {record['ttl']}s")
                        print(f"    Data: {record['rdata']}")
        
        except Exception as e:
            print(f"\n[ERROR] Failed to parse packet: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
    
    def start(self):
        """Start monitoring mDNS traffic."""
        try:
            # Create socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Allow multiple listeners (for Windows)
            if hasattr(socket, 'SO_REUSEPORT'):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            
            # Bind to mDNS port
            self.sock.bind(('', MDNS_PORT))
            
            # Join multicast group
            mreq = struct.pack('4sl', socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            self.running = True
            
            print(f"\n{'='*70}")
            print(f"mDNS Monitor Started")
            print(f"{'='*70}")
            print(f"Listening on: {MDNS_ADDR}:{MDNS_PORT}")
            if self.filter_type:
                print(f"Filter: {self.filter_type.upper()} packets only")
            print(f"Verbose: {self.verbose}")
            print(f"Press Ctrl+C to stop")
            print(f"{'='*70}")
            
            # Listen for packets
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(9000)
                    self.parse_packet(data, addr)
                except Exception as e:
                    if self.running:
                        print(f"\n[ERROR] {e}")
        
        except PermissionError:
            print("\n[ERROR] Permission denied. Try running with administrator/root privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"\n[ERROR] Failed to start monitor: {e}")
            sys.exit(1)
    
    def stop(self):
        """Stop the monitor."""
        print(f"\n\n{'='*70}")
        print(f"mDNS Monitor Stopped")
        print(f"Total packets captured: {self.packet_count}")
        print(f"{'='*70}\n")
        self.running = False
        if self.sock:
            self.sock.close()


def main():
    parser = argparse.ArgumentParser(
        description='mDNS Monitor - Capture and analyze mDNS traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Monitor all traffic:
    python mdns_monitor.py
  
  Monitor with detailed output:
    python mdns_monitor.py --verbose
  
  Monitor only queries:
    python mdns_monitor.py --filter query
  
  Monitor only responses:
    python mdns_monitor.py --filter response
        ''')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show verbose output including additional records')
    parser.add_argument('-f', '--filter', choices=['query', 'response'],
                       help='Filter by packet type (query or response)')
    
    args = parser.parse_args()
    
    monitor = MDNSMonitor(verbose=args.verbose, filter_type=args.filter)
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        monitor.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    monitor.start()


if __name__ == '__main__':
    main()
