#!/usr/bin/env python3
"""
Network Discovery Tool

Discover all mDNS devices and services on your local network by sending
multiple queries and collecting responses. This tool helps you see everything
that's available on your network.
"""

import socket
import struct
import sys
import signal
import argparse
import time
from datetime import datetime
from typing import Dict, Set, Tuple


# mDNS Constants
MDNS_ADDR = '224.0.0.251'
MDNS_PORT = 5353

# DNS Record Types
TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_ANY = 255

# DNS Classes
CLASS_IN = 1

# Common service types to query
COMMON_SERVICES = [
    '_services._dns-sd._udp.local',  # Service enumeration
    '_http._tcp.local',               # Web servers
    '_https._tcp.local',              # Secure web servers
    '_ssh._tcp.local',                # SSH servers
    '_smb._tcp.local',                # Samba/Windows file sharing
    '_ftp._tcp.local',                # FTP servers
    '_printer._tcp.local',            # Printers
    '_ipp._tcp.local',                # Internet Printing Protocol
    '_scanner._tcp.local',            # Scanners
    '_airplay._tcp.local',            # Apple AirPlay
    '_raop._tcp.local',               # Remote Audio Output
    '_spotify-connect._tcp.local',    # Spotify Connect
    '_googlecast._tcp.local',         # Google Chromecast
    '_workstation._tcp.local',        # Workstations
    '_device-info._tcp.local',        # Device info
    '_sftp-ssh._tcp.local',          # SFTP over SSH
    '_homekit._tcp.local',           # Apple HomeKit
    '_hap._tcp.local',               # HomeKit Accessory Protocol
    '_companion-link._tcp.local',     # Apple devices
]


class NetworkDiscovery:
    """Discover all mDNS devices and services on the network."""
    
    def __init__(self, timeout: int = 3, custom_services: list = None, debug: bool = False):
        self.timeout = timeout
        self.custom_services = custom_services or []
        self.debug = debug
        self.running = False
        self.sock = None
        
        # Discovery results
        self.services = {}  # service_type -> set of instances
        self.hosts = {}     # hostname -> set of IPs
        self.service_details = {}  # full_service_name -> {host, port, txt}
        self.raw_responses = []
        
    def encode_dns_name(self, name: str) -> bytes:
        """Encode a domain name into DNS wire format."""
        encoded = b''
        for label in name.split('.'):
            if label:
                encoded += bytes([len(label)]) + label.encode('utf-8')
        encoded += b'\x00'
        return encoded
    
    def decode_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Decode a DNS name from wire format, handling compression."""
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
    
    def parse_rdata(self, data: bytes, offset: int, rtype: int, rdlength: int) -> Tuple[str, int]:
        """Parse resource record data."""
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
                    if pos >= len(data):
                        break
                    length = data[pos]
                    pos += 1
                    if pos + length > rdata_end:
                        break
                    txt = data[pos:pos + length].decode('utf-8', errors='ignore')
                    txt_parts.append(txt)
                    pos += length
                return txt_parts, rdata_end
            
            elif rtype == 33:  # SRV record
                if rdlength >= 6:
                    priority, weight, port = struct.unpack('!HHH', data[offset:offset + 6])
                    target, _ = self.decode_name(data, offset + 6)
                    return {'port': port, 'target': target, 'priority': priority, 'weight': weight}, rdata_end
        
        except Exception:
            pass
        
        return None, rdata_end
    
    def parse_record(self, data: bytes, offset: int) -> Tuple[dict, int]:
        """Parse a DNS resource record."""
        name, offset = self.decode_name(data, offset)
        if offset + 10 > len(data):
            return None, offset
        
        rtype, rclass, ttl = struct.unpack('!HHI', data[offset:offset + 8])
        rdlength = struct.unpack('!H', data[offset + 8:offset + 10])[0]
        offset += 10
        
        rclass = rclass & 0x7FFF  # Remove cache flush bit
        
        rdata, offset = self.parse_rdata(data, offset, rtype, rdlength)
        
        return {
            'name': name,
            'type': rtype,
            'class': rclass,
            'ttl': ttl,
            'rdata': rdata
        }, offset
    
    def parse_response(self, data: bytes, addr: Tuple[str, int]):
        """Parse an mDNS response and extract discovered information."""
        try:
            if len(data) < 12:
                if self.debug:
                    print(f"[DEBUG] Packet too small: {len(data)} bytes")
                return
            
            # Parse header
            transaction_id, flags, qdcount, ancount, nscount, arcount = \
                struct.unpack('!HHHHHH', data[:12])
            
            if self.debug:
                is_query = (flags & 0x8000) == 0
                rcode = flags & 0x000F
                print(f"[DEBUG] Header: QD={qdcount}, AN={ancount}, NS={nscount}, AR={arcount}, Query={is_query}, RCODE={rcode}")
            
            # If no answers, authority, or additional records, skip
            if ancount == 0 and nscount == 0 and arcount == 0:
                if self.debug:
                    print(f"[DEBUG] No records in response")
                return
            
            # Process both queries and responses (some devices send unsolicited announcements as queries)
            offset = 12
            
            # Skip questions
            for _ in range(qdcount):
                if offset >= len(data):
                    break
                name, offset = self.decode_name(data, offset)
                if offset + 4 > len(data):
                    break
                offset += 4  # Skip type and class
            
            # Parse all records (answers + authority + additional)
            all_records = []
            total_records = ancount + nscount + arcount
            if self.debug and total_records > 0:
                print(f"[DEBUG] Parsing {total_records} records...")
            
            for i in range(total_records):
                if offset >= len(data):
                    if self.debug:
                        print(f"[DEBUG] Ran out of data at record {i}")
                    break
                try:
                    record, offset = self.parse_record(data, offset)
                    if record and record.get('rdata'):
                        all_records.append(record)
                        if self.debug:
                            print(f"[DEBUG] Parsed record {i+1}: {record}")
                except Exception as e:
                    if self.debug:
                        print(f"[DEBUG] Error parsing record {i}: {e}")
                    break
            
            # Process records to extract useful information
            for record in all_records:
                rtype = record['type']
                name = record['name']
                rdata = record['rdata']
                
                if self.debug:
                    print(f"[DEBUG] Record: type={rtype}, name={name}, rdata={rdata}")
                
                if rtype == 12:  # PTR record
                    # Service instance discovered
                    service_type = name
                    instance_name = rdata
                    if service_type not in self.services:
                        self.services[service_type] = set()
                    self.services[service_type].add(instance_name)
                
                elif rtype == 33:  # SRV record (service location)
                    # Extract service type from full service name
                    if isinstance(rdata, dict) and '._' in name:
                        # Extract service type (e.g., "_http._tcp.local" from "My Service._http._tcp.local")
                        parts = name.split('.', 1)
                        if len(parts) > 1:
                            service_type = parts[1]
                            instance_name = name
                            if service_type not in self.services:
                                self.services[service_type] = set()
                            self.services[service_type].add(instance_name)
                
                elif rtype == 1:  # A record
                    # Hostname to IP mapping
                    hostname = name
                    ip = rdata
                    if hostname not in self.hosts:
                        self.hosts[hostname] = set()
                    self.hosts[hostname].add(ip)
                
                elif rtype == 28:  # AAAA record
                    # IPv6 address
                    hostname = name
                    ipv6 = rdata
                    if hostname not in self.hosts:
                        self.hosts[hostname] = set()
                    self.hosts[hostname].add(f"[{ipv6}]")
                
                elif rtype == 33:  # SRV record
                    # Service details
                    if isinstance(rdata, dict):
                        if name not in self.service_details:
                            self.service_details[name] = {}
                        self.service_details[name].update({
                            'host': rdata['target'],
                            'port': rdata['port'],
                            'priority': rdata['priority'],
                            'weight': rdata['weight']
                        })
                
                elif rtype == 16:  # TXT record
                    # Service metadata
                    if isinstance(rdata, list):
                        if name not in self.service_details:
                            self.service_details[name] = {}
                        self.service_details[name]['txt'] = rdata
        
        except Exception as e:
            pass  # Silently ignore malformed packets
    
    def send_query(self, qname: str, qtype: int):
        """Send an mDNS query."""
        try:
            # Build query packet
            header = struct.pack('!HHHHHH', 0, 0x0000, 1, 0, 0, 0)
            question = self.encode_dns_name(qname)
            question += struct.pack('!HH', qtype, CLASS_IN)
            packet = header + question
            
            # Send the query
            self.sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
        except Exception as e:
            print(f"[ERROR] Failed to send query for {qname}: {e}")
    
    def discover(self):
        """Run the discovery process."""
        try:
            # Create socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Allow multiple listeners
            if hasattr(socket, 'SO_REUSEPORT'):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            
            # Bind to mDNS port on all interfaces
            self.sock.bind(('', MDNS_PORT))
            
            # Join multicast group on ALL interfaces
            # This ensures we listen on WiFi, not just Docker
            mreq = struct.pack('4s4s', socket.inet_aton(MDNS_ADDR), socket.inet_aton('0.0.0.0'))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            # Also try to add membership on specific local network interfaces
            try:
                # Get local IP addresses and try to join on each
                import socket as sock_module
                hostname = sock_module.gethostname()
                local_ips = sock_module.gethostbyname_ex(hostname)[2]
                for ip in local_ips:
                    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                        try:
                            mreq_specific = struct.pack('4s4s', socket.inet_aton(MDNS_ADDR), socket.inet_aton(ip))
                            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq_specific)
                            if self.debug:
                                print(f"[DEBUG] Joined multicast group on interface {ip}")
                        except:
                            pass
            except:
                pass
            
            # Set multicast TTL
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            
            # Set multicast interface to use (prefer non-Docker IPs)
            try:
                import socket as sock_module
                hostname = sock_module.gethostname()
                local_ips = sock_module.gethostbyname_ex(hostname)[2]
                # Prefer 192.168.x.x addresses (typical home network)
                preferred_ip = None
                for ip in local_ips:
                    if ip.startswith('192.168.'):
                        preferred_ip = ip
                        break
                if not preferred_ip:
                    for ip in local_ips:
                        if not ip.startswith('172.') and not ip.startswith('127.'):
                            preferred_ip = ip
                            break
                
                if preferred_ip:
                    self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, 
                                        socket.inet_aton(preferred_ip))
                    if self.debug:
                        print(f"[DEBUG] Sending multicast from interface {preferred_ip}")
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] Could not set multicast interface: {e}")
            
            # Set socket timeout
            self.sock.settimeout(0.1)
            
            self.running = True
            
            print(f"\n{'='*70}")
            print(f"Network Discovery Started")
            print(f"{'='*70}")
            print(f"Querying for devices and services...")
            print(f"Timeout: {self.timeout} seconds\n")
            
            # Send queries for common services
            services_to_query = COMMON_SERVICES + self.custom_services
            
            for service in services_to_query:
                self.send_query(service, TYPE_PTR)
                time.sleep(0.05)  # Small delay between queries
            
            # Listen for responses
            start_time = time.time()
            response_count = 0
            
            while self.running and (time.time() - start_time) < self.timeout:
                try:
                    data, addr = self.sock.recvfrom(9000)
                    if self.debug:
                        print(f"[DEBUG] Received {len(data)} bytes from {addr[0]}")
                    self.parse_response(data, addr)
                    response_count += 1
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.debug:
                        print(f"[DEBUG] Error receiving: {e}")
            
            print(f"Received {response_count} responses")
            print(f"\n{'='*70}")
            
        except PermissionError:
            print("\n[ERROR] Permission denied. Try running with administrator/root privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"\n[ERROR] Discovery failed: {e}")
            sys.exit(1)
        finally:
            if self.sock:
                self.sock.close()
    
    def display_results(self, verbose: bool = False):
        """Display discovered devices and services."""
        print(f"\n{'='*70}")
        print(f"DISCOVERY RESULTS")
        print(f"{'='*70}\n")
        
        # Display discovered hosts
        if self.hosts:
            print(f"📱 DISCOVERED HOSTS ({len(self.hosts)})")
            print(f"{'-'*70}")
            for hostname in sorted(self.hosts.keys()):
                ips = ', '.join(sorted(self.hosts[hostname]))
                print(f"  {hostname}")
                print(f"    IP: {ips}")
            print()
        else:
            print(f"📱 No hosts discovered\n")
        
        # Display discovered services by type
        if self.services:
            print(f"🔧 DISCOVERED SERVICES ({len(self.services)} types)")
            print(f"{'-'*70}")
            for service_type in sorted(self.services.keys()):
                instances = self.services[service_type]
                print(f"\n  {service_type} ({len(instances)} instance(s))")
                
                for instance in sorted(instances):
                    print(f"    • {instance}")
                    
                    # Show details if available
                    if instance in self.service_details:
                        details = self.service_details[instance]
                        if 'host' in details and 'port' in details:
                            host = details['host']
                            port = details['port']
                            
                            # Try to get IP for the host
                            ip_str = ""
                            if host in self.hosts:
                                ips = list(self.hosts[host])
                                if ips:
                                    ip_str = f" ({ips[0]})"
                            
                            print(f"      Location: {host}:{port}{ip_str}")
                        
                        if verbose and 'txt' in details:
                            txt_records = details['txt']
                            if txt_records:
                                print(f"      Metadata: {', '.join(txt_records)}")
            print()
        else:
            print(f"🔧 No services discovered\n")
        
        # Summary
        total_hosts = len(self.hosts)
        total_service_types = len(self.services)
        total_service_instances = sum(len(instances) for instances in self.services.values())
        
        print(f"{'='*70}")
        print(f"SUMMARY")
        print(f"{'='*70}")
        print(f"  Hosts: {total_hosts}")
        print(f"  Service Types: {total_service_types}")
        print(f"  Service Instances: {total_service_instances}")
        print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Network Discovery - Discover all mDNS devices and services',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Basic discovery (3 second timeout):
    python discover_all.py
  
  Quick scan (1 second):
    python discover_all.py --timeout 1
  
  Thorough scan (10 seconds):
    python discover_all.py --timeout 10
  
  Discovery with verbose details:
    python discover_all.py --verbose
  
  Add custom service types:
    python discover_all.py --service _myapp._tcp.local --service _custom._udp.local
        ''')
    
    parser.add_argument('-t', '--timeout', type=int, default=3,
                       help='Timeout in seconds (default: 3)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show verbose output including TXT records')
    parser.add_argument('-s', '--service', action='append',
                       help='Additional service type to query (can be specified multiple times)')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Show debug output for troubleshooting')
    
    args = parser.parse_args()
    
    discovery = NetworkDiscovery(timeout=args.timeout, custom_services=args.service or [], debug=args.debug)
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        discovery.running = False
        print("\n\n[INTERRUPTED] Discovery stopped by user")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Run discovery
    discovery.discover()
    
    # Display results
    discovery.display_results(verbose=args.verbose)


if __name__ == '__main__':
    main()
