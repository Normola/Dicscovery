#!/usr/bin/env python3
"""
mDNS Network Database

Continuously monitors mDNS traffic and maintains a persistent database of all
discovered devices and services. Updates in real-time as devices come and go.
"""

import socket
import struct
import sys
import signal
import argparse
import json
import time
from datetime import datetime
from typing import Dict, Set, Tuple, Optional
from pathlib import Path


# mDNS Constants
MDNS_ADDR = '224.0.0.251'
MDNS_PORT = 5353

# DNS Record Types
TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33


class NetworkDatabase:
    """Maintains a database of discovered network hosts and services."""
    
    def __init__(self, db_file: str = "network_db.json", auto_save_interval: int = 30):
        self.db_file = Path(db_file)
        self.auto_save_interval = auto_save_interval
        self.last_save_time = time.time()
        
        # Database structure
        self.hosts = {}  # hostname -> {ips: set, last_seen: timestamp, first_seen: timestamp}
        self.services = {}  # service_type -> {instances: {name -> details}}
        self.service_to_host = {}  # service_instance_name -> hostname
        
        # Statistics
        self.stats = {
            'packets_received': 0,
            'records_processed': 0,
            'hosts_discovered': 0,
            'services_discovered': 0,
            'started_at': datetime.now().isoformat(),
            'last_activity': None
        }
        
        # Load existing database if it exists
        self.load_database()
    
    def load_database(self):
        """Load existing database from file."""
        if not self.db_file.exists():
            print(f"[INFO] No existing database found, starting fresh")
            return
        
        try:
            with open(self.db_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Convert sets back from lists
            for hostname, host_data in data.get('hosts', {}).items():
                self.hosts[hostname] = {
                    'ips': set(host_data.get('ips', [])),
                    'first_seen': host_data.get('first_seen'),
                    'last_seen': host_data.get('last_seen'),
                    'seen_count': host_data.get('seen_count', 1)
                }
            
            self.services = data.get('services', {})
            self.service_to_host = data.get('service_to_host', {})
            self.stats = data.get('stats', self.stats)
            
            print(f"[LOADED] Database with {len(self.hosts)} hosts and {len(self.services)} service types")
        
        except Exception as e:
            print(f"[ERROR] Failed to load database: {e}")
            print(f"[INFO] Starting with fresh database")
    
    def save_database(self):
        """Save database to file."""
        try:
            # Convert sets to lists for JSON serialization
            data = {
                'hosts': {
                    hostname: {
                        'ips': list(host_data['ips']),
                        'first_seen': host_data['first_seen'],
                        'last_seen': host_data['last_seen'],
                        'seen_count': host_data.get('seen_count', 1)
                    }
                    for hostname, host_data in self.hosts.items()
                },
                'services': self.services,
                'service_to_host': self.service_to_host,
                'stats': self.stats
            }
            
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            self.last_save_time = time.time()
            print(f"[SAVED] Database to {self.db_file}")
        
        except Exception as e:
            print(f"[ERROR] Failed to save database: {e}")
    
    def auto_save_if_needed(self):
        """Save database if enough time has passed."""
        if time.time() - self.last_save_time >= self.auto_save_interval:
            self.save_database()
    
    def add_host(self, hostname: str, ip: str):
        """Add or update a host in the database."""
        now = datetime.now().isoformat()
        
        # Don't add if both hostname and IP are invalid
        if not hostname or hostname == 'unknown':
            return
        
        if hostname not in self.hosts:
            self.hosts[hostname] = {
                'ips': {ip} if ip != 'unknown' else set(),
                'first_seen': now,
                'last_seen': now,
                'seen_count': 1
            }
            self.stats['hosts_discovered'] += 1
            if ip != 'unknown':
                print(f"[NEW HOST] {hostname} ({ip})")
            else:
                print(f"[NEW HOST] {hostname} (IP pending)")
        else:
            host_data = self.hosts[hostname]
            if ip != 'unknown' and ip not in host_data['ips']:
                host_data['ips'].add(ip)
                print(f"[UPDATE] {hostname} added IP: {ip}")
            host_data['last_seen'] = now
            host_data['seen_count'] = host_data.get('seen_count', 1) + 1
        
        self.stats['last_activity'] = now
    
    def add_service(self, service_type: str, instance_name: str, 
                   hostname: Optional[str] = None, port: Optional[int] = None,
                   txt_records: Optional[list] = None):
        """Add or update a service in the database."""
        now = datetime.now().isoformat()
        
        if service_type not in self.services:
            self.services[service_type] = {'instances': {}}
        
        if instance_name not in self.services[service_type]['instances']:
            self.services[service_type]['instances'][instance_name] = {
                'first_seen': now,
                'last_seen': now,
                'seen_count': 1
            }
            self.stats['services_discovered'] += 1
            print(f"[NEW SERVICE] {instance_name}")
        else:
            instance_data = self.services[service_type]['instances'][instance_name]
            instance_data['last_seen'] = now
            instance_data['seen_count'] = instance_data.get('seen_count', 1) + 1
        
        instance_data = self.services[service_type]['instances'][instance_name]
        
        # Update details
        if hostname:
            instance_data['hostname'] = hostname
            self.service_to_host[instance_name] = hostname
        if port:
            instance_data['port'] = port
        if txt_records:
            instance_data['txt'] = txt_records
        
        self.stats['last_activity'] = now
    
    def display_status(self, show_all: bool = False):
        """Display current database status."""
        print(f"\n{'='*70}")
        print(f"NETWORK DATABASE STATUS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}")
        print(f"Packets: {self.stats['packets_received']} | Records: {self.stats['records_processed']}")
        print(f"Running since: {self.stats['started_at']}")
        print(f"{'='*70}\n")
        
        # Display hosts
        print(f"DISCOVERED HOSTS ({len(self.hosts)})")
        print(f"{'-'*70}")
        
        # Sort hosts by last seen
        sorted_hosts = sorted(
            self.hosts.items(), 
            key=lambda x: x[1]['last_seen'], 
            reverse=True
        )
        
        display_limit = None if show_all else 10
        for hostname, data in sorted_hosts[:display_limit]:
            ips = ', '.join(sorted(data['ips']))
            last_seen = data['last_seen'].split('T')[1][:8] if 'T' in data['last_seen'] else data['last_seen']
            count = data.get('seen_count', 1)
            print(f"  {hostname}")
            print(f"    IPs: {ips} | Last seen: {last_seen} | Count: {count}")
        
        if not show_all and len(self.hosts) > 10:
            print(f"  ... and {len(self.hosts) - 10} more (use --show-all to see all)")
        print()
        
        # Display services
        print(f"DISCOVERED SERVICES ({len(self.services)} types)")
        print(f"{'-'*70}")
        
        for service_type in sorted(self.services.keys()):
            instances = self.services[service_type]['instances']
            print(f"\n  {service_type} ({len(instances)} instance(s))")
            
            display_instances = list(instances.items())[:5] if not show_all else list(instances.items())
            
            for instance_name, instance_data in display_instances:
                last_seen = instance_data['last_seen'].split('T')[1][:8] if 'T' in instance_data['last_seen'] else instance_data['last_seen']
                print(f"    • {instance_name}")
                
                if 'hostname' in instance_data and 'port' in instance_data:
                    hostname = instance_data['hostname']
                    port = instance_data['port']
                    
                    # Get IP if available
                    ip_str = ""
                    if hostname in self.hosts:
                        ips = list(self.hosts[hostname]['ips'])
                        if ips:
                            ip_str = f" ({ips[0]})"
                    
                    print(f"      Location: {hostname}:{port}{ip_str}")
                
                if 'txt' in instance_data:
                    txt = instance_data['txt']
                    if txt:
                        print(f"      TXT: {', '.join(txt)}")
                
                print(f"      Last seen: {last_seen}")
            
            if not show_all and len(instances) > 5:
                print(f"    ... and {len(instances) - 5} more instances")
        
        print(f"\n{'='*70}\n")


class MDNSMonitorDB:
    """Monitor mDNS traffic and update database."""
    
    def __init__(self, database: NetworkDatabase, verbose: bool = False, active_mode: bool = False, query_interval: int = 300, interface: str = '0.0.0.0'):
        self.database = database
        self.verbose = verbose
        self.active_mode = active_mode
        self.query_interval = query_interval
        self.interface = interface
        self.running = False
        self.sock = None
        
        # Common services to query in active mode
        self.query_services = [
            '_services._dns-sd._udp.local',
            '_http._tcp.local',
            '_https._tcp.local',
            '_ssh._tcp.local',
            '_smb._tcp.local',
            '_printer._tcp.local',
            '_ipp._tcp.local',
            '_airplay._tcp.local',
            '_googlecast._tcp.local',
            '_spotify-connect._tcp.local',
            '_workstation._tcp.local',
        ]
    
    def decode_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Decode a DNS name from wire format."""
        labels = []
        jumped = False
        jumps = 0
        max_jumps = 20
        original_offset = offset
        
        while True:
            if jumps > max_jumps or offset >= len(data):
                break
            
            length = data[offset]
            
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
            
            if length == 0:
                offset += 1
                break
            
            offset += 1
            if offset + length > len(data):
                break
            label = data[offset:offset + length].decode('utf-8', errors='ignore')
            labels.append(label)
            offset += length
        
        return '.'.join(labels), original_offset if jumped else offset
    
    def parse_rdata(self, data: bytes, offset: int, rtype: int, rdlength: int):
        """Parse resource record data."""
        rdata_end = offset + rdlength
        
        if rdata_end > len(data):
            return None, offset + rdlength
        
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
                    return {'port': port, 'target': target}, rdata_end
        
        except Exception:
            pass
        
        return None, rdata_end
    
    def encode_dns_name(self, name: str) -> bytes:
        """Encode a domain name into DNS wire format."""
        encoded = b''
        for label in name.split('.'):
            if label:
                encoded += bytes([len(label)]) + label.encode('utf-8')
        encoded += b'\x00'
        return encoded
    
    def send_query(self, qname: str, qtype: int = TYPE_PTR):
        """Send an mDNS query."""
        try:
            # Build query packet
            header = struct.pack('!HHHHHH', 0, 0x0000, 1, 0, 0, 0)
            question = self.encode_dns_name(qname)
            question += struct.pack('!HH', qtype, 1)  # CLASS_IN
            packet = header + question
            
            # Send the query
            self.sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
            
            if self.verbose:
                print(f"[QUERY] Sent query for {qname}")
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Failed to send query: {e}")
    
    def send_periodic_queries(self):
        """Send queries for common services periodically."""
        while self.running:
            for service in self.query_services:
                if not self.running:
                    break
                self.send_query(service)
                time.sleep(0.1)  # Small delay between queries
            
            # Wait before next query cycle
            for _ in range(self.query_interval):
                if not self.running:
                    break
                time.sleep(1)
    
    def parse_record(self, data: bytes, offset: int):
        """Parse a DNS resource record."""
        name, offset = self.decode_name(data, offset)
        if offset + 10 > len(data):
            return None, offset
        
        rtype, rclass, ttl = struct.unpack('!HHI', data[offset:offset + 8])
        rdlength = struct.unpack('!H', data[offset + 8:offset + 10])[0]
        offset += 10
        
        rclass = rclass & 0x7FFF
        
        rdata, offset = self.parse_rdata(data, offset, rtype, rdlength)
        
        return {
            'name': name,
            'type': rtype,
            'ttl': ttl,
            'rdata': rdata
        }, offset
    
    def process_packet(self, data: bytes, addr: Tuple[str, int]):
        """Process an mDNS packet and update database."""
        try:
            if len(data) < 12:
                return
            
            self.database.stats['packets_received'] += 1
            
            # Parse header
            transaction_id, flags, qdcount, ancount, nscount, arcount = \
                struct.unpack('!HHHHHH', data[:12])
            
            offset = 12
            
            # Skip questions
            for _ in range(qdcount):
                if offset >= len(data):
                    break
                name, offset = self.decode_name(data, offset)
                if offset + 4 > len(data):
                    break
                offset += 4
            
            # Parse all records
            total_records = ancount + nscount + arcount
            if total_records == 0:
                return
            
            records = []
            for _ in range(total_records):
                if offset >= len(data):
                    break
                try:
                    record, offset = self.parse_record(data, offset)
                    if record and record.get('rdata'):
                        records.append(record)
                        self.database.stats['records_processed'] += 1
                except Exception:
                    break
            
            # Process records and update database
            for record in records:
                rtype = record['type']
                name = record['name']
                rdata = record['rdata']
                
                if self.verbose:
                    print(f"[RECORD] Type={rtype}, Name={name}, Data={rdata}")
                
                if rtype == 1:  # A record
                    if rdata and isinstance(rdata, str):
                        self.database.add_host(name, rdata)
                
                elif rtype == 28:  # AAAA record
                    if rdata and isinstance(rdata, str):
                        self.database.add_host(name, f"[{rdata}]")
                
                elif rtype == 12:  # PTR record
                    if rdata and isinstance(rdata, str):
                        # Extract service type
                        service_type = name
                        instance_name = rdata
                        self.database.add_service(service_type, instance_name)
                
                elif rtype == 33:  # SRV record
                    if isinstance(rdata, dict) and rdata.get('target') and rdata.get('port'):
                        # Also add the target hostname
                        target_hostname = rdata['target']
                        if target_hostname and not target_hostname.startswith('_'):
                            # Try to get IP from addr or leave for later
                            self.database.add_host(target_hostname, 'unknown')
                        
                        # Extract service type from name
                        if '._' in name:
                            parts = name.split('.', 1)
                            if len(parts) > 1:
                                service_type = parts[1]
                                instance_name = name
                                self.database.add_service(
                                    service_type, instance_name,
                                    hostname=rdata['target'],
                                    port=rdata['port']
                                )
                
                elif rtype == 16:  # TXT record
                    if isinstance(rdata, list) and '._' in name:
                        parts = name.split('.', 1)
                        if len(parts) > 1:
                            service_type = parts[1]
                            instance_name = name
                            self.database.add_service(
                                service_type, instance_name,
                                txt_records=rdata
                            )
            
            # Auto-save periodically
            self.database.auto_save_if_needed()
        
        except Exception as e:
            if self.verbose:
                print(f"[ERROR] Error processing packet: {e}")
    
    def start(self, update_interval: int = 60):
        """Start monitoring mDNS traffic."""
        try:
            # Create socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            if hasattr(socket, 'SO_REUSEPORT'):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            
            self.sock.bind((self.interface, MDNS_PORT))
            
            # Join multicast group
            interface_ip = self.interface if self.interface != '0.0.0.0' else '0.0.0.0'
            mreq = struct.pack('4s4s', socket.inet_aton(MDNS_ADDR), socket.inet_aton(interface_ip))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            self.sock.settimeout(1.0)
            
            self.running = True
            
            print(f"\n{'='*70}")
            print(f"mDNS Network Database Monitor Started")
            print(f"{'='*70}")
            print(f"Database file: {self.database.db_file}")
            print(f"Auto-save interval: {self.database.auto_save_interval}s")
            print(f"Status update interval: {update_interval}s")
            print(f"Network interface: {self.interface}")
            print(f"Active mode: {'Enabled (sending queries)' if self.active_mode else 'Disabled (passive only)'}")
            print(f"Press Ctrl+C to stop\n")
            
            # Start query thread if in active mode
            if self.active_mode:
                import threading
                query_thread = threading.Thread(target=self.send_periodic_queries, daemon=True)
                query_thread.start()
                interval_str = f"{self.query_interval} seconds" if self.query_interval < 60 else f"{self.query_interval // 60} minutes"
                print(f"[ACTIVE MODE] Sending discovery queries every {interval_str}...\n")
            
            last_status_update = time.time()
            
            # Main loop
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(9000)
                    self.process_packet(data, addr)
                except socket.timeout:
                    # Check for auto-save even when no packets received
                    self.database.auto_save_if_needed()
                except Exception as e:
                    if self.verbose:
                        print(f"[ERROR] {e}")
                
                # Periodic status update and force save check
                if time.time() - last_status_update >= update_interval:
                    self.database.display_status()
                    self.database.auto_save_if_needed()  # Force check on status update
                    last_status_update = time.time()
        
        except PermissionError:
            print("\n[ERROR] Permission denied. Try running with administrator privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"\n[ERROR] Failed to start monitor: {e}")
            sys.exit(1)
        finally:
            if self.sock:
                self.sock.close()
    
    def stop(self):
        """Stop monitoring and save database."""
        print("\n[STOPPING] Shutting down monitor...")
        self.running = False
        self.database.save_database()
        self.database.display_status(show_all=True)
        print("[STOPPED] Database saved and monitor stopped.\n")


def main():
    parser = argparse.ArgumentParser(
        description='mDNS Network Database - Continuous network monitoring with persistent storage',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Start monitoring with default settings:
    python network_db.py
  
  Use custom database file:
    python network_db.py --db my_network.json
  
  Show status updates every 30 seconds:
    python network_db.py --update-interval 30
  
  Auto-save every minute:
    python network_db.py --save-interval 60
  
  Verbose mode:
    python network_db.py --verbose
  
  Show all devices (not just recent 10):
    python network_db.py --show-all
  
  Active mode (send queries):
    python network_db.py --active --query-interval 30
        ''')
    
    parser.add_argument('--db', default='network_db.json',
                       help='Database file path (default: network_db.json)')
    parser.add_argument('--save-interval', type=int, default=30,
                       help='Auto-save interval in seconds (default: 30)')
    parser.add_argument('--update-interval', type=int, default=60,
                       help='Status display interval in seconds (default: 60)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show verbose debug output')
    parser.add_argument('--show-all', action='store_true',
                       help='Show all devices in status updates')
    parser.add_argument('-a', '--active', action='store_true',
                       help='Active mode: send periodic queries to discover devices (default: passive listening only)')
    parser.add_argument('--query-interval', type=int, default=300,
                       help='Query interval in seconds for active mode (default: 300 = 5 minutes)')
    parser.add_argument('--interface', default='0.0.0.0',
                       help='Network interface IP to bind to (default: 0.0.0.0 = all interfaces)')
    
    args = parser.parse_args()
    
    # Create database
    database = NetworkDatabase(db_file=args.db, auto_save_interval=args.save_interval)
    
    # Create monitor
    monitor = MDNSMonitorDB(database=database, verbose=args.verbose, active_mode=args.active, query_interval=args.query_interval, interface=args.interface)
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        monitor.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    monitor.start(update_interval=args.update_interval)


if __name__ == '__main__':
    main()
