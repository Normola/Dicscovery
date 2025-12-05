#!/usr/bin/env python3
"""
Network OS Detection Scanner

Uses nmap to perform OS detection and service identification on the local network.
This complements mDNS discovery by providing deeper host information.
"""

import subprocess
import sys
import argparse
import json
import re
from typing import Dict, List


def check_nmap_installed() -> bool:
    """Check if nmap is installed and accessible."""
    try:
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_network_range() -> str:
    """
    Detect the local network range from active network interfaces.
    Returns CIDR notation like 192.168.0.0/24
    """
    try:
        # Use ipconfig on Windows
        result = subprocess.run(['ipconfig'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        
        # Look for IPv4 addresses in 192.168.x.x or 10.x.x.x range
        lines = result.stdout.split('\n')
        for line in lines:
            if 'IPv4 Address' in line:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    # Check if it's a private network
                    if ip.startswith('192.168.') or ip.startswith('10.'):
                        # Convert to /24 network
                        parts = ip.split('.')
                        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                        return network
        
        # Default fallback
        return "192.168.0.0/24"
    
    except Exception as e:
        print(f"[WARNING] Could not auto-detect network: {e}")
        return "192.168.0.0/24"


def run_nmap_scan(target: str, scan_type: str = 'quick', sudo: bool = False) -> str:
    """
    Run nmap scan with specified options.
    
    Args:
        target: IP address or CIDR range to scan
        scan_type: 'quick', 'full', 'os', or 'vuln'
        sudo: Whether to run with elevated privileges (needed for OS detection)
    
    Returns:
        nmap output as string
    """
    
    # Build nmap command based on scan type
    if scan_type == 'quick':
        # Quick scan: just find live hosts and open ports
        cmd = ['nmap', '-sn', target]  # Ping scan
        
    elif scan_type == 'full':
        # Full scan: all ports, service detection
        cmd = ['nmap', '-sV', '-T4', target]
        
    elif scan_type == 'os':
        # OS detection scan (requires admin/sudo)
        cmd = ['nmap', '-O', '-sV', '--osscan-guess', '-T4', target]
        
    elif scan_type == 'vuln':
        # Vulnerability scan
        cmd = ['nmap', '-sV', '--script=vuln', '-T4', target]
    
    else:
        print(f"[ERROR] Unknown scan type: {scan_type}")
        return ""
    
    # Add sudo/admin elevation if needed
    if sudo and scan_type in ['os', 'vuln']:
        print("[INFO] OS detection requires administrator privileges")
        print("[INFO] Please run PowerShell as Administrator for full OS detection")
    
    print(f"\n[RUNNING] {' '.join(cmd)}")
    print(f"[INFO] This may take a few minutes...\n")
    
    try:
        result = subprocess.run(cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=300)  # 5 minute timeout
        
        if result.returncode != 0:
            print(f"[ERROR] nmap failed with code {result.returncode}")
            if result.stderr:
                print(f"Error: {result.stderr}")
            return ""
        
        return result.stdout
    
    except subprocess.TimeoutExpired:
        print("[ERROR] Scan timed out after 5 minutes")
        return ""
    except Exception as e:
        print(f"[ERROR] Failed to run nmap: {e}")
        return ""


def parse_nmap_output(output: str) -> List[Dict]:
    """
    Parse nmap output and extract host information.
    Returns list of discovered hosts with their details.
    """
    hosts = []
    current_host = None
    
    lines = output.split('\n')
    for line in lines:
        line = line.strip()
        
        # Host line: "Nmap scan report for 192.168.0.1"
        if line.startswith('Nmap scan report for'):
            if current_host:
                hosts.append(current_host)
            
            # Extract IP and hostname
            match = re.search(r'for (.+?)(?:\s+\((\d+\.\d+\.\d+\.\d+)\))?$', line)
            if match:
                host_or_ip = match.group(1)
                ip = match.group(2) if match.group(2) else host_or_ip
                hostname = host_or_ip if match.group(2) else None
                
                current_host = {
                    'ip': ip,
                    'hostname': hostname,
                    'status': 'unknown',
                    'os': None,
                    'ports': [],
                    'services': []
                }
        
        # Status line: "Host is up"
        elif 'Host is up' in line:
            if current_host:
                current_host['status'] = 'up'
                # Extract latency if present
                match = re.search(r'\((.+?)\s+latency\)', line)
                if match:
                    current_host['latency'] = match.group(1)
        
        # MAC Address line
        elif 'MAC Address:' in line:
            if current_host:
                match = re.search(r'MAC Address:\s+([0-9A-F:]+)\s+\((.+?)\)', line)
                if match:
                    current_host['mac'] = match.group(1)
                    current_host['vendor'] = match.group(2)
        
        # OS detection line
        elif line.startswith('Running:') or line.startswith('OS details:'):
            if current_host:
                current_host['os'] = line.split(':', 1)[1].strip()
        
        # Port line: "22/tcp open ssh"
        elif '/tcp' in line or '/udp' in line:
            if current_host:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    current_host['ports'].append({
                        'port': port_proto,
                        'state': state,
                        'service': service
                    })
    
    # Add last host
    if current_host:
        hosts.append(current_host)
    
    return hosts


def display_results(hosts: List[Dict], verbose: bool = False):
    """Display scan results in a formatted way."""
    
    if not hosts:
        print("\n[RESULT] No hosts discovered")
        return
    
    print(f"\n{'='*70}")
    print(f"NETWORK SCAN RESULTS")
    print(f"{'='*70}\n")
    
    print(f"📡 DISCOVERED HOSTS ({len(hosts)})\n")
    
    for i, host in enumerate(hosts, 1):
        print(f"{'-'*70}")
        print(f"Host #{i}: {host['ip']}")
        
        if host.get('hostname'):
            print(f"  Hostname: {host['hostname']}")
        
        print(f"  Status: {host['status'].upper()}")
        
        if host.get('latency'):
            print(f"  Latency: {host['latency']}")
        
        if host.get('mac'):
            print(f"  MAC: {host['mac']}")
            if host.get('vendor'):
                print(f"  Vendor: {host['vendor']}")
        
        if host.get('os'):
            print(f"  OS: {host['os']}")
        
        if verbose and host.get('ports'):
            print(f"  Open Ports ({len(host['ports'])}):")
            for port in host['ports']:
                print(f"    • {port['port']} - {port['state']} - {port['service']}")
        elif host.get('ports'):
            print(f"  Open Ports: {len(host['ports'])} found")
        
        print()
    
    print(f"{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Total Hosts: {len(hosts)}")
    live_hosts = sum(1 for h in hosts if h['status'] == 'up')
    print(f"  Live Hosts: {live_hosts}")
    hosts_with_os = sum(1 for h in hosts if h.get('os'))
    print(f"  OS Detected: {hosts_with_os}")
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Network OS Detection Scanner using nmap',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Quick host discovery on auto-detected network:
    python nmap_scan.py
  
  Quick scan on specific network:
    python nmap_scan.py --target 192.168.1.0/24
  
  Full port and service scan:
    python nmap_scan.py --scan full
  
  OS detection (requires admin):
    python nmap_scan.py --scan os
  
  Scan specific host:
    python nmap_scan.py --target 192.168.0.1
  
  Verbose output:
    python nmap_scan.py --scan full --verbose

Note: OS detection requires running PowerShell as Administrator
        ''')
    
    parser.add_argument('-t', '--target', 
                       help='Target IP or CIDR range (auto-detected if not specified)')
    parser.add_argument('-s', '--scan', 
                       choices=['quick', 'full', 'os', 'vuln'],
                       default='quick',
                       help='Scan type (default: quick)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show verbose output including all ports')
    parser.add_argument('--raw', action='store_true',
                       help='Show raw nmap output instead of parsed results')
    
    args = parser.parse_args()
    
    # Check if nmap is installed
    if not check_nmap_installed():
        print("\n[ERROR] nmap is not installed or not in PATH")
        print("\nTo install nmap on Windows:")
        print("  1. Download from: https://nmap.org/download.html")
        print("  2. Run the installer")
        print("  3. Restart PowerShell")
        print("\nOr install via Chocolatey:")
        print("  choco install nmap")
        sys.exit(1)
    
    # Determine target
    if args.target:
        target = args.target
    else:
        target = get_network_range()
        print(f"[INFO] Auto-detected network: {target}")
    
    # Run scan
    output = run_nmap_scan(target, args.scan, sudo=False)
    
    if not output:
        print("[ERROR] No scan results")
        sys.exit(1)
    
    # Display results
    if args.raw:
        print("\n" + output)
    else:
        hosts = parse_nmap_output(output)
        display_results(hosts, verbose=args.verbose)
        
        # Save to file
        if hosts:
            filename = f"scan_results_{target.replace('/', '_')}.txt"
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"[SAVED] Full scan results saved to: {filename}")
            except Exception as e:
                print(f"[WARNING] Could not save results: {e}")


if __name__ == '__main__':
    main()
