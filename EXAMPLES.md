# mDNS/DNS-SD Learning Examples

This file contains practical examples and experiments you can run to learn how mDNS and DNS-SD work.

## Getting Started

All tools are standalone Python scripts with no external dependencies. They work with Python 3.6+.

```powershell
# Verify Python version
python --version
```

## Tool 1: mDNS Monitor (mdns_monitor.py)

The monitor tool lets you see all mDNS traffic on your network in real-time.

### Basic Usage

```powershell
# Monitor all mDNS traffic (start this first!)
python mdns_monitor.py

# Monitor with verbose output (shows additional records)
python mdns_monitor.py --verbose

# Monitor only queries
python mdns_monitor.py --filter query

# Monitor only responses
python mdns_monitor.py --filter response
```

### Learning Exercise 1: Discover Your Network

1. Start the monitor:
   ```powershell
   python mdns_monitor.py --verbose
   ```

2. Open another terminal and run queries (see examples below)

3. Watch the monitor to see:
   - How queries are formatted
   - How responses are sent
   - What services are on your network

## Tool 2: mDNS Broadcaster (mdns_broadcaster.py)

This tool sends various types of mDNS messages.

### Query Operations

```powershell
# Query for a specific hostname (A record)
python mdns_broadcaster.py query mydevice.local

# Query for a hostname with unicast response
python mdns_broadcaster.py query mydevice.local --unicast

# Query for any record type
python mdns_broadcaster.py query mydevice.local --type ANY

# Browse for HTTP services on the network
python mdns_broadcaster.py browse _http._tcp.local

# Browse for other common services
python mdns_broadcaster.py browse _ssh._tcp.local
python mdns_broadcaster.py browse _printer._tcp.local
python mdns_broadcaster.py browse _airplay._tcp.local
python mdns_broadcaster.py browse _googlecast._tcp.local
```

### Announcement Operations

```powershell
# Announce a hostname with IP address
python mdns_broadcaster.py announce myhost.local 192.168.1.100

# Announce with custom TTL (time-to-live)
python mdns_broadcaster.py announce myhost.local 192.168.1.100 --ttl 300

# Announce a complete service
python mdns_broadcaster.py service "My Web Server" _http._tcp.local myhost.local 8080 192.168.1.100

# Announce a service with metadata (TXT records)
python mdns_broadcaster.py service "My API" _api._tcp.local myhost.local 3000 192.168.1.100 --txt version=1.0 --txt env=dev
```

### Probe Operations

Probing checks if a hostname is already taken before claiming it.

```powershell
# Probe for name conflicts (sends 3 probe queries)
python mdns_broadcaster.py probe testdevice.local 192.168.1.50

# The proper mDNS sequence:
# 1. Probe for the name
python mdns_broadcaster.py probe myhost.local 192.168.1.100

# 2. If no conflict, announce it
python mdns_broadcaster.py announce myhost.local 192.168.1.100
```

### Goodbye Operations

```powershell
# Send goodbye packet (TTL=0) to remove a hostname
python mdns_broadcaster.py goodbye myhost.local 192.168.1.100
```

## Tool 3: DNS-SD Service Advertiser (dnssd_advertiser.py)

This tool runs continuously and advertises a service, responding to queries.

### Basic Service Advertisement

```powershell
# Advertise a web server
python dnssd_advertiser.py --service "My Web Server" --type _http._tcp.local --port 8080 --hostname webserver.local --ip 192.168.1.100

# Short form (using aliases)
python dnssd_advertiser.py -s "My Web Server" -t _http._tcp.local -p 8080 -H webserver.local -i 192.168.1.100
```

### Service Advertisement with Metadata

```powershell
# Advertise SSH server with version info
python dnssd_advertiser.py -s "Dev Server SSH" -t _ssh._tcp.local -p 22 -H devbox.local -i 192.168.1.50 --txt version=1.0 --txt os=linux

# Advertise API with multiple TXT records
python dnssd_advertiser.py -s "My REST API" -t _http._tcp.local -p 3000 -H api.local -i 192.168.1.200 --txt path=/api/v1 --txt version=2.0 --txt auth=required

# Advertise custom service
python dnssd_advertiser.py -s "Game Server" -t _game._tcp.local -p 7777 -H gameserver.local -i 192.168.1.150 --txt game=minecraft --txt slots=20
```

### How It Works

The advertiser will:
1. Send initial announcements when it starts
2. Listen for queries about your service
3. Respond to PTR queries (service browsing)
4. Respond to SRV queries (getting port/hostname)
5. Respond to TXT queries (getting metadata)
6. Respond to A queries (hostname to IP)
7. Send periodic re-announcements
8. Send goodbye packet when you press Ctrl+C

## Complete Learning Scenarios

### Scenario 1: Basic Query and Response

**Terminal 1** - Start monitor:
```powershell
python mdns_monitor.py
```

**Terminal 2** - Send a query:
```powershell
python mdns_broadcaster.py query test.local
```

**What you'll see:**
- The monitor shows your query going out
- You might see responses from devices on your network

### Scenario 2: Service Discovery Flow

**Terminal 1** - Monitor:
```powershell
python mdns_monitor.py --verbose
```

**Terminal 2** - Advertise a service:
```powershell
python dnssd_advertiser.py -s "Test Server" -t _http._tcp.local -p 8080 -H test.local -i 192.168.1.100
```

**Terminal 3** - Browse for the service:
```powershell
python mdns_broadcaster.py browse _http._tcp.local
```

**What you'll see:**
- The advertiser sends initial announcements
- The browse query is sent
- The advertiser responds with PTR record
- All traffic is visible in the monitor

### Scenario 3: Name Conflict Detection

**Terminal 1** - Monitor:
```powershell
python mdns_monitor.py
```

**Terminal 2** - Advertise first service:
```powershell
python dnssd_advertiser.py -s "Server1" -t _test._tcp.local -p 8080 -H myhost.local -i 192.168.1.100
```

**Terminal 3** - Try to probe the same name:
```powershell
python mdns_broadcaster.py probe myhost.local 192.168.1.101
```

**What you'll see:**
- First advertiser announces myhost.local
- Probe queries are sent
- First advertiser should respond, indicating conflict

### Scenario 4: Service Lifecycle

**Terminal 1** - Monitor all traffic:
```powershell
python mdns_monitor.py --verbose
```

**Terminal 2** - Run complete service lifecycle:

1. Probe for the name:
```powershell
python mdns_broadcaster.py probe webapp.local 192.168.1.100
```

2. Announce the hostname:
```powershell
python mdns_broadcaster.py announce webapp.local 192.168.1.100
```

3. Start advertising the service:
```powershell
python dnssd_advertiser.py -s "My Web App" -t _http._tcp.local -p 8080 -H webapp.local -i 192.168.1.100 --txt version=1.0
```

4. Press Ctrl+C to stop (sends goodbye packets)

**What you'll learn:**
- Proper mDNS registration sequence
- How announcements work
- How goodbye packets work

## Advanced Experiments

### Experiment 1: Multiple Services on One Host

Run these in separate terminals:

```powershell
# Terminal 1: HTTP service
python dnssd_advertiser.py -s "Web" -t _http._tcp.local -p 80 -H multi.local -i 192.168.1.100

# Terminal 2: SSH service
python dnssd_advertiser.py -s "SSH" -t _ssh._tcp.local -p 22 -H multi.local -i 192.168.1.100

# Terminal 3: Custom service
python dnssd_advertiser.py -s "API" -t _api._tcp.local -p 3000 -H multi.local -i 192.168.1.100
```

All services share the same hostname but different service types.

### Experiment 2: Cache Flush Behavior

**Terminal 1** - Monitor:
```powershell
python mdns_monitor.py --verbose
```

**Terminal 2** - Announce with cache flush:
```powershell
python mdns_broadcaster.py announce test.local 192.168.1.100
```

**What to observe:**
- Look for the [FLUSH] flag in the monitor output
- This tells receivers to flush their cached records

### Experiment 3: TTL and Goodbye Packets

**Terminal 1** - Monitor:
```powershell
python mdns_monitor.py
```

**Terminal 2** - Announce with short TTL:
```powershell
python mdns_broadcaster.py announce short-lived.local 192.168.1.100 --ttl 10
```

**Terminal 3** - Send goodbye after a few seconds:
```powershell
python mdns_broadcaster.py goodbye short-lived.local 192.168.1.100
```

**What to learn:**
- TTL controls how long receivers cache the record
- TTL=0 (goodbye) tells receivers to immediately remove it

### Experiment 4: Query Response Patterns

```powershell
# Standard multicast query
python mdns_broadcaster.py query test.local

# Unicast response request (QU bit set)
python mdns_broadcaster.py query test.local --unicast

# Query for specific record types
python mdns_broadcaster.py query test.local --type A      # IPv4
python mdns_broadcaster.py query test.local --type ANY    # All records
python mdns_broadcaster.py query _http._tcp.local --type PTR  # Services
```

## Common Service Types to Experiment With

```powershell
# Standard services
_http._tcp.local          # Web servers
_https._tcp.local         # Secure web servers
_ssh._tcp.local           # SSH servers
_ftp._tcp.local           # FTP servers
_printer._tcp.local       # Printers
_ipp._tcp.local           # Internet Printing Protocol
_scanner._tcp.local       # Scanners

# Media services
_airplay._tcp.local       # Apple AirPlay
_spotify-connect._tcp.local  # Spotify Connect
_googlecast._tcp.local    # Google Chromecast
_raop._tcp.local          # Remote Audio Output Protocol

# File sharing
_smb._tcp.local           # Samba/Windows file sharing
_afpovertcp._tcp.local    # Apple File Protocol
_nfs._tcp.local           # Network File System

# Development
_workstation._tcp.local   # Workstations
_sftp-ssh._tcp.local     # SFTP over SSH
_git._tcp.local          # Git servers
```

## Troubleshooting

### No packets showing in monitor?

```powershell
# Check if mDNS is blocked by firewall
# Windows: Allow UDP port 5353 in Windows Firewall
# Run PowerShell as Administrator:
New-NetFirewallRule -DisplayName "mDNS" -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Allow
```

### Permission denied error?

```powershell
# Run PowerShell as Administrator
# Right-click PowerShell and select "Run as Administrator"
```

### Can't see your own broadcasts in monitor?

This is normal! The socket might not receive its own multicast messages.
Use two separate computers or virtual machines to see full interaction.

### Getting socket errors?

```powershell
# Make sure only one instance of monitor or advertiser is running
# Check if port 5353 is already in use
netstat -an | Select-String "5353"
```

## Learning Checklist

- [ ] Run the monitor and observe existing network traffic
- [ ] Send a simple hostname query
- [ ] Browse for HTTP services
- [ ] Announce a hostname
- [ ] Advertise a complete service
- [ ] Understand probe/announce/goodbye sequence
- [ ] Observe cache flush behavior
- [ ] Experiment with TTL values
- [ ] Try different service types
- [ ] Understand PTR, SRV, TXT, and A records
- [ ] See unicast vs multicast responses
- [ ] Observe service lifecycle (start to goodbye)

## Next Steps

1. Read the technical details in README.md
2. Capture real mDNS traffic with Wireshark for deeper analysis
3. Try creating your own service type
4. Experiment with multiple instances on different IPs
5. Test interoperability with real devices (printers, phones, etc.)

## Additional Resources

- RFC 6762: Multicast DNS - https://tools.ietf.org/html/rfc6762
- RFC 6763: DNS-SD - https://tools.ietf.org/html/rfc6763
- Wireshark for packet analysis - https://www.wireshark.org/
- IANA Service Names - https://www.iana.org/assignments/service-names-port-numbers/
