# mDNS and DNS-SD Technical Overview

## Table of Contents
1. [Introduction](#introduction)
2. [mDNS (Multicast DNS)](#mdns-multicast-dns)
3. [DNS-SD (DNS Service Discovery)](#dns-sd-dns-service-discovery)
4. [Protocol Details](#protocol-details)
5. [Python Tools](#python-tools)

## Introduction

**mDNS** (Multicast DNS) and **DNS-SD** (DNS Service Discovery) are protocols that enable zero-configuration networking, allowing devices to discover each other and advertise services on a local network without requiring a centralized DNS server.

## mDNS (Multicast DNS)

### Overview
mDNS is defined in RFC 6762 and provides hostname resolution in local networks without requiring a traditional DNS server. It uses IP multicast to query all devices on the local network simultaneously.

### Key Characteristics

- **Multicast Address**: 
  - IPv4: `224.0.0.251`
  - IPv6: `FF02::FB`
- **Port**: UDP port `5353`
- **Domain**: `.local` TLD (Top Level Domain)
- **TTL**: IP multicast packets use TTL of 255

### How mDNS Works

1. **Query Process**:
   - A device sends a multicast DNS query to `224.0.0.251:5353`
   - All devices on the network receive the query
   - The device with the matching hostname responds directly or via multicast
   - Responses are cached by all listening devices

2. **Name Resolution**:
   - Instead of querying a DNS server for "device.local"
   - The query is multicast to all devices
   - The device named "device" responds with its IP address

3. **Probing and Announcing**:
   - **Probing**: Before claiming a hostname, a device sends probe queries to check if the name is already taken
   - **Announcing**: Once confirmed unique, the device announces its presence with its hostname and IP address

### mDNS Message Types

1. **Query (QR=0)**:
   - Standard query for a hostname or service
   - Can be "One-Shot" (QU bit set) expecting unicast response
   - Or standard multicast query

2. **Response (QR=1)**:
   - Contains answer records
   - Can be unicast or multicast
   - May contain additional records for efficiency

3. **Probe Query**:
   - Special query to check name uniqueness
   - Sent with the proposed record in the Authority section
   - Sent 3 times with 250ms intervals

4. **Announcement**:
   - Unsolicited response announcing presence
   - Contains resource records with full TTL
   - Typically sent when a service starts or network interface comes up

### DNS Record Types Used in mDNS

- **A Record**: Maps hostname to IPv4 address
- **AAAA Record**: Maps hostname to IPv6 address
- **PTR Record**: Pointer for reverse lookups and service enumeration
- **SRV Record**: Service location (hostname, port, priority, weight)
- **TXT Record**: Key-value metadata about services
- **NSEC Record**: Negative assertion (proves non-existence of records)

## DNS-SD (DNS Service Discovery)

### Overview
DNS-SD is defined in RFC 6763 and builds on top of DNS (or mDNS) to enable service discovery. It uses standard DNS record types (PTR, SRV, TXT) to advertise and discover services.

### Service Naming Convention

Services are named using a hierarchical structure:
```
<Instance>._<Service>._<Proto>.<Domain>
```

**Example**: `My Printer._ipp._tcp.local`

- **Instance**: Human-readable service instance name (e.g., "My Printer")
- **Service**: Service type (e.g., "_ipp" for Internet Printing Protocol)
- **Proto**: Transport protocol ("_tcp" or "_udp")
- **Domain**: Domain name (e.g., "local" for mDNS)

### Service Discovery Process

1. **Service Enumeration**:
   - Query for `_services._dns-sd._udp.local` (PTR)
   - Returns list of available service types

2. **Service Type Browsing**:
   - Query for `_http._tcp.local` (PTR)
   - Returns list of specific service instances

3. **Service Resolution**:
   - Query for SRV record: Get hostname and port
   - Query for TXT record: Get service metadata
   - Query for A/AAAA record: Resolve hostname to IP address

### Common Service Types

- `_http._tcp`: Web servers
- `_ssh._tcp`: SSH servers
- `_ftp._tcp`: FTP servers
- `_printer._tcp`: Printers
- `_ipp._tcp`: Internet Printing Protocol
- `_airplay._tcp`: Apple AirPlay
- `_spotify-connect._tcp`: Spotify Connect
- `_googlecast._tcp`: Google Chromecast
- `_smb._tcp`: Samba/CIFS file sharing

### DNS-SD Records Example

For a service instance "My Web Server._http._tcp.local":

```
; PTR record for browsing
_http._tcp.local. 3600 IN PTR My Web Server._http._tcp.local.

; SRV record for location
My Web Server._http._tcp.local. 120 IN SRV 0 0 8080 myserver.local.

; TXT record for metadata
My Web Server._http._tcp.local. 3600 IN TXT "path=/index.html" "version=1.0"

; A record for IP resolution
myserver.local. 120 IN A 192.168.1.100
```

## Protocol Details

### DNS Packet Structure

All mDNS and DNS-SD messages use standard DNS packet format:

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   Header                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  Questions                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   Answers                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  Authority                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                 Additional                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### DNS Header (12 bytes)

```
 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

**Header Fields**:
- **ID**: 16-bit identifier (usually 0 for mDNS queries)
- **QR**: Query (0) or Response (1)
- **Opcode**: Operation code (0 for standard query)
- **AA**: Authoritative Answer
- **TC**: Truncated message
- **RD**: Recursion Desired (should be 0 for mDNS)
- **RA**: Recursion Available
- **RCODE**: Response code
- **QDCOUNT**: Number of questions
- **ANCOUNT**: Number of answer records
- **NSCOUNT**: Number of authority records
- **ARCOUNT**: Number of additional records

### Resource Record Format

```
 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     NAME                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     TYPE                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
|                     RDATA                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### Important mDNS-Specific Behaviors

1. **Cache Flush Bit**: 
   - Most significant bit of CLASS field
   - When set (0x8001), tells receivers to flush cached records
   - Critical for updating changed information

2. **Known-Answer Suppression**:
   - Queries can include known answers in Answer section
   - Responders don't reply if their answer is already listed
   - Reduces network traffic

3. **Continuous Querying**:
   - Clients may send periodic queries to discover new services
   - Typically at exponentially increasing intervals

4. **Goodbye Packets**:
   - Resource records with TTL=0 indicate service is going away
   - Receivers immediately flush these from cache

## Python Tools

This repository includes three Python tools for working with mDNS and DNS-SD:

### 1. mDNS Broadcaster (`mdns_broadcaster.py`)
Send various mDNS messages onto the network:
- Send hostname queries
- Send service discovery queries
- Announce hostnames and services
- Probe for name conflicts

### 2. DNS-SD Service Advertiser (`dnssd_advertiser.py`)
Advertise services on the network:
- Register custom services
- Respond to service queries
- Send periodic announcements
- Send goodbye packets on exit

### 3. mDNS Monitor (`mdns_monitor.py`)
Listen to and analyze mDNS traffic:
- Capture all mDNS packets
- Display queries and responses
- Show service announcements
- Decode DNS records

## Installation

```bash
pip install -r requirements.txt
```

## Usage Examples

### Monitor Network Traffic
```bash
python mdns_monitor.py
```

### Query for a Hostname
```bash
python mdns_broadcaster.py query mydevice.local
```

### Announce a Hostname
```bash
python mdns_broadcaster.py announce myhost.local 192.168.1.100
```

### Browse for HTTP Services
```bash
python mdns_broadcaster.py browse _http._tcp.local
```

### Advertise a Service
```bash
python dnssd_advertiser.py --service "My Web Server" --type _http._tcp --port 8080
```

### Probe for Name Conflicts
```bash
python mdns_broadcaster.py probe testdevice.local
```

## References

- **RFC 6762**: Multicast DNS
- **RFC 6763**: DNS-Based Service Discovery
- **RFC 1035**: Domain Names - Implementation and Specification
- **IANA Service Name Registry**: https://www.iana.org/assignments/service-names-port-numbers/

## Network Topology Considerations

### Multicast Forwarding
- mDNS is designed for single subnet operation
- Routers typically don't forward multicast traffic between subnets
- Some enterprise networks may block multicast for security

### Firewall Configuration
- Ensure UDP port 5353 is open
- Allow multicast traffic to 224.0.0.251
- Some firewalls require explicit multicast group membership

### IPv6 Considerations
- mDNS works over IPv6 using FF02::FB
- Dual-stack systems should handle both IPv4 and IPv6
- Link-local addresses are commonly used in mDNS responses

## Security Considerations

1. **No Authentication**: mDNS has no built-in authentication mechanism
2. **Spoofing**: Malicious actors can send fake responses
3. **Information Disclosure**: Services are advertised to entire local network
4. **Cache Poisoning**: False records can be injected into caches
5. **Denial of Service**: Flood of queries or responses can impact network

### Best Practices
- Only use mDNS on trusted local networks
- Implement application-level authentication for services
- Monitor for suspicious mDNS activity
- Consider network segmentation for sensitive devices
- Use firewall rules to restrict mDNS to local subnet only

## License

MIT License - Feel free to use and modify these tools for learning and experimentation.
