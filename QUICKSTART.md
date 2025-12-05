# Quick Start Guide

Get started with mDNS/DNS-SD learning tools in 2 minutes!

## Prerequisites

- Python 3.6 or later
- Windows PowerShell (or any terminal)
- Administrator privileges (for binding to multicast port)

## Quick Test (3 Steps)

### Step 1: Open PowerShell as Administrator
Right-click PowerShell → "Run as Administrator"

### Step 2: Navigate to the project
```powershell
cd C:\Users\Normo\Dev\Dicscovery
```

### Step 3: Run the Monitor
```powershell
python mdns_monitor.py
```

You should see mDNS traffic from devices on your network!

## Quick Experiments

### Experiment A: Send a Query (30 seconds)

**Terminal 1:**
```powershell
python mdns_monitor.py
```

**Terminal 2:**
```powershell
python mdns_broadcaster.py query mydevice.local
```

Watch the query appear in Terminal 1!

### Experiment B: Advertise a Service (2 minutes)

**Terminal 1:**
```powershell
python mdns_monitor.py
```

**Terminal 2:**
```powershell
python dnssd_advertiser.py -s "Test" -t _http._tcp.local -p 8080 -H test.local -i 192.168.1.100
```

**Terminal 3:**
```powershell
python mdns_broadcaster.py browse _http._tcp.local
```

Watch the complete service discovery flow!

## File Overview

| File | Purpose | Usage |
|------|---------|-------|
| `README.md` | Technical documentation | Learn how mDNS/DNS-SD work |
| `EXAMPLES.md` | Detailed examples | Step-by-step learning scenarios |
| `mdns_monitor.py` | Traffic analyzer | See all mDNS packets |
| `mdns_broadcaster.py` | Send packets | Query, announce, probe |
| `dnssd_advertiser.py` | Service advertiser | Long-running service |

## Common Commands

```powershell
# Monitor traffic
python mdns_monitor.py

# Query hostname
python mdns_broadcaster.py query hostname.local

# Browse services
python mdns_broadcaster.py browse _http._tcp.local

# Announce hostname
python mdns_broadcaster.py announce myhost.local 192.168.1.100

# Advertise service
python dnssd_advertiser.py -s "Name" -t _http._tcp.local -p 8080 -H host.local -i 192.168.1.100
```

## Get Help

```powershell
python mdns_monitor.py --help
python mdns_broadcaster.py --help
python dnssd_advertiser.py --help
```

## Troubleshooting

**"Permission denied"** → Run PowerShell as Administrator

**"Address already in use"** → Close other instances first

**Not seeing packets?** → Check Windows Firewall allows UDP 5353

## Next Steps

1. ✅ Run the quick test above
2. 📖 Read `README.md` for technical details
3. 🧪 Try examples in `EXAMPLES.md`
4. 🔬 Experiment with your own services!

Happy learning! 🎉
