"""
DNS-SD Service Types Database

This database contains common mDNS/DNS-SD service types and their descriptions.
Downloads from the official DNS-SD registry and caches locally.

References:
- http://www.dns-sd.org/ServiceTypes.html
- IANA Service Name and Transport Protocol Port Number Registry
"""

import json
import urllib.request
from pathlib import Path
from datetime import datetime, timedelta

# Cache file location
CACHE_FILE = Path(__file__).parent / 'service_types_cache.json'
CACHE_DURATION = timedelta(days=7)  # Refresh weekly

# Official DNS-SD service types registry
# Primary source: Parse from dns-sd.org website
REGISTRY_URL = 'http://www.dns-sd.org/ServiceTypes.html'
# Fallback: IANA service names
IANA_URL = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml'

# Fallback built-in database
SERVICE_TYPES_BUILTIN = {
    # Apple/AirPlay Services
    '_airplay._tcp': 'AirPlay - Apple wireless streaming',
    '_raop._tcp': 'Remote Audio Output Protocol - AirPlay audio',
    '_airport._tcp': 'AirPort Base Station',
    '_homekit._tcp': 'HomeKit Accessory Protocol',
    '_hap._tcp': 'HomeKit Accessory Protocol',
    '_companion-link._tcp': 'Apple Companion Link',
    '_sleep-proxy._udp': 'Sleep Proxy Server',
    
    # Google Cast/Chromecast
    '_googlecast._tcp': 'Google Cast - Chromecast devices',
    '_googlerpc._tcp': 'Google RPC',
    
    # Printing Services
    '_ipp._tcp': 'Internet Printing Protocol',
    '_ipps._tcp': 'Internet Printing Protocol over HTTPS',
    '_printer._tcp': 'LPD Printer Service',
    '_pdl-datastream._tcp': 'PDL Data Stream',
    '_ptp._tcp': 'Picture Transfer Protocol',
    
    # File Sharing
    '_smb._tcp': 'Server Message Block - Windows/Samba file sharing',
    '_afpovertcp._tcp': 'Apple Filing Protocol over TCP',
    '_nfs._tcp': 'Network File System',
    '_ftp._tcp': 'File Transfer Protocol',
    '_sftp-ssh._tcp': 'Secure File Transfer over SSH',
    '_webdav._tcp': 'WebDAV File Sharing',
    
    # Media Servers
    '_http._tcp': 'Web Server (HTTP)',
    '_https._tcp': 'Secure Web Server (HTTPS)',
    '_daap._tcp': 'Digital Audio Access Protocol - iTunes sharing',
    '_dpap._tcp': 'Digital Photo Access Protocol - iPhoto sharing',
    '_dacp._tcp': 'Digital Audio Control Protocol - iTunes remote',
    '_touch-able._tcp': 'iTunes Remote Pairing',
    '_appletv-v2._tcp': 'Apple TV (2nd gen and later)',
    '_mediaremotetv._tcp': 'Apple TV Remote Control',
    '_plex-api._tcp': 'Plex Media Server API',
    '_plexmediasvr._tcp': 'Plex Media Server',
    '_spotify-connect._tcp': 'Spotify Connect',
    '_sonos._tcp': 'Sonos Audio System',
    
    # Remote Access/Management
    '_ssh._tcp': 'Secure Shell (SSH)',
    '_sftp-ssh._tcp': 'SSH File Transfer Protocol',
    '_telnet._tcp': 'Telnet Remote Terminal',
    '_rfb._tcp': 'Remote Frame Buffer (VNC)',
    '_vnc._tcp': 'Virtual Network Computing',
    '_rdp._tcp': 'Remote Desktop Protocol',
    '_net-assistant._tcp': 'Apple Remote Desktop',
    '_workstation._tcp': 'Workstation Service',
    
    # Device Management
    '_device-info._tcp': 'Device Information',
    '_sleep-proxy._udp': 'Sleep Proxy Service',
    '_wsd._tcp': 'Web Services for Devices',
    '_dosvc._tcp': 'Delivery Optimization Service - Windows Update P2P',
    '_esphomelib._tcp': 'ESPHome Device',
    
    # Smart Home/IoT
    '_homekit._tcp': 'HomeKit Accessory',
    '_matter._tcp': 'Matter Smart Home Protocol',
    '_hue._tcp': 'Philips Hue Bridge',
    '_wemo._tcp': 'Belkin WeMo Device',
    '_ewelink._tcp': 'eWeLink Smart Home',
    '_xiaomi-smart._tcp': 'Xiaomi Smart Home',
    '_mqtt._tcp': 'MQTT Broker',
    '_coap._tcp': 'Constrained Application Protocol',
    '_octoprint._tcp': 'OctoPrint 3D Printer Server',
    
    # Gaming/Entertainment
    '_nvstream._tcp': 'NVIDIA GameStream',
    '_steam._tcp': 'Steam In-Home Streaming',
    '_xbmc-jsonrpc-h._tcp': 'Kodi/XBMC JSON-RPC over HTTP',
    '_xbmc-events._udp': 'Kodi/XBMC Event Server',
    
    # Database Services
    '_postgresql._tcp': 'PostgreSQL Database',
    '_mysql._tcp': 'MySQL Database',
    '_mongodb._tcp': 'MongoDB Database',
    '_redis._tcp': 'Redis Key-Value Store',
    
    # Development Services
    '_git._tcp': 'Git Version Control',
    '_svn._tcp': 'Subversion Version Control',
    '_distcc._tcp': 'Distributed C/C++ Compiler',
    '_presence._tcp': 'Peer Presence Detection',
    
    # Scanning Services
    '_scanner._tcp': 'Document Scanner',
    '_scan._tcp': 'Network Scanner',
    '_uscan._tcp': 'Universal Scanner',
    '_uscans._tcp': 'Universal Scanner (Secure)',
    
    # Time Services
    '_ntp._udp': 'Network Time Protocol',
    '_daytime._tcp': 'Daytime Protocol',
    '_time._tcp': 'Time Protocol',
    
    # Home Automation
    '_hap._tcp': 'HomeKit Accessory Protocol',
    '_AxisVideo._tcp': 'Axis Network Camera',
    '_nvstream_dbd._tcp': 'NVIDIA Shield',
    '_androidtvremote2._tcp': 'Android TV Remote',
    
    # Network Infrastructure
    '_domain._udp': 'DNS Server',
    '_dns-sd._udp': 'DNS Service Discovery',
    '_dns-llq._udp': 'DNS Long-Lived Queries',
    '_dns-update._udp': 'DNS Dynamic Updates',
    
    # Audio/Video Streaming
    '_rtsp._tcp': 'Real Time Streaming Protocol',
    '_rtp._udp': 'Real-time Transport Protocol',
    '_sip._tcp': 'Session Initiation Protocol',
    '_sip._udp': 'Session Initiation Protocol (UDP)',
    
    # Windows Services
    '_smb._tcp': 'Server Message Block',
    '_device-info._tcp': 'Windows Device Info',
    '_workstation._tcp': 'Windows Workstation',
    '_dosvc._tcp': 'Windows Delivery Optimization',
    
    # Misc Services
    '_api._tcp': 'Generic API Service',
    '_rest._tcp': 'RESTful API',
    '_soap._tcp': 'SOAP Web Service',
    '_upnp._tcp': 'Universal Plug and Play',
    '_ssdp._udp': 'Simple Service Discovery Protocol',
}

# Active database (loaded from cache or built-in)
SERVICE_TYPES = {}

def load_cache():
    """Load service types from cache file."""
    try:
        if CACHE_FILE.exists():
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            # Check if cache is still valid
            cache_time = datetime.fromisoformat(cache_data.get('timestamp', '2000-01-01'))
            if datetime.now() - cache_time < CACHE_DURATION:
                return cache_data.get('services', {})
    except Exception as e:
        print(f"Warning: Could not load cache: {e}")
    
    return None

def save_cache(services):
    """Save service types to cache file."""
    try:
        cache_data = {
            'timestamp': datetime.now().isoformat(),
            'services': services,
            'source': 'downloaded'
        }
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save cache: {e}")

def download_service_types():
    """
    Download service types from official registry.
    Falls back to built-in database if download fails.
    """
    try:
        print(f"Parsing DNS-SD service types from {REGISTRY_URL}...")
        
        # Download with timeout
        req = urllib.request.Request(REGISTRY_URL, headers={'User-Agent': 'mDNS-Discovery/1.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore')
        
        # Parse HTML to extract service types
        # Format in HTML: service type name followed by description
        services = {}
        import re
        
        # Look for service type patterns like _servicename._tcp or _servicename._udp
        # followed by their descriptions
        pattern = r'(_[a-zA-Z0-9\-]+\._(tcp|udp))\s+([^\n<]+)'
        matches = re.findall(pattern, content, re.IGNORECASE)
        
        for match in matches:
            service_type = match[0]  # e.g., _http._tcp
            description = match[2].strip()
            # Clean up description
            description = re.sub(r'\s+', ' ', description)
            description = description.split('\n')[0].strip()
            if description and len(description) < 200:
                services[service_type] = description
        
        if services and len(services) > 50:  # Sanity check
            print(f"Parsed {len(services)} service types from DNS-SD registry")
            save_cache(services)
            return services
        else:
            print(f"Warning: Only found {len(services)} services, may be parsing issue")
        
    except Exception as e:
        print(f"Warning: Could not download service types: {e}")
    
    return None

def initialize_database():
    """Initialize the service types database."""
    global SERVICE_TYPES
    
    # Try to load from cache first
    cached = load_cache()
    if cached:
        SERVICE_TYPES = cached
        return
    
    # Try to download fresh data
    downloaded = download_service_types()
    if downloaded:
        SERVICE_TYPES = downloaded
        return
    
    # Fall back to built-in database
    print("Using built-in service types database")
    SERVICE_TYPES = SERVICE_TYPES_BUILTIN.copy()

def get_service_description(service_type):
    """
    Get a human-readable description for a service type.
    
    Args:
        service_type: Service type string (e.g., '_googlecast._tcp.local')
    
    Returns:
        Description string or the service type if not found
    """
    # Ensure database is initialized
    if not SERVICE_TYPES:
        initialize_database()
    
    # Remove .local suffix if present
    clean_type = service_type.replace('.local', '')
    
    return SERVICE_TYPES.get(clean_type, clean_type)

def list_all_services():
    """Return a list of all known service types."""
    if not SERVICE_TYPES:
        initialize_database()
    return sorted(SERVICE_TYPES.keys())

def search_services(keyword):
    """
    Search for services matching a keyword.
    
    Args:
        keyword: Search term (case-insensitive)
    
    Returns:
        Dictionary of matching service types and descriptions
    """
    if not SERVICE_TYPES:
        initialize_database()
    
    keyword = keyword.lower()
    results = {}
    
    for service_type, description in SERVICE_TYPES.items():
        if keyword in service_type.lower() or keyword in description.lower():
            results[service_type] = description
    
    return results

def update_database(force=False):
    """
    Manually update the service types database.
    
    Args:
        force: If True, ignore cache and force download
    
    Returns:
        True if database was updated, False otherwise
    """
    global SERVICE_TYPES
    
    if force or not load_cache():
        downloaded = download_service_types()
        if downloaded:
            SERVICE_TYPES = downloaded
            return True
    
    return False

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'update':
            print("Forcing database update...")
            if update_database(force=True):
                print("✓ Database updated successfully")
                initialize_database()
                print(f"Total service types: {len(SERVICE_TYPES)}")
            else:
                print("✗ Update failed, using built-in database")
        elif sys.argv[1] == 'list':
            print("Known DNS-SD Service Types:")
            print("-" * 70)
            for service_type in list_all_services():
                print(f"{service_type:30} {SERVICE_TYPES[service_type]}")
        elif sys.argv[1] == 'search':
            if len(sys.argv) > 2:
                keyword = sys.argv[2]
                results = search_services(keyword)
                print(f"Services matching '{keyword}':")
                print("-" * 70)
                for service_type, desc in sorted(results.items()):
                    print(f"{service_type:30} {desc}")
            else:
                print("Usage: python service_types.py search <keyword>")
        elif sys.argv[1] == 'cache':
            if CACHE_FILE.exists():
                with open(CACHE_FILE, 'r') as f:
                    cache_data = json.load(f)
                timestamp = cache_data.get('timestamp', 'unknown')
                count = len(cache_data.get('services', {}))
                print(f"Cache file: {CACHE_FILE}")
                print(f"Last updated: {timestamp}")
                print(f"Service types: {count}")
            else:
                print("No cache file found")
        else:
            service = sys.argv[1]
            desc = get_service_description(service)
            print(f"{service}: {desc}")
    else:
        initialize_database()
        print(f"Total known service types: {len(SERVICE_TYPES)}")
        print(f"Cache file: {CACHE_FILE}")
        print("\nUsage:")
        print("  python service_types.py update                # Update database")
        print("  python service_types.py list                  # List all services")
        print("  python service_types.py search <keyword>      # Search services")
        print("  python service_types.py cache                 # Show cache info")
        print("  python service_types.py <service_type>        # Get description")
        print("\nExamples:")
        print("  python service_types.py update")
        print("  python service_types.py _googlecast._tcp")
        print("  python service_types.py search apple")
        print("  python service_types.py list")

# Initialize on import
initialize_database()
