"""Catalogue des ports / services et préréglages de scan."""
from __future__ import annotations

SERVICES: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    69: "TFTP", 80: "HTTP", 81: "HTTP alt (caméras)", 82: "HTTP alt", 85: "HTTP alt (caméras)",
    88: "Kerberos / HTTP alt", 102: "Siemens S7", 110: "POP3", 111: "RPCbind", 123: "NTP",
    135: "MS-RPC", 137: "NetBIOS-NS", 139: "NetBIOS/SMB", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 502: "Modbus TCP", 515: "LPD (imprimante)",
    548: "AFP", 554: "RTSP (vidéo)", 587: "SMTP submission", 631: "IPP (imprimante)", 636: "LDAPS",
    873: "rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1400: "Sonos",
    1433: "MS-SQL", 1521: "Oracle", 1723: "PPTP", 1880: "Node-RED", 1883: "MQTT", 1900: "UPnP",
    1935: "RTMP", 2000: "Cisco SCCP / MikroTik bw", 2020: "HTTP alt", 2049: "NFS",
    3000: "HTTP dev / Grafana", 3001: "HTTP alt", 3306: "MySQL", 3389: "Bureau à distance (RDP)",
    3478: "STUN", 3702: "WS-Discovery (ONVIF)", 4025: "EnvisaLink (DSC/Honeywell)",
    4370: "ZKTeco (pointeuse/accès)", 4840: "OPC UA", 5000: "HTTP alt / Synology / UPnP",
    5001: "Synology HTTPS", 5060: "SIP", 5061: "SIP TLS", 5353: "mDNS", 5432: "PostgreSQL",
    5555: "ADB Android", 5900: "VNC", 5985: "WinRM", 5986: "WinRM HTTPS", 6036: "NVR (TVT/Uniview)",
    6379: "Redis", 6668: "Tuya", 7001: "HTTP alt / WebLogic", 7443: "HTTPS alt (UniFi)",
    7547: "TR-069 (FAI)", 8000: "Hikvision SDK / HTTP alt", 8001: "HTTP alt", 8008: "HTTP alt / Chromecast",
    8009: "Chromecast / AJP", 8080: "HTTP alt", 8081: "HTTP alt", 8088: "HTTP alt",
    8089: "HTTP alt", 8123: "Home Assistant", 8200: "Hikvision / DLNA", 8291: "MikroTik Winbox",
    8443: "HTTPS alt", 8554: "RTSP alt", 8728: "MikroTik API", 8729: "MikroTik API-SSL",
    8880: "HTTP alt", 8883: "MQTT TLS", 8888: "HTTP alt", 8899: "ONVIF (caméras chinoises)",
    9000: "HTTP alt / Dahua / Portainer", 9001: "HTTP alt", 9090: "HTTP alt", 9100: "Impression RAW (JetDirect)",
    9443: "HTTPS alt", 9999: "TP-Link Kasa", 10000: "Paradox IP150 / Webmin", 10001: "Ubiquiti discovery",
    10554: "RTSP alt", 20000: "DNP3", 27017: "MongoDB", 34567: "XMeye / NetSurveillance (DVR)",
    34599: "XMeye", 37777: "Dahua (TCP)", 37778: "Dahua (UDP/TCP)", 47808: "BACnet",
    49152: "UPnP / Windows RPC", 62078: "Apple iDevice",
}

HTTP_PORTS = {80, 81, 82, 85, 88, 2020, 3000, 3001, 5000, 7001, 8000, 8001, 8008, 8080, 8081, 8088,
              8089, 8123, 8200, 8880, 8888, 8899, 9000, 9001, 9090, 10000, 1880}
HTTPS_PORTS = {443, 5001, 7443, 8443, 9443, 5986}
RTSP_PORTS = {554, 8554, 10554}

TOP_PORTS = [21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 502, 515,
             548, 554, 587, 631, 993, 995, 1080, 1194, 1433, 1521, 1723, 1880, 1883, 1900, 2000, 2049,
             3000, 3306, 3389, 4025, 4370, 5000, 5001, 5060, 5432, 5555, 5900, 5985, 6036, 6379, 6668,
             7001, 7443, 7547, 8000, 8008, 8009, 8080, 8081, 8088, 8123, 8200, 8291, 8443, 8554, 8728,
             8883, 8888, 8899, 9000, 9090, 9100, 9443, 9999, 10000, 10554, 27017, 34567, 37777, 49152,
             62078]

PRESETS: dict[str, list[int] | str] = {
    "Ports courants (≈85)": TOP_PORTS,
    "Caméras / NVR / DVR": [80, 81, 85, 88, 443, 554, 1935, 2020, 5000, 6036, 7001, 8000, 8080, 8081, 8200,
                            8443, 8554, 8888, 8899, 9000, 10554, 34567, 34599, 37777, 37778],
    "Contrôle d'accès / alarme": [80, 443, 502, 3001, 4025, 4370, 5000, 7001, 8080, 8443, 9000, 10000,
                                  10001],
    "Domotique / IoT": [80, 443, 502, 1400, 1880, 1883, 4840, 5353, 6668, 8008, 8009, 8080, 8123, 8883,
                        9999, 47808],
    "Réseau / administration": [21, 22, 23, 53, 80, 161, 443, 830, 2000, 7443, 8080, 8291, 8443, 8728,
                                8729, 10001],
    "Windows / serveurs": [21, 22, 25, 53, 80, 88, 135, 139, 389, 443, 445, 636, 1433, 3306, 3389, 5432,
                           5900, 5985, 5986, 8080],
    "Ports 1 à 1024": "1-1024",
    "Tous les ports (1-65535)": "1-65535",
}

# Ports testés pour détecter un hôte qui ne répond pas au ping
PROBE_PORTS = [80, 443, 554, 22, 445, 8000, 8080, 37777, 34567, 3389, 139, 4370, 62078]


def service_name(port: int) -> str:
    return SERVICES.get(port, "")


def parse_ports(text: str) -> list[int]:
    """'22,80,8000-8010' -> liste triée sans doublons."""
    ports: set[int] = set()
    for part in text.replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            lo, hi = int(a), int(b)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(max(1, lo), min(65535, hi) + 1))
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def preset_ports(name: str) -> list[int]:
    v = PRESETS[name]
    return parse_ports(v) if isinstance(v, str) else sorted(set(v))
