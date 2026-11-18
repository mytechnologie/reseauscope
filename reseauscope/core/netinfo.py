"""Informations sur les interfaces réseau locales."""
from __future__ import annotations

import ipaddress
import socket
import subprocess
import sys
from dataclasses import dataclass

import psutil

from .oui import normalize_mac

IS_WINDOWS = sys.platform.startswith("win")


@dataclass
class Interface:
    name: str
    ip: str
    netmask: str
    mac: str
    is_up: bool
    speed: int

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(f"{self.ip}/{self.netmask}", strict=False)

    @property
    def cidr(self) -> str:
        return str(self.network)


def interfaces(include_down: bool = False) -> list[Interface]:
    out = []
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        mac = ""
        v4 = []
        for a in addrs:
            if a.family == socket.AF_INET:
                v4.append(a)
            elif a.family == psutil.AF_LINK:
                mac = normalize_mac(a.address)
        st = stats.get(name)
        up = bool(st and st.isup)
        if not up and not include_down:
            continue
        for a in v4:
            if a.address.startswith("127.") or a.address.startswith("169.254.") or not a.netmask:
                continue
            out.append(Interface(name, a.address, a.netmask, mac, up, st.speed if st else 0))
    return out


def primary_ip() -> str:
    """IP de l'interface utilisée pour sortir (sans envoyer de paquet)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except OSError:
            return ""


def default_range() -> str:
    """Sous-réseau suggéré pour le scan (celui de l'interface principale)."""
    ip = primary_ip()
    for itf in interfaces():
        if itf.ip == ip:
            net = itf.network
            if net.prefixlen < 22:  # évite de proposer un /16 par défaut
                net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return str(net)
    itfs = interfaces()
    return itfs[0].cidr if itfs else "192.168.1.0/24"


def local_network_of(ip: str) -> Interface | None:
    addr = ipaddress.IPv4Address(ip)
    for itf in interfaces():
        if addr in itf.network:
            return itf
    return None


def default_gateway() -> str:
    try:
        if IS_WINDOWS:
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True, text=True,
                                 timeout=5, creationflags=0x08000000).stdout
            for line in out.splitlines():
                cols = line.split()
                if len(cols) >= 3 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0":
                    return cols[2]
        else:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    cols = line.split()
                    if cols[1] == "00000000":
                        return socket.inet_ntoa(int(cols[2], 16).to_bytes(4, "little"))
    except (OSError, subprocess.TimeoutExpired, IndexError, ValueError):
        pass
    return ""


def dns_servers() -> list[str]:
    try:
        if IS_WINDOWS:
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses"],
                                 capture_output=True, text=True, timeout=8, creationflags=0x08000000).stdout
            return list(dict.fromkeys(x.strip() for x in out.splitlines() if x.strip()))
        with open("/etc/resolv.conf") as f:
            return [line.split()[1] for line in f if line.startswith("nameserver")]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return []


def parse_targets(text: str, limit: int = 65536) -> list[str]:
    """Accepte : 192.168.1.0/24 · 192.168.1.10-50 · 192.168.1.10-192.168.2.20 · listes séparées par virgules."""
    ips: list[str] = []
    for part in text.replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            net = ipaddress.IPv4Network(part, strict=False)
            hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
            ips.extend(str(h) for h in hosts)
        elif "-" in part:
            a, _, b = part.partition("-")
            start = ipaddress.IPv4Address(a.strip())
            if "." in b:
                end = ipaddress.IPv4Address(b.strip())
            else:
                end = ipaddress.IPv4Address(".".join(a.strip().split(".")[:3] + [b.strip()]))
            if int(end) < int(start):
                start, end = end, start
            if int(end) - int(start) >= limit:
                raise ValueError(f"Plage trop grande (max {limit} adresses)")
            ips.extend(str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1))
        else:
            try:
                ips.append(str(ipaddress.IPv4Address(part)))
            except ipaddress.AddressValueError:
                ips.append(socket.gethostbyname(part))
        if len(ips) > limit:
            raise ValueError(f"Plage trop grande (max {limit} adresses)")
    return list(dict.fromkeys(ips))
