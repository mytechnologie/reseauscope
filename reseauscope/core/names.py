"""Résolution de noms : DNS inverse, NetBIOS (Windows/NAS) et mDNS (Apple, Linux, IoT, caméras)."""
from __future__ import annotations

import os
import socket
import struct
from concurrent.futures import ThreadPoolExecutor

from .oui import normalize_mac

_pool = ThreadPoolExecutor(max_workers=32)


def reverse_dns(ip: str, timeout: float = 1.5) -> str:
    fut = _pool.submit(socket.gethostbyaddr, ip)
    try:
        return fut.result(timeout=timeout)[0]
    except Exception:
        return ""


def forward_dns(name: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(name, None)
    except OSError:
        return []
    seen = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


# --- NetBIOS -----------------------------------------------------------------

def netbios_query(ip: str, timeout: float = 1.0) -> dict:
    """Requête NBSTAT (UDP 137). Retourne {'name', 'workgroup', 'mac'} si l'hôte répond."""
    tid = os.urandom(2)
    name = b"\x20" + b"CK" + b"A" * 30 + b"\x00"
    packet = tid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x21\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(packet, (ip, 137))
            data, _ = s.recvfrom(2048)
        except OSError:
            return {}
    return parse_nbstat(data, tid)


def parse_nbstat(data: bytes, tid: bytes | None = None) -> dict:
    try:
        if tid and data[:2] != tid:
            return {}
        off = 12
        if data[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while data[off] != 0:
                off += data[off] + 1
            off += 1
        off += 2 + 2 + 4 + 2  # type, class, ttl, rdlength
        count = data[off]
        off += 1
        result = {"name": "", "workgroup": "", "mac": ""}
        for _ in range(count):
            raw = data[off:off + 15].decode("latin-1").strip()
            suffix = data[off + 15]
            flags = struct.unpack(">H", data[off + 16:off + 18])[0]
            off += 18
            group = bool(flags & 0x8000)
            if suffix == 0x00 and not group and not result["name"]:
                result["name"] = raw
            elif suffix == 0x00 and group and not result["workgroup"]:
                result["workgroup"] = raw
        mac = normalize_mac(data[off:off + 6].hex())
        result["mac"] = mac
        return result if result["name"] else {}
    except (IndexError, struct.error):
        return {}


# --- DNS minimal (pour mDNS) -----------------------------------------------------

def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("utf-8")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _read_name(data: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped_end = None
    while True:
        if depth > 10 or off >= len(data):
            raise ValueError("nom DNS invalide")
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if jumped_end is None:
                jumped_end = off + 2
            sub, _ = _read_name(data, ptr, depth + 1)
            labels.append(sub)
            off = jumped_end
            return ".".join(x for x in labels if x), off
        labels.append(data[off + 1:off + 1 + ln].decode("utf-8", errors="replace"))
        off += 1 + ln
    return ".".join(labels), off


def mdns_reverse(ip: str, timeout: float = 1.0) -> str:
    """Demande PTR mDNS unicast directement à l'hôte (port 5353)."""
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    tid = os.urandom(2)
    q = tid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + _encode_name(rev) + b"\x00\x0c\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(q, (ip, 5353))
            data, _ = s.recvfrom(4096)
        except OSError:
            return ""
    try:
        qd, an = struct.unpack(">HH", data[4:8])
        off = 12
        for _ in range(qd):
            _, off = _read_name(data, off)
            off += 4
        for _ in range(an):
            _, off = _read_name(data, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 12:
                name, _ = _read_name(data, off)
                return name.rstrip(".")
            off += rdlen
    except (ValueError, struct.error, IndexError):
        pass
    return ""


def resolve_name(ip: str, timeout: float = 1.0) -> tuple[str, dict]:
    """Essaie DNS inverse, puis NetBIOS, puis mDNS. Retourne (nom, infos NetBIOS)."""
    nb = netbios_query(ip, timeout)
    name = reverse_dns(ip, timeout + 0.5)
    if not name and nb:
        name = nb.get("name", "")
    if not name:
        name = mdns_reverse(ip, timeout)
    return name, nb
