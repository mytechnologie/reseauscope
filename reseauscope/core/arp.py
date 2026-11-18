"""Résolution d'adresse MAC (ARP).

Windows : SendARP (iphlpapi) — envoie une vraie requête ARP, ce qui détecte aussi
les équipements qui bloquent le ping (très fréquent sur les caméras).
Autres : lecture de la table ARP du système.
"""
from __future__ import annotations

import re
import socket
import subprocess
import sys

from .oui import normalize_mac

IS_WINDOWS = sys.platform.startswith("win")
_RE_ARP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+.*?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")

if IS_WINDOWS:
    import ctypes

    _iphlp = ctypes.WinDLL("iphlpapi")
    _SendARP = _iphlp.SendARP
    _SendARP.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    _SendARP.restype = ctypes.c_ulong

    def arp_request(ip: str) -> str:
        """Requête ARP active. Retourne la MAC ou ''. Bloque jusqu'à ~1-3 s si absent."""
        try:
            dest = int.from_bytes(socket.inet_aton(ip), "little")
        except OSError:
            return ""
        buf = (ctypes.c_ubyte * 8)()
        size = ctypes.c_ulong(6)
        if _SendARP(dest, 0, buf, ctypes.byref(size)) != 0 or size.value < 6:
            return ""
        return normalize_mac(":".join(f"{b:02X}" for b in buf[:6]))
else:
    def arp_request(ip: str) -> str:
        return arp_table().get(ip, "")


def arp_table() -> dict[str, str]:
    """Table ARP du système : {ip: mac}."""
    table: dict[str, str] = {}
    if not IS_WINDOWS:
        try:
            with open("/proc/net/arp") as f:
                next(f, None)
                for line in f:
                    cols = line.split()
                    if len(cols) >= 4:
                        mac = normalize_mac(cols[3])
                        if mac:
                            table[cols[0]] = mac
            return table
        except OSError:
            pass
    try:
        flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5,
                             creationflags=flags).stdout
    except (OSError, subprocess.TimeoutExpired):
        return table
    for m in _RE_ARP.finditer(out):
        mac = normalize_mac(m.group(2))
        if mac:
            table[m.group(1)] = mac
    return table
