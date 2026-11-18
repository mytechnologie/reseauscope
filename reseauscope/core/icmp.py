"""Ping ICMP sans droits administrateur.

Sous Windows : API native IcmpSendEcho (iphlpapi.dll) via ctypes. Aucune
dépendance à la langue de Windows (pas d'analyse de la sortie de ping.exe)
et support du TTL pour le traceroute.

Ailleurs (Linux/macOS, utile pour le développement) : commande système `ping`.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass

IS_WINDOWS = sys.platform.startswith("win")

# Statuts renvoyés
OK = "ok"                 # réponse echo de la cible
TTL_EXPIRED = "ttl"       # un routeur intermédiaire a répondu (traceroute)
TIMEOUT = "timeout"
UNREACHABLE = "unreachable"
ERROR = "error"


@dataclass
class PingResult:
    status: str
    rtt_ms: float | None = None
    reply_from: str | None = None
    ttl: int | None = None
    detail: str = ""

    @property
    def alive(self) -> bool:
        return self.status == OK


def resolve(host: str) -> str:
    """Résout un nom en IPv4 (lève socket.gaierror si impossible)."""
    return socket.gethostbyname(host.strip())


if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    class IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Ttl", ctypes.c_ubyte),
            ("Tos", ctypes.c_ubyte),
            ("Flags", ctypes.c_ubyte),
            ("OptionsSize", ctypes.c_ubyte),
            ("OptionsData", ctypes.c_void_p),
        ]

    class ICMP_ECHO_REPLY(ctypes.Structure):
        _fields_ = [
            ("Address", ctypes.c_ulong),
            ("Status", ctypes.c_ulong),
            ("RoundTripTime", ctypes.c_ulong),
            ("DataSize", ctypes.c_ushort),
            ("Reserved", ctypes.c_ushort),
            ("Data", ctypes.c_void_p),
            ("Options", IP_OPTION_INFORMATION),
        ]

    _iphlp = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _IcmpCreateFile = _iphlp.IcmpCreateFile
    _IcmpCreateFile.restype = wintypes.HANDLE
    _IcmpCloseHandle = _iphlp.IcmpCloseHandle
    _IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    _IcmpSendEcho = _iphlp.IcmpSendEcho
    _IcmpSendEcho.argtypes = [
        wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort,
        ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p, wintypes.DWORD,
        wintypes.DWORD,
    ]
    _IcmpSendEcho.restype = wintypes.DWORD

    _INVALID_HANDLE = ctypes.c_void_p(-1).value

    IP_SUCCESS = 0
    _UNREACH_CODES = {11002, 11003, 11004, 11005, 11032, 11040}
    _TTL_CODES = {11013, 11014}  # TTL expiré en transit / au réassemblage
    _TIMEOUT_CODES = {11010}

    def _ip_to_addr(ip: str) -> int:
        return int.from_bytes(socket.inet_aton(ip), "little")

    def _addr_to_ip(addr: int) -> str:
        return socket.inet_ntoa(int(addr).to_bytes(4, "little"))

    def ping(host: str, timeout: float = 1.0, ttl: int = 128, size: int = 32) -> PingResult:
        try:
            ip = resolve(host)
        except OSError as exc:
            return PingResult(ERROR, detail=f"Résolution impossible : {exc}")
        handle = _IcmpCreateFile()
        if not handle or handle == _INVALID_HANDLE:
            return PingResult(ERROR, detail="IcmpCreateFile a échoué")
        try:
            payload = (b"ReseauScope" * (size // 11 + 1))[:size]
            req = ctypes.create_string_buffer(payload, size)
            reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + size + 64
            reply_buf = ctypes.create_string_buffer(reply_size)
            opts = IP_OPTION_INFORMATION(Ttl=max(1, min(255, ttl)))
            t0 = time.perf_counter()
            ret = _IcmpSendEcho(handle, _ip_to_addr(ip), req, size, ctypes.byref(opts),
                                reply_buf, reply_size, int(timeout * 1000))
            elapsed = (time.perf_counter() - t0) * 1000
            reply = ICMP_ECHO_REPLY.from_buffer(reply_buf)
            if ret == 0:
                err = ctypes.get_last_error()
                # Certaines versions renvoient 0 mais remplissent quand même la réponse
                if reply.Address and reply.Status in (_TTL_CODES | _UNREACH_CODES):
                    err = reply.Status
                if err in _TTL_CODES:
                    return PingResult(TTL_EXPIRED, rtt_ms=elapsed, reply_from=_addr_to_ip(reply.Address))
                if err in _UNREACH_CODES:
                    frm = _addr_to_ip(reply.Address) if reply.Address else None
                    return PingResult(UNREACHABLE, reply_from=frm, detail=f"Code {err}")
                return PingResult(TIMEOUT, detail=f"Code {err}" if err not in _TIMEOUT_CODES else "")
            status = reply.Status
            frm = _addr_to_ip(reply.Address)
            if status == IP_SUCCESS:
                rtt = float(reply.RoundTripTime)
                if rtt == 0:
                    rtt = min(elapsed, 1.0)
                return PingResult(OK, rtt_ms=rtt, reply_from=frm, ttl=reply.Options.Ttl)
            if status in _TTL_CODES:
                return PingResult(TTL_EXPIRED, rtt_ms=float(reply.RoundTripTime) or elapsed, reply_from=frm)
            if status in _UNREACH_CODES:
                return PingResult(UNREACHABLE, reply_from=frm, detail=f"Code {status}")
            if status in _TIMEOUT_CODES:
                return PingResult(TIMEOUT)
            return PingResult(ERROR, reply_from=frm, detail=f"Code {status}")
        finally:
            _IcmpCloseHandle(handle)

else:
    _RE_TIME = re.compile(r"time[=<]\s*([\d.]+)\s*ms")
    _RE_TTL = re.compile(r"ttl[=](\d+)", re.I)
    _RE_FROM = re.compile(r"[Ff]rom ([\d.]+)")

    def ping(host: str, timeout: float = 1.0, ttl: int = 64, size: int = 32) -> PingResult:
        try:
            ip = resolve(host)
        except OSError as exc:
            return PingResult(ERROR, detail=f"Résolution impossible : {exc}")
        wait = max(1, int(round(timeout)))
        cmd = ["ping", "-n", "-c", "1", "-W", str(wait), "-t", str(ttl), "-s", str(size), ip]
        env = dict(os.environ, LANG="C", LC_ALL="C")
        t0 = time.perf_counter()
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=wait + 2, env=env).stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            return PingResult(ERROR, detail=str(exc))
        elapsed = (time.perf_counter() - t0) * 1000
        if "Time to live exceeded" in out:
            m = _RE_FROM.search(out)
            return PingResult(TTL_EXPIRED, rtt_ms=elapsed, reply_from=m.group(1) if m else None)
        m = _RE_TIME.search(out)
        if m:
            t = _RE_TTL.search(out)
            return PingResult(OK, rtt_ms=float(m.group(1)), reply_from=ip, ttl=int(t.group(1)) if t else None)
        if "Unreachable" in out:
            m = _RE_FROM.search(out)
            return PingResult(UNREACHABLE, reply_from=m.group(1) if m else None)
        return PingResult(TIMEOUT)
