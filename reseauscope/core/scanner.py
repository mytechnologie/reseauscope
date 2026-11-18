"""Scan d'un réseau : détection des hôtes actifs puis identification de chaque équipement."""
from __future__ import annotations

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import arp, icmp, names
from .classify import identify
from .netinfo import interfaces
from .oui import get_db, is_locally_administered
from .portscan import scan_ports, tcp_open
from .services import PROBE_PORTS

# Ports testés pour l'identification rapide (si l'option est cochée)
IDENTIFY_PORTS = [21, 22, 23, 53, 80, 102, 135, 443, 445, 502, 515, 554, 631, 1400, 1883, 3389, 4025,
                  4370, 5000, 5001, 5060, 5985, 6036, 6668, 8000, 8008, 8009, 8080, 8123, 8291, 8443,
                  8554, 8728, 8899, 9100, 10000, 34567, 37777, 62078]


@dataclass
class Host:
    ip: str
    alive: bool = False
    method: str = ""          # ICMP, ARP, TCP
    rtt_ms: float | None = None
    ttl: int | None = None
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    workgroup: str = ""
    open_ports: list[int] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    category: str = ""
    brand: str = ""
    confidence: str = ""
    reasons: str = ""
    os_guess: str = ""
    web_url: str = ""

    def as_dict(self) -> dict:
        return {
            "ip": self.ip, "etat": "Actif" if self.alive else "Inactif", "detection": self.method,
            "latence_ms": round(self.rtt_ms, 1) if self.rtt_ms is not None else "",
            "ttl": self.ttl or "", "os_probable": self.os_guess, "nom_hote": self.hostname,
            "groupe": self.workgroup, "mac": self.mac, "fabricant": self.vendor,
            "type_equipement": self.category, "marque": self.brand, "confiance": self.confidence,
            "indices": self.reasons, "ports_ouverts": ", ".join(map(str, self.open_ports)),
            "interface_web": self.web_url,
        }


def os_from_ttl(ttl: int | None) -> str:
    if not ttl:
        return ""
    if ttl <= 64:
        return "Linux / embarqué"
    if ttl <= 128:
        return "Windows"
    return "Équipement réseau"


@dataclass
class ScanOptions:
    timeout: float = 1.0
    workers: int = 128
    resolve_names: bool = True
    identify_ports: bool = True
    tcp_probe: bool = True
    show_dead: bool = False


class NetworkScanner:
    def __init__(self, targets: list[str], options: ScanOptions, on_host=None, on_progress=None,
                 on_log=None) -> None:
        self.targets = targets
        self.opt = options
        self.on_host = on_host
        self.on_progress = on_progress
        self.on_log = on_log or (lambda m: None)
        self.stop = threading.Event()
        self.oui = get_db()
        self._local_nets = [i.network for i in interfaces()]
        self._local_ips = {i.ip: i for i in interfaces()}

    def _is_local(self, ip: str) -> bool:
        a = ipaddress.IPv4Address(ip)
        return any(a in n for n in self._local_nets)

    # -- étape 1 : l'hôte est-il actif ? ------------------------------------
    def _detect(self, ip: str) -> Host:
        h = Host(ip)
        if self.stop.is_set():
            return h
        if ip in self._local_ips:
            itf = self._local_ips[ip]
            h.alive, h.method, h.mac, h.rtt_ms = True, "Ce PC", itf.mac, 0.0
            return h
        local = self._is_local(ip)
        with ThreadPoolExecutor(max_workers=2) as ex:
            f_arp = ex.submit(arp.arp_request, ip) if local and arp.IS_WINDOWS else None
            r = icmp.ping(ip, timeout=self.opt.timeout)
            if r.alive:
                h.alive, h.method, h.rtt_ms, h.ttl = True, "ICMP", r.rtt_ms, r.ttl
            if f_arp is not None:
                mac = f_arp.result()
                if mac:
                    h.mac = mac
                    if not h.alive:
                        h.alive, h.method = True, "ARP"
        if not h.alive and self.opt.tcp_probe and not self.stop.is_set():
            for p in PROBE_PORTS:
                if self.stop.is_set():
                    break
                t0 = time.perf_counter()
                if tcp_open(ip, p, min(self.opt.timeout, 0.6)):
                    h.alive, h.method = True, f"TCP {p}"
                    h.rtt_ms = (time.perf_counter() - t0) * 1000
                    break
        return h

    # -- étape 2 : identification -------------------------------------------
    def _enrich(self, h: Host, arp_cache: dict[str, str]) -> Host:
        if not h.mac and self._is_local(h.ip):
            h.mac = arp_cache.get(h.ip) or arp.arp_table().get(h.ip, "")
        texts: list[str] = []
        if self.opt.resolve_names and not self.stop.is_set():
            name, nb = names.resolve_name(h.ip, timeout=min(1.0, self.opt.timeout))
            h.hostname = name
            if nb:
                h.workgroup = nb.get("workgroup", "")
                if not h.mac and nb.get("mac"):
                    h.mac = nb["mac"]
            texts.append(h.hostname)
        if self.opt.identify_ports and not self.stop.is_set():
            res = scan_ports(h.ip, IDENTIFY_PORTS, timeout=min(0.8, self.opt.timeout), workers=40,
                             banners=True, stop=self.stop)
            h.open_ports = [r.port for r in res]
            for r in res:
                if r.banner:
                    h.banners[r.port] = r.banner
                    texts.append(r.banner)
            for p, scheme in ((80, "http"), (443, "https"), (8080, "http"), (8443, "https"), (8000, "http")):
                if p in h.open_ports:
                    h.web_url = f"{scheme}://{h.ip}" + ("" if p in (80, 443) else f":{p}")
                    break
        h.vendor = self.oui.lookup(h.mac) if h.mac else ""
        h.os_guess = os_from_ttl(h.ttl)
        ident = identify(h.vendor, h.open_ports, texts, random_mac=bool(h.mac) and is_locally_administered(h.mac))
        h.category, h.brand, h.confidence, h.reasons = ident.label, ident.brand, ident.confidence, ident.reasons
        if h.method == "Ce PC":
            h.category = "💻 Ce PC"
        return h

    def run(self) -> list[Host]:
        total = len(self.targets)
        self.on_log(f"Détection des hôtes actifs sur {total} adresse(s)…")
        alive: list[Host] = []
        done = 0
        with ThreadPoolExecutor(max_workers=self.opt.workers) as ex:
            futs = {ex.submit(self._detect, ip): ip for ip in self.targets}
            for f in as_completed(futs):
                done += 1
                h = f.result()
                if h.alive:
                    alive.append(h)
                    if self.on_host:
                        self.on_host(h)
                elif self.opt.show_dead and self.on_host:
                    self.on_host(h)
                if self.on_progress:
                    self.on_progress(done, total * 2 if self.opt.resolve_names or self.opt.identify_ports else total)
                if self.stop.is_set():
                    for x in futs:
                        x.cancel()
                    break
        if self.stop.is_set():
            return alive
        self.on_log(f"{len(alive)} hôte(s) actif(s). Identification des équipements…")
        cache = arp.arp_table()
        done2 = 0
        with ThreadPoolExecutor(max_workers=min(32, max(1, len(alive)))) as ex:
            futs = [ex.submit(self._enrich, h, cache) for h in alive]
            for f in as_completed(futs):
                done2 += 1
                h = f.result()
                if self.on_host:
                    self.on_host(h)
                if self.on_progress:
                    self.on_progress(total + int(done2 / max(1, len(alive)) * total), total * 2)
                if self.stop.is_set():
                    break
        if self.on_progress:
            self.on_progress(1, 1)
        alive.sort(key=lambda x: ipaddress.IPv4Address(x.ip))
        return alive


def traceroute(host: str, max_hops: int = 30, timeout: float = 1.0, probes: int = 3,
               resolve: bool = True, stop: threading.Event | None = None, on_hop=None) -> list[dict]:
    """Traceroute ICMP (sans droits admin sous Windows)."""
    target = icmp.resolve(host)
    hops = []
    for ttl in range(1, max_hops + 1):
        if stop and stop.is_set():
            break
        rtts: list[str] = []
        addr = ""
        reached = False
        for _ in range(probes):
            r = icmp.ping(target, timeout=timeout, ttl=ttl)
            if r.status in (icmp.OK, icmp.TTL_EXPIRED) and r.reply_from:
                addr = addr or r.reply_from
                rtts.append(f"{r.rtt_ms:.0f} ms" if r.rtt_ms is not None else "?")
                reached = reached or r.status == icmp.OK
            else:
                rtts.append("*")
        hop = {"hop": ttl, "ip": addr or "*", "nom": names.reverse_dns(addr) if (resolve and addr) else "",
               "rtt": rtts, "atteint": reached}
        hops.append(hop)
        if on_hop:
            on_hop(hop)
        if reached or addr == target:
            break
    return hops
