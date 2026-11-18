"""Scan de ports TCP (connexion complète, sans droits admin) + lecture des bannières."""
from __future__ import annotations

import re
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .services import HTTP_PORTS, HTTPS_PORTS, RTSP_PORTS, service_name

_RE_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_RE_HEADER = re.compile(rb"^(Server|WWW-Authenticate|Location):\s*(.+?)\r?$", re.I | re.M)


@dataclass
class PortResult:
    port: int
    open: bool
    service: str = ""
    banner: str = ""
    extra: dict = field(default_factory=dict)


def tcp_open(ip: str, port: int, timeout: float = 0.8) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


def _recv_all(sock: socket.socket, limit: int = 16384) -> bytes:
    data = b""
    try:
        while len(data) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"</title>" in data.lower() or b"</head>" in data.lower():
                break
    except OSError:
        pass
    return data


def _summarize_http(raw: bytes) -> tuple[str, dict]:
    extra: dict = {}
    first = raw.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    for m in _RE_HEADER.finditer(raw):
        extra[m.group(1).decode().lower()] = m.group(2).decode("latin-1", errors="replace").strip()
    t = _RE_TITLE.search(raw)
    if t:
        title = re.sub(r"\s+", " ", t.group(1).decode("utf-8", errors="replace")).strip()
        extra["title"] = title[:120]
    parts = [first]
    if "server" in extra:
        parts.append(f"Server: {extra['server']}")
    if "title" in extra:
        parts.append(f"Titre: {extra['title']}")
    if "www-authenticate" in extra:
        parts.append(f"Auth: {extra['www-authenticate'][:60]}")
    return " | ".join(p for p in parts if p), extra


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> tuple[str, dict]:
    try:
        if port in HTTPS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=ip) as s:
                    s.settimeout(timeout)
                    cert_cn = ""
                    try:
                        der = s.getpeercert(binary_form=True)
                        if der:
                            m = re.search(rb"\x06\x03\x55\x04\x03.{2}([\x20-\x7e]{2,64})", der)
                            if m:
                                cert_cn = m.group(1).decode()
                    except (ssl.SSLError, ValueError):
                        pass
                    s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: ReseauScope\r\n\r\n".encode())
                    banner, extra = _summarize_http(_recv_all(s))
                    if cert_cn:
                        extra["cert_cn"] = cert_cn
                        banner += f" | Certificat: {cert_cn}"
                    return banner, extra
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in HTTP_PORTS:
                s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: ReseauScope\r\n\r\n".encode())
                raw = _recv_all(s)
                if raw.startswith(b"HTTP/"):
                    return _summarize_http(raw)
                return raw[:120].decode("latin-1", errors="replace").strip(), {}
            if port in RTSP_PORTS:
                s.sendall(f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: ReseauScope\r\n\r\n".encode())
                raw = _recv_all(s, 4096)
                text = raw.decode("latin-1", errors="replace")
                server = re.search(r"^Server:\s*(.+?)\r?$", text, re.I | re.M)
                first = text.split("\r\n", 1)[0]
                extra = {"server": server.group(1).strip()} if server else {}
                return (first + (f" | Server: {extra['server']}" if extra else "")).strip(), extra
            # Services qui parlent en premier (SSH, FTP, SMTP, Telnet, MySQL…)
            try:
                data = s.recv(1024)
            except OSError:
                data = b""
            text = data.decode("latin-1", errors="replace")
            text = "".join(c if c.isprintable() else " " for c in text)
            return re.sub(r"\s+", " ", text).strip()[:160], {}
    except (OSError, ssl.SSLError):
        return "", {}


def scan_ports(ip: str, ports: list[int], timeout: float = 0.8, workers: int = 200,
               banners: bool = True, stop: threading.Event | None = None,
               on_result=None, on_progress=None) -> list[PortResult]:
    """Scanne les ports ; appelle on_result(PortResult) pour chaque port ouvert."""
    results: list[PortResult] = []
    done = 0
    total = len(ports)

    def task(port: int) -> PortResult | None:
        if stop and stop.is_set():
            return None
        if not tcp_open(ip, port, timeout):
            return None
        res = PortResult(port, True, service_name(port))
        if banners and not (stop and stop.is_set()):
            res.banner, res.extra = grab_banner(ip, port, max(1.5, timeout * 2))
        return res

    with ThreadPoolExecutor(max_workers=max(1, min(workers, total or 1))) as ex:
        futures = [ex.submit(task, p) for p in ports]
        for fut in as_completed(futures):
            done += 1
            r = fut.result()
            if r:
                results.append(r)
                if on_result:
                    on_result(r)
            if on_progress and (done % 25 == 0 or done == total):
                on_progress(done, total)
            if stop and stop.is_set():
                for f in futures:
                    f.cancel()
                break
    results.sort(key=lambda r: r.port)
    return results
