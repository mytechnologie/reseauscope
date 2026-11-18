"""Outils divers : Wake-on-LAN, calculateur IP, exports."""
from __future__ import annotations

import csv
import html
import ipaddress
import json
import socket
from datetime import datetime

from .oui import normalize_mac


def wake_on_lan(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> None:
    m = normalize_mac(mac)
    if not m:
        raise ValueError("Adresse MAC invalide")
    payload = b"\xff" * 6 + bytes.fromhex(m.replace(":", "")) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(payload, (broadcast, port))


def subnet_info(text: str) -> list[tuple[str, str]]:
    net = ipaddress.IPv4Interface(text.strip()).network if "/" in text else ipaddress.IPv4Network(
        text.strip() + "/24", strict=False)
    iface = ipaddress.IPv4Interface(text.strip() if "/" in text else text.strip() + "/24")
    hosts = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
    first = net.network_address + 1 if net.prefixlen < 31 else net.network_address
    last = net.broadcast_address - 1 if net.prefixlen < 31 else net.broadcast_address
    wildcard = ipaddress.IPv4Address(int(net.hostmask))
    return [
        ("Adresse", str(iface.ip)),
        ("Réseau", f"{net.network_address}/{net.prefixlen}"),
        ("Masque", str(net.netmask)),
        ("Masque inverse (wildcard)", str(wildcard)),
        ("Diffusion (broadcast)", str(net.broadcast_address)),
        ("Première adresse utilisable", str(first)),
        ("Dernière adresse utilisable", str(last)),
        ("Nombre d'hôtes", f"{hosts:,}".replace(",", " ")),
        ("Type", "Privée" if net.is_private else "Publique"),
        ("Binaire (masque)", ".".join(f"{int(o):08b}" for o in str(net.netmask).split("."))),
    ]


def export_csv(path: str, rows: list[dict]) -> None:
    if not rows:
        raise ValueError("Aucun résultat à exporter")
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), delimiter=";")
        w.writeheader()
        w.writerows(rows)


def export_json(path: str, rows: list[dict], meta: dict | None = None) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"genere_le": datetime.now().isoformat(timespec="seconds"), **(meta or {}),
                   "resultats": rows}, f, ensure_ascii=False, indent=2)


def export_html(path: str, rows: list[dict], title: str, meta: dict | None = None) -> None:
    if not rows:
        raise ValueError("Aucun résultat à exporter")
    cols = list(rows[0].keys())
    head = "".join(f"<th>{html.escape(c.replace('_', ' ').capitalize())}</th>" for c in cols)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(r.get(c, '')))}</td>" for c in cols) + "</tr>"
                   for r in rows)
    info = "".join(f"<li><b>{html.escape(k)}</b> : {html.escape(str(v))}</li>" for k, v in (meta or {}).items())
    doc = f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1f24}}h1{{font-size:20px}}
table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{border:1px solid #d0d7de;padding:4px 6px;text-align:left}}
th{{background:#0b3d63;color:#fff;position:sticky;top:0}}tr:nth-child(even){{background:#f3f6f9}}ul{{font-size:13px}}</style>
</head><body><h1>{html.escape(title)}</h1><ul><li><b>Généré le</b> : {datetime.now():%Y-%m-%d %H:%M}</li>{info}</ul>
<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
