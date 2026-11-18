"""Base de fabricants MAC (OUI IEEE : MA-L 24 bits, MA-M 28 bits, MA-S 36 bits).

Ordre de priorité des sources :
  1. Fichier perso de l'utilisateur  (%APPDATA%/ReseauScope/oui_perso.csv)  "PREFIXE;Libellé"
  2. Base téléchargée depuis l'IEEE    (%APPDATA%/ReseauScope/oui_ieee.tsv.gz)
  3. Base embarquée dans l'exécutable  (data/oui.tsv.gz)
"""
from __future__ import annotations

import csv
import gzip
import io
import os
import re
import sys
import threading
import urllib.request

_HEX = re.compile(r"[^0-9A-F]")

IEEE_URLS = [
    "https://standards-oui.ieee.org/oui/oui.csv",        # MA-L
    "https://standards-oui.ieee.org/oui28/mam.csv",      # MA-M
    "https://standards-oui.ieee.org/oui36/oui36.csv",    # MA-S
]


def resource_path(*parts: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, *parts)


def user_dir() -> str:
    root = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    path = os.path.join(root, "ReseauScope")
    os.makedirs(path, exist_ok=True)
    return path


def normalize_mac(mac: str | None) -> str:
    """Retourne la MAC au format AA:BB:CC:DD:EE:FF (ou '' si invalide)."""
    if not mac:
        return ""
    h = _HEX.sub("", mac.upper())
    if len(h) != 12 or h in ("000000000000", "FFFFFFFFFFFF"):
        return ""
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def is_locally_administered(mac: str) -> bool:
    """Bit 'administré localement' : MAC aléatoire (téléphones, Windows/Android privés) ou virtuelle."""
    h = _HEX.sub("", (mac or "").upper())
    return len(h) >= 2 and bool(int(h[:2], 16) & 0x02)


class OuiDatabase:
    def __init__(self) -> None:
        self._db: dict[str, str] = {}
        self._custom: dict[str, str] = {}
        self._lock = threading.Lock()
        self.source = ""
        self.load()

    # -- chargement -------------------------------------------------------
    def load(self) -> None:
        db: dict[str, str] = {}
        ieee = os.path.join(user_dir(), "oui_ieee.tsv.gz")
        bundled = resource_path("data", "oui.tsv.gz")
        for path, label in ((bundled, "embarquée"), (ieee, "IEEE à jour")):
            if os.path.exists(path):
                try:
                    with gzip.open(path, "rt", encoding="utf-8") as f:
                        for line in f:
                            k, _, v = line.rstrip("\n").partition("\t")
                            if k and v:
                                db[k] = v
                    self.source = label
                except OSError:
                    pass
        custom = self._load_custom()
        with self._lock:
            self._db, self._custom = db, custom

    def _load_custom(self) -> dict[str, str]:
        path = self.custom_path()
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write("# Préfixes MAC personnalisés : PREFIXE;Libellé  (6, 7 ou 9 caractères hexa, ou MAC complète)\n"
                        "# Exemple :\n# 001122;Caméra entrepôt client X\n")
            return {}
        out = {}
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                k, _, v = line.partition(";")
                k = _HEX.sub("", k.upper())
                if k and v.strip():
                    out[k] = v.strip()
        return out

    @staticmethod
    def custom_path() -> str:
        return os.path.join(user_dir(), "oui_perso.csv")

    def __len__(self) -> int:
        return len(self._db)

    # -- recherche --------------------------------------------------------
    def lookup(self, mac: str | None) -> str:
        h = _HEX.sub("", (mac or "").upper())
        if len(h) != 12:
            return ""
        with self._lock:
            for n in (12, 9, 7, 6):
                if h[:n] in self._custom:
                    return self._custom[h[:n]]
            for n in (9, 7, 6):
                v = self._db.get(h[:n])
                if v:
                    return v
        if is_locally_administered(h):
            return "(MAC aléatoire / locale)"
        return ""

    # -- mise à jour depuis l'IEEE ----------------------------------------
    def update_from_ieee(self, progress=None) -> int:
        db: dict[str, str] = {}
        for url in IEEE_URLS:
            if progress:
                progress(f"Téléchargement {url} …")
            req = urllib.request.Request(url, headers={"User-Agent": "ReseauScope/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            for row in csv.reader(io.StringIO(text)):
                if len(row) >= 3 and row[0] != "Registry":
                    k = _HEX.sub("", row[1].upper())
                    if k:
                        db[k] = row[2].strip()
        if len(db) < 10000:
            raise RuntimeError("Base IEEE incomplète, mise à jour annulée")
        path = os.path.join(user_dir(), "oui_ieee.tsv.gz")
        with gzip.open(path, "wt", encoding="utf-8") as f:
            for k in sorted(db):
                f.write(f"{k}\t{db[k]}\n")
        self.load()
        return len(db)


_instance: OuiDatabase | None = None


def get_db() -> OuiDatabase:
    global _instance
    if _instance is None:
        _instance = OuiDatabase()
    return _instance
