"""Onglet Outils : interfaces locales, calculateur de sous-réseau, recherche MAC, Wake-on-LAN, mise à jour OUI."""
from __future__ import annotations

from PySide6.QtWidgets import (QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
                               QPlainTextEdit, QPushButton, QVBoxLayout, QWidget)

from ..core import netinfo
from ..core.oui import get_db
from ..core.tools import subnet_info, wake_on_lan
from .widgets import Bridge, run_in_thread


class ToolsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.bridge = Bridge()
        self._build()
        self.bridge.finished.connect(self._update_done)
        self.bridge.failed.connect(lambda m: QMessageBox.warning(self, "Mise à jour OUI", m))
        self.bridge.log.connect(lambda m: self.oui_status.setText(m))

    def _build(self):
        root = QVBoxLayout(self)
        cols = QHBoxLayout(); root.addLayout(cols)
        left = QVBoxLayout(); right = QVBoxLayout()
        cols.addLayout(left, 1); cols.addLayout(right, 1)

        # Interfaces locales
        g_itf = QGroupBox("Interfaces réseau de ce PC")
        v = QVBoxLayout(g_itf)
        self.itf_view = QPlainTextEdit(readOnly=True)
        self.itf_view.setStyleSheet("font-family: Consolas, monospace;")
        v.addWidget(self.itf_view)
        self._refresh_itf()
        left.addWidget(g_itf)

        # Recherche MAC
        g_mac = QGroupBox("Rechercher un fabricant par MAC")
        f = QFormLayout(g_mac)
        self.mac_in = QLineEdit(); self.mac_in.setPlaceholderText("Ex. : 44:19:B6:12:34:56")
        self.mac_in.textChanged.connect(self._lookup_mac)
        self.mac_out = QLabel("—"); self.mac_out.setWordWrap(True)
        f.addRow("Adresse MAC :", self.mac_in)
        f.addRow("Fabricant :", self.mac_out)
        left.addWidget(g_mac)

        # Wake-on-LAN
        g_wol = QGroupBox("Wake-on-LAN (réveil d'un poste)")
        fw = QFormLayout(g_wol)
        self.wol_mac = QLineEdit(); self.wol_mac.setPlaceholderText("MAC de la carte réseau")
        self.wol_bcast = QLineEdit("255.255.255.255")
        btn_wol = QPushButton("Envoyer le paquet magique"); btn_wol.clicked.connect(self._send_wol)
        fw.addRow("MAC :", self.wol_mac)
        fw.addRow("Diffusion :", self.wol_bcast)
        fw.addRow(btn_wol)
        left.addWidget(g_wol)
        left.addStretch(1)

        # Calculateur de sous-réseau
        g_sub = QGroupBox("Calculateur de sous-réseau")
        fs = QFormLayout(g_sub)
        self.sub_in = QLineEdit("192.168.1.0/24")
        self.sub_in.textChanged.connect(self._calc_subnet)
        self.sub_out = QPlainTextEdit(readOnly=True)
        self.sub_out.setStyleSheet("font-family: Consolas, monospace;")
        fs.addRow("Réseau / masque :", self.sub_in)
        fs.addRow(self.sub_out)
        right.addWidget(g_sub, 1)
        self._calc_subnet()

        # Base OUI
        g_oui = QGroupBox("Base de fabricants (OUI)")
        vo = QVBoxLayout(g_oui)
        db = get_db()
        self.oui_status = QLabel(f"{len(db)} préfixes chargés — source : {db.source}")
        self.oui_status.setWordWrap(True)
        btn_up = QPushButton("Mettre à jour depuis l'IEEE (internet)")
        btn_up.clicked.connect(self._update_oui)
        self.btn_up = btn_up
        btn_custom = QPushButton("Ouvrir le fichier de préfixes personnalisés")
        btn_custom.clicked.connect(self._open_custom)
        vo.addWidget(self.oui_status); vo.addWidget(btn_up); vo.addWidget(btn_custom)
        lbl = QLabel("Astuce : ajoutez vos propres préfixes (parc client) dans le fichier perso, "
                     "au format <code>PREFIXE;Libellé</code>.")
        lbl.setWordWrap(True); vo.addWidget(lbl)
        right.addWidget(g_oui)

    def _refresh_itf(self):
        lines = []
        gw = netinfo.default_gateway()
        dns = ", ".join(netinfo.dns_servers())
        for i in netinfo.interfaces():
            lines.append(f"{i.name}\n  IP     : {i.ip}  ({i.cidr})\n  Masque : {i.netmask}\n"
                         f"  MAC    : {i.mac}\n  Débit  : {i.speed or '?'} Mb/s")
        lines.append(f"\nPasserelle : {gw}\nDNS        : {dns}")
        self.itf_view.setPlainText("\n".join(lines) or "Aucune interface active détectée.")

    def _lookup_mac(self, text):
        v = get_db().lookup(text)
        self.mac_out.setText(v or "Aucun fabricant trouvé (préfixe inconnu ou MAC incomplète).")

    def _send_wol(self):
        try:
            wake_on_lan(self.wol_mac.text(), self.wol_bcast.text() or "255.255.255.255")
            QMessageBox.information(self, "Wake-on-LAN", "Paquet magique envoyé.")
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Wake-on-LAN", str(exc))

    def _calc_subnet(self):
        try:
            rows = subnet_info(self.sub_in.text())
            width = max(len(k) for k, _ in rows)
            self.sub_out.setPlainText("\n".join(f"{k.ljust(width)} : {v}" for k, v in rows))
        except (ValueError, Exception) as exc:  # noqa: BLE001
            self.sub_out.setPlainText(f"Entrée invalide : {exc}")

    def _update_oui(self):
        self.btn_up.setEnabled(False)
        self.oui_status.setText("Mise à jour en cours…")

        def work():
            return get_db().update_from_ieee(progress=self.bridge.log.emit)
        run_in_thread(work, self.bridge)

    def _update_done(self, n):
        self.btn_up.setEnabled(True)
        db = get_db()
        self.oui_status.setText(f"Mise à jour terminée : {n} préfixes — source : {db.source}")

    def _open_custom(self):
        import os
        import subprocess
        import sys
        path = get_db().custom_path()
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # noqa: S606
            elif sys.platform == "darwin":
                subprocess.run(["open", path])
            else:
                subprocess.run(["xdg-open", path])
        except OSError as exc:
            QMessageBox.information(self, "Fichier personnalisé", f"{path}\n\n{exc}")
