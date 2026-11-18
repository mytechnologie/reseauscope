"""Onglet Scan de ports d'un hôte unique."""
from __future__ import annotations

import threading

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QProgressBar,
                               QPushButton, QVBoxLayout, QWidget)

from ..core import icmp
from ..core.classify import identify
from ..core.oui import get_db
from ..core.portscan import PortResult, scan_ports
from ..core.services import PRESETS, parse_ports, preset_ports
from .widgets import Bridge, ResultTable

COLS = ["Port", "État", "Service", "Détails / bannière"]


class PortsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.bridge = Bridge()
        self._stop: threading.Event | None = None
        self._texts: list[str] = []
        self._ports: list[int] = []
        self._build()
        self.bridge.item.connect(self._on_port)
        self.bridge.progress.connect(lambda d, t: (self.progress.setMaximum(t), self.progress.setValue(d)))
        self.bridge.finished.connect(self._done)
        self.bridge.failed.connect(self._failed)

    def _build(self):
        root = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.host = QLineEdit(); self.host.setPlaceholderText("IP ou nom d'hôte")
        self.host.returnPressed.connect(self.start)
        self.preset = QComboBox()
        for name in PRESETS:
            self.preset.addItem(name)
        self.preset.currentTextChanged.connect(self._fill_ports)
        self.ports = QLineEdit(); self.ports.setToolTip("Ex. : 22,80,443,8000-8100")
        self.btn = QPushButton("▶  Scanner"); self.btn.clicked.connect(self.start)
        bar.addWidget(QLabel("Hôte :")); bar.addWidget(self.host, 2)
        bar.addWidget(QLabel("Préréglage :")); bar.addWidget(self.preset)
        root.addLayout(bar)
        bar2 = QHBoxLayout()
        bar2.addWidget(QLabel("Ports :")); bar2.addWidget(self.ports, 3); bar2.addWidget(self.btn)
        root.addLayout(bar2)
        self._fill_ports(self.preset.currentText())

        self.table = ResultTable(COLS); root.addWidget(self.table, 1)
        foot = QHBoxLayout()
        self.progress = QProgressBar()
        self.ident = QLabel(""); self.status = QLabel("Prêt.")
        foot.addWidget(self.progress, 1); foot.addWidget(self.ident, 1); foot.addWidget(self.status, 1)
        root.addLayout(foot)

    def _fill_ports(self, name):
        try:
            self.ports.setText(",".join(map(str, preset_ports(name))) if "65535" not in name else "1-65535")
        except KeyError:
            pass

    def start(self):
        host = self.host.text().strip()
        if not host:
            return
        try:
            ip = icmp.resolve(host)
            self._ports = parse_ports(self.ports.text())
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Entrée invalide", str(exc)); return
        if not self._ports:
            QMessageBox.warning(self, "Ports", "Indiquez au moins un port."); return
        self.table.clear_rows(); self._texts = []
        self.ident.setText(""); self._stop = threading.Event()
        self.btn.setEnabled(False)
        self.status.setText(f"Scan de {len(self._ports)} port(s) sur {ip} …")

        def work():
            return scan_ports(ip, self._ports, timeout=0.8, workers=200, banners=True,
                              stop=self._stop, on_result=self.bridge.item.emit,
                              on_progress=self.bridge.progress.emit)
        from .widgets import run_in_thread
        run_in_thread(work, self.bridge)

    def _on_port(self, r: PortResult):
        self.table.add_row([r.port, "● Ouvert", r.service, r.banner],
                           [r.port, True, r.service, r.banner])
        if r.banner:
            self._texts.append(r.banner)

    def _done(self, results):
        self.btn.setEnabled(True)
        self.progress.setValue(self.progress.maximum())
        opened = len(results)
        self.status.setText(f"Terminé — {opened} port(s) ouvert(s) sur {len(self._ports)} testé(s).")
        self.table.resizeColumnsToContents()
        ports = [r.port for r in results]
        mac = get_db().lookup("")  # pas de MAC ici (hôte distant)
        ident = identify("", ports, self._texts)
        if ident.category:
            self.ident.setText(f"Équipement probable : {ident.label}  ({ident.confidence}) — {ident.reasons}")

    def _failed(self, msg):
        self.btn.setEnabled(True)
        QMessageBox.warning(self, "Scan de ports", msg)

    def set_host(self, ip):
        self.host.setText(ip)
