"""Onglet Traceroute."""
from __future__ import annotations

from PySide6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QSpinBox,
                               QVBoxLayout, QWidget)

from ..core import scanner
from .widgets import Bridge, ResultTable

COLS = ["Saut", "Adresse IP", "Nom", "Temps 1", "Temps 2", "Temps 3"]


class TraceTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.bridge = Bridge()
        self._stop = None
        self._build()
        self.bridge.item.connect(self._on_hop)
        self.bridge.finished.connect(self._done)
        self.bridge.failed.connect(self._failed)

    def _build(self):
        root = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.host = QLineEdit(); self.host.setPlaceholderText("Destination (IP ou nom, ex. : 8.8.8.8)")
        self.host.returnPressed.connect(self.start)
        self.max_hops = QSpinBox(); self.max_hops.setRange(1, 64); self.max_hops.setValue(30)
        self.max_hops.setPrefix("max ")
        self.btn = QPushButton("▶  Tracer"); self.btn.clicked.connect(self.start)
        bar.addWidget(QLabel("Destination :")); bar.addWidget(self.host, 2)
        bar.addWidget(QLabel("Sauts :")); bar.addWidget(self.max_hops); bar.addWidget(self.btn)
        root.addLayout(bar)
        self.table = ResultTable(COLS); root.addWidget(self.table, 1)
        self.status = QLabel("Prêt."); root.addWidget(self.status)

    def start(self):
        import threading
        host = self.host.text().strip()
        if not host:
            return
        if self._stop:
            self._stop.set()
        self.table.clear_rows()
        self._stop = threading.Event()
        self.btn.setEnabled(False)
        self.status.setText(f"Traceroute vers {host} …")

        def work():
            return scanner.traceroute(host, max_hops=self.max_hops.value(), stop=self._stop,
                                      on_hop=self.bridge.item.emit)
        from .widgets import run_in_thread
        run_in_thread(work, self.bridge)

    def _on_hop(self, hop):
        rtts = hop["rtt"] + ["", "", ""]
        self.table.add_row([hop["hop"], hop["ip"], hop["nom"], rtts[0], rtts[1], rtts[2]],
                           [hop["hop"], hop["ip"], hop["nom"], None, None, None])

    def _done(self, hops):
        self.btn.setEnabled(True)
        if hops and hops[-1].get("atteint"):
            self.status.setText(f"Destination atteinte en {hops[-1]['hop']} saut(s).")
        else:
            self.status.setText("Traceroute terminé (destination non atteinte).")
        self.table.resizeColumnsToContents()

    def _failed(self, msg):
        self.btn.setEnabled(True)
        QMessageBox.warning(self, "Traceroute", msg)
        self.status.setText("Échec : " + msg)

    def set_host(self, ip):
        self.host.setText(ip)
