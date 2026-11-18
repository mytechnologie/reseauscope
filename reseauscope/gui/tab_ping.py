"""Onglet Ping continu (surveillance d'un hôte)."""
from __future__ import annotations

import threading
import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QSpinBox,
                               QVBoxLayout, QWidget)

from ..core import icmp
from .widgets import Bridge, Sparkline


class PingTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.bridge = Bridge()
        self.stop_evt: threading.Event | None = None
        self.sent = self.recv = 0
        self.rtts: list[float] = []
        self._build()
        self.bridge.item.connect(self._on_reply)
        self.bridge.failed.connect(lambda m: self.log.appendPlainText("Erreur : " + m))

    def _build(self):
        root = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.host = QLineEdit(); self.host.setPlaceholderText("Adresse IP ou nom d'hôte (ex. : 192.168.1.1)")
        self.host.returnPressed.connect(self.toggle)
        self.interval = QSpinBox(); self.interval.setRange(100, 10000); self.interval.setValue(1000)
        self.interval.setSuffix(" ms"); self.interval.setSingleStep(100)
        self.count = QSpinBox(); self.count.setRange(0, 100000); self.count.setValue(0)
        self.count.setSpecialValueText("∞"); self.count.setPrefix("n = ")
        self.btn = QPushButton("▶  Démarrer"); self.btn.clicked.connect(self.toggle)
        bar.addWidget(QLabel("Hôte :")); bar.addWidget(self.host, 2)
        bar.addWidget(QLabel("Intervalle :")); bar.addWidget(self.interval)
        bar.addWidget(QLabel("Nombre :")); bar.addWidget(self.count)
        bar.addWidget(self.btn)
        root.addLayout(bar)

        self.spark = Sparkline(); root.addWidget(self.spark)
        self.stats = QLabel("—"); root.addWidget(self.stats)
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        self.log.setStyleSheet("font-family: Consolas, monospace;")
        root.addWidget(self.log, 1)

    def toggle(self):
        if self.stop_evt:
            self.stop_evt.set(); self.stop_evt = None
            self.btn.setText("▶  Démarrer"); return
        host = self.host.text().strip()
        if not host:
            return
        self.sent = self.recv = 0; self.rtts = []
        self.spark.reset(); self.log.clear()
        self.log.appendPlainText(f"Ping de {host} …")
        self.stop_evt = threading.Event()
        self.btn.setText("■  Arrêter")
        threading.Thread(target=self._loop, args=(host, self.stop_evt), daemon=True).start()

    def _loop(self, host, stop):
        limit = self.count.value()
        i = 0
        while not stop.is_set():
            r = icmp.ping(host, timeout=self.interval.value() / 1000 + 0.5)
            self.bridge.item.emit(r)
            i += 1
            if limit and i >= limit:
                break
            stop.wait(self.interval.value() / 1000)
        self.bridge.item.emit("__fin__")

    def _on_reply(self, r):
        if r == "__fin__":
            self.btn.setText("▶  Démarrer"); self.stop_evt = None
            self.log.appendPlainText("— terminé —"); return
        self.sent += 1
        if r.alive:
            self.recv += 1
            self.rtts.append(r.rtt_ms)
            self.spark.push(r.rtt_ms)
            self.log.appendPlainText(f"Réponse de {r.reply_from}  temps={r.rtt_ms:.0f} ms  TTL={r.ttl}")
        else:
            self.spark.push(None)
            label = {"timeout": "Délai dépassé", "unreachable": "Inaccessible",
                     "error": r.detail or "Erreur"}.get(r.status, r.status)
            self.log.appendPlainText(f"{label}" + (f"  (depuis {r.reply_from})" if r.reply_from else ""))
        loss = 100 * (self.sent - self.recv) / self.sent if self.sent else 0
        if self.rtts:
            self.stats.setText(f"Envoyés {self.sent} · Reçus {self.recv} · Perte {loss:.0f} %   |   "
                               f"min {min(self.rtts):.0f} / moy {sum(self.rtts)/len(self.rtts):.0f} / "
                               f"max {max(self.rtts):.0f} ms")
        else:
            self.stats.setText(f"Envoyés {self.sent} · Reçus {self.recv} · Perte {loss:.0f} %")

    def set_host(self, ip: str):
        self.host.setText(ip)
