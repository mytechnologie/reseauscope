"""Onglet principal : scan et inventaire du réseau."""
from __future__ import annotations

import webbrowser

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor, QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
                               QLabel, QLineEdit, QMenu, QMessageBox, QProgressBar, QPushButton,
                               QSpinBox, QVBoxLayout, QWidget)

from ..core import netinfo
from ..core.classify import CATEGORY_ICONS
from ..core.scanner import Host, NetworkScanner, ScanOptions
from ..core.tools import export_csv, export_html, export_json, wake_on_lan
from .widgets import Bridge, ResultTable, ip_key, run_in_thread

COLS = ["IP", "État", "Type d'équipement", "Marque", "Fabricant (MAC)", "Nom d'hôte", "MAC",
        "Ports ouverts", "Latence", "OS probable", "Détection", "Confiance", "Indices"]
CAT_COLORS = {"Caméra / NVR": "#8250df", "Contrôle d'accès": "#bf3989", "Alarme / intrusion": "#cf222e",
              "Interphone / VoIP": "#9a6700", "Domotique / IoT": "#1a7f37", "Réseau (routeur, switch, Wi-Fi)": "#0969da",
              "Stockage (NAS)": "#6639ba", "Imprimante": "#656d76", "Automate / bâtiment": "#953800"}


class ScanTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner: NetworkScanner | None = None
        self.bridge = Bridge()
        self.row_by_ip: dict[str, int] = {}
        self.hosts: dict[str, Host] = {}
        self._build()
        self.bridge.item.connect(self._on_host)
        self.bridge.progress.connect(self._on_progress)
        self.bridge.log.connect(lambda m: self.status.setText(m))
        self.bridge.finished.connect(self._on_finished)
        self.bridge.failed.connect(self._on_failed)

    def _build(self):
        root = QVBoxLayout(self)
        cfg = QGroupBox("Cible et options")
        form = QHBoxLayout(cfg)

        left = QFormLayout()
        self.target = QLineEdit(netinfo.default_range())
        self.target.setToolTip("Ex. : 192.168.1.0/24  ·  192.168.1.10-50  ·  10.0.0.1,10.0.0.5")
        row = QHBoxLayout()
        row.addWidget(self.target)
        btn_local = QPushButton("Mon réseau")
        btn_local.clicked.connect(lambda: self.target.setText(netinfo.default_range()))
        row.addWidget(btn_local)
        w = QWidget(); w.setLayout(row)
        left.addRow("Plage à scanner :", w)

        self.timeout = QSpinBox(); self.timeout.setRange(200, 5000); self.timeout.setValue(1000)
        self.timeout.setSuffix(" ms"); self.timeout.setSingleStep(100)
        left.addRow("Délai d'attente :", self.timeout)
        self.workers = QSpinBox(); self.workers.setRange(1, 512); self.workers.setValue(128)
        left.addRow("Scans simultanés :", self.workers)
        form.addLayout(left, 2)

        right = QVBoxLayout()
        self.cb_names = QCheckBox("Résoudre les noms d'hôte (DNS / NetBIOS / mDNS)"); self.cb_names.setChecked(True)
        self.cb_ports = QCheckBox("Identifier via les ports ouverts (recommandé)"); self.cb_ports.setChecked(True)
        self.cb_tcp = QCheckBox("Détecter aussi par TCP (hôtes qui bloquent le ping)"); self.cb_tcp.setChecked(True)
        self.cb_dead = QCheckBox("Afficher aussi les adresses inactives")
        for cb in (self.cb_names, self.cb_ports, self.cb_tcp, self.cb_dead):
            right.addWidget(cb)
        form.addLayout(right, 3)
        root.addWidget(cfg)

        bar = QHBoxLayout()
        self.btn_scan = QPushButton("▶  Lancer le scan")
        self.btn_scan.clicked.connect(self.start)
        self.btn_stop = QPushButton("■  Arrêter"); self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop)
        self.filter = QLineEdit(); self.filter.setPlaceholderText("Filtrer (ex. : caméra, hikvision, 192.168.1.)")
        self.filter.textChanged.connect(lambda t: self.table.proxy.setFilterFixedString(t))
        self.cat_filter = QComboBox(); self.cat_filter.addItem("Tous les types")
        for c in CATEGORY_ICONS:
            self.cat_filter.addItem(f"{CATEGORY_ICONS[c]} {c}", c)
        self.cat_filter.currentIndexChanged.connect(self._apply_cat)
        bar.addWidget(self.btn_scan); bar.addWidget(self.btn_stop)
        bar.addWidget(self.filter, 2); bar.addWidget(self.cat_filter)
        self.btn_export = QPushButton("Exporter…"); self.btn_export.clicked.connect(self.export)
        bar.addWidget(self.btn_export)
        root.addLayout(bar)

        self.table = ResultTable(COLS)
        self.table.customContextMenuRequested.connect(self._menu)
        self.table.doubleClicked.connect(self._open_web)
        root.addWidget(self.table, 1)

        foot = QHBoxLayout()
        self.progress = QProgressBar(); self.progress.setTextVisible(True)
        self.status = QLabel("Prêt.")
        self.count = QLabel("")
        foot.addWidget(self.progress, 1); foot.addWidget(self.count); foot.addWidget(self.status, 2)
        root.addLayout(foot)

    # -- actions ----------------------------------------------------------
    def start(self):
        try:
            targets = netinfo.parse_targets(self.target.text())
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Cible invalide", str(exc)); return
        if not targets:
            QMessageBox.warning(self, "Cible invalide", "Aucune adresse à scanner."); return
        if len(targets) > 4096 and QMessageBox.question(
                self, "Grande plage", f"{len(targets)} adresses à scanner. Continuer ?") != QMessageBox.Yes:
            return
        self.table.clear_rows(); self.row_by_ip.clear(); self.hosts.clear()
        self.progress.setMaximum(0)
        opt = ScanOptions(timeout=self.timeout.value() / 1000, workers=self.workers.value(),
                          resolve_names=self.cb_names.isChecked(), identify_ports=self.cb_ports.isChecked(),
                          tcp_probe=self.cb_tcp.isChecked(), show_dead=self.cb_dead.isChecked())
        self.scanner = NetworkScanner(targets, opt, on_host=self.bridge.item.emit,
                                      on_progress=self.bridge.progress.emit, on_log=self.bridge.log.emit)
        self.btn_scan.setEnabled(False); self.btn_stop.setEnabled(True)
        run_in_thread(self.scanner.run, self.bridge)

    def stop(self):
        if self.scanner:
            self.scanner.stop.set()
            self.status.setText("Arrêt en cours…")

    def _on_host(self, h: Host):
        self.hosts[h.ip] = h
        vals = [h.ip, "● Actif" if h.alive else "○ Inactif", h.category or "—", h.brand,
                h.vendor, h.hostname, h.mac, ", ".join(map(str, h.open_ports)),
                f"{h.rtt_ms:.0f} ms" if h.rtt_ms is not None else "", h.os_guess, h.method,
                h.confidence, h.reasons]
        keys = [ip_key(h.ip), h.alive, h.category, h.brand, h.vendor, h.hostname, h.mac,
                len(h.open_ports), h.rtt_ms if h.rtt_ms is not None else -1, h.os_guess, h.method,
                {"Élevée": 3, "Moyenne": 2, "Faible": 1}.get(h.confidence, 0), h.reasons]
        if h.ip in self.row_by_ip:
            self.table.set_row(self.row_by_ip[h.ip], vals, keys)
            row = self.row_by_ip[h.ip]
        else:
            row = self.table.add_row(vals, keys)
            self.row_by_ip[h.ip] = row
        base = (h.category or "").split(" ", 1)[-1]
        col = CAT_COLORS.get(base)
        self.table.color_row(row, QColor(col) if col else (QColor("#8c959f") if not h.alive else None))
        self._update_count()

    def _update_count(self):
        active = sum(1 for h in self.hosts.values() if h.alive)
        cats: dict[str, int] = {}
        for h in self.hosts.values():
            if h.alive and h.category and "Ce PC" not in h.category:
                cats[h.category] = cats.get(h.category, 0) + 1
        top = sorted(cats.items(), key=lambda x: -x[1])[:4]
        extra = "  ·  " + "  ".join(f"{k.split(' ',1)[0]}{v}" for k, v in top) if top else ""
        self.count.setText(f"{active} actif(s){extra}")

    def _on_progress(self, done: int, total: int):
        if total > 0:
            self.progress.setMaximum(total); self.progress.setValue(done)

    def _on_finished(self, _hosts):
        self.btn_scan.setEnabled(True); self.btn_stop.setEnabled(False)
        self.progress.setMaximum(1); self.progress.setValue(1)
        self.status.setText(f"Scan terminé — {sum(1 for h in self.hosts.values() if h.alive)} hôte(s) actif(s).")
        self.table.resizeColumnsToContents()

    def _on_failed(self, msg):
        self.btn_scan.setEnabled(True); self.btn_stop.setEnabled(False)
        self.progress.setMaximum(1)
        QMessageBox.critical(self, "Erreur de scan", msg)

    def _apply_cat(self):
        cat = self.cat_filter.currentData()
        self.table.proxy.setFilterKeyColumn(-1 if not cat else 2)
        self.table.proxy.setFilterFixedString("" if not cat else cat)

    # -- menu contextuel --------------------------------------------------
    def _selected_hosts(self) -> list[Host]:
        out = []
        for r in self.table.selected_source_rows():
            ip = self.table.cell(r, 0)
            if ip in self.hosts:
                out.append(self.hosts[ip])
        return out

    def _menu(self, pos):
        hosts = self._selected_hosts()
        if not hosts:
            return
        m = QMenu(self)
        h = hosts[0]
        if h.web_url:
            a = QAction(f"Ouvrir {h.web_url}", self); a.triggered.connect(lambda: webbrowser.open(h.web_url)); m.addAction(a)
        a2 = QAction("Copier l'IP", self); a2.triggered.connect(lambda: QGuiApplication.clipboard().setText(h.ip)); m.addAction(a2)
        if h.mac:
            a3 = QAction("Copier la MAC", self); a3.triggered.connect(lambda: QGuiApplication.clipboard().setText(h.mac)); m.addAction(a3)
            a4 = QAction("Réveiller (Wake-on-LAN)", self); a4.triggered.connect(lambda: self._wol(h)); m.addAction(a4)
        a5 = QAction("Copier la ligne", self); a5.triggered.connect(lambda: self._copy_rows(hosts)); m.addAction(a5)
        a6 = QAction("Scanner tous les ports de cet hôte", self)
        a6.triggered.connect(lambda: self._to_portscan(h.ip)); m.addAction(a6)
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _wol(self, h: Host):
        try:
            wake_on_lan(h.mac)
            self.status.setText(f"Paquet Wake-on-LAN envoyé à {h.mac}.")
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Wake-on-LAN", str(exc))

    def _copy_rows(self, hosts):
        lines = ["\t".join(COLS)]
        for h in hosts:
            d = h.as_dict()
            lines.append("\t".join(str(d.get(k, "")) for k in
                                   ["ip", "etat", "type_equipement", "marque", "fabricant", "nom_hote",
                                    "mac", "ports_ouverts", "latence_ms", "os_probable", "detection",
                                    "confiance", "indices"]))
        QGuiApplication.clipboard().setText("\n".join(lines))
        self.status.setText("Copié dans le presse-papiers.")

    def _open_web(self, index):
        ip = self.table.cell(self.table.proxy.mapToSource(index).row(), 0)
        h = self.hosts.get(ip)
        if h and h.web_url:
            webbrowser.open(h.web_url)

    def _to_portscan(self, ip):
        mw = self.window()
        if hasattr(mw, "open_portscan"):
            mw.open_portscan(ip)

    def export(self):
        rows = [self.hosts[self.table.cell(self.table.proxy.mapToSource(self.table.proxy.index(r, 0)).row(), 0)].as_dict()
                for r in range(self.table.proxy.rowCount())
                if self.table.cell(self.table.proxy.mapToSource(self.table.proxy.index(r, 0)).row(), 0) in self.hosts]
        if not rows:
            QMessageBox.information(self, "Export", "Aucun résultat à exporter."); return
        path, flt = QFileDialog.getSaveFileName(self, "Exporter les résultats", "scan_reseau",
                                                "CSV (*.csv);;HTML (*.html);;JSON (*.json)")
        if not path:
            return
        try:
            meta = {"Plage scannée": self.target.text(), "Hôtes actifs": len(rows)}
            if path.endswith(".json") or "JSON" in flt:
                export_json(path, rows, meta)
            elif path.endswith(".html") or "HTML" in flt:
                export_html(path, rows, "ReseauScope — inventaire réseau", meta)
            else:
                export_csv(path, rows)
            self.status.setText(f"Exporté : {path}")
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "Export", str(exc))
