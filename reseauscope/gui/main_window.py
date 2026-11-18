"""Fenêtre principale de ReseauScope."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import QApplication, QMainWindow, QMessageBox, QTabWidget

from .. import __version__
from .tab_ping import PingTab
from .tab_ports import PortsTab
from .tab_scan import ScanTab
from .tab_tools import ToolsTab
from .tab_trace import TraceTab

APP_NAME = "ReseauScope"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {__version__} — inventaire et diagnostic réseau")
        self.resize(1180, 720)
        self.tabs = QTabWidget()
        self.scan = ScanTab(); self.ping = PingTab(); self.trace = TraceTab()
        self.ports = PortsTab(); self.tools = ToolsTab()
        self.tabs.addTab(self.scan, "🔍  Scan réseau")
        self.tabs.addTab(self.ports, "🔌  Scan de ports")
        self.tabs.addTab(self.ping, "📶  Ping")
        self.tabs.addTab(self.trace, "🛰  Traceroute")
        self.tabs.addTab(self.tools, "🧰  Outils")
        self.setCentralWidget(self.tabs)
        self.statusBar().showMessage("Prêt. Scannez votre réseau pour inventorier caméras, accès et équipements.")
        self._menu()

    def _menu(self):
        m = self.menuBar().addMenu("&Fichier")
        act_exp = QAction("Exporter l'inventaire…", self)
        act_exp.setShortcut(QKeySequence.Save)
        act_exp.triggered.connect(self.scan.export)
        m.addAction(act_exp)
        m.addSeparator()
        act_quit = QAction("Quitter", self); act_quit.setShortcut("Ctrl+Q")
        act_quit.triggered.connect(self.close)
        m.addAction(act_quit)

        h = self.menuBar().addMenu("&Aide")
        act_about = QAction("À propos", self); act_about.triggered.connect(self._about)
        h.addAction(act_about)
        act_legal = QAction("Usage et responsabilité", self); act_legal.triggered.connect(self._legal)
        h.addAction(act_legal)

    def open_portscan(self, ip: str):
        self.ports.set_host(ip)
        self.tabs.setCurrentWidget(self.ports)
        self.ports.start()

    def open_ping(self, ip: str):
        self.ping.set_host(ip)
        self.tabs.setCurrentWidget(self.ping)

    def _about(self):
        QMessageBox.about(self, "À propos de " + APP_NAME,
                          f"<h3>{APP_NAME} {__version__}</h3>"
                          "<p>Utilitaire d'inventaire et de diagnostic réseau pour installateurs "
                          "de caméras, contrôle d'accès, alarme et domotique.</p>"
                          "<p>Scan d'IP, ping, traceroute, scan de ports, identification d'équipements "
                          "par fabricant (MAC/OUI) et par ports ouverts.</p>"
                          "<p>Fonctionne sans droits administrateur.</p>")

    def _legal(self):
        QMessageBox.information(self, "Usage et responsabilité",
                               "Cet outil est destiné à l'analyse de réseaux dont vous êtes "
                               "responsable ou pour lesquels vous disposez d'une autorisation écrite "
                               "(vos propres réseaux ou ceux de vos clients).\n\n"
                               "L'analyse de réseaux tiers sans autorisation peut être illégale. "
                               "Vous êtes seul responsable de l'usage de ce logiciel.")
