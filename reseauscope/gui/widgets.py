"""Widgets et utilitaires communs à l'interface."""
from __future__ import annotations

import threading
import traceback

from PySide6.QtCore import QObject, QSortFilterProxyModel, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPen, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QHeaderView, QTableView, QWidget


class Bridge(QObject):
    """Relaye des événements d'un thread de travail vers l'interface (signaux mis en file)."""
    item = Signal(object)
    progress = Signal(int, int)
    log = Signal(str)
    finished = Signal(object)
    failed = Signal(str)


def run_in_thread(target, bridge: Bridge, *args, **kwargs) -> threading.Thread:
    def wrapper():
        try:
            bridge.finished.emit(target(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001 - on remonte toute erreur à l'interface
            traceback.print_exc()
            bridge.failed.emit(str(exc))
    t = threading.Thread(target=wrapper, daemon=True)
    t.start()
    return t


class NumericItem(QStandardItem):
    """Cellule triée numériquement (IP, ports, latence)."""

    def __init__(self, text: str, sort_key=None):
        super().__init__(text)
        self.setData(sort_key if sort_key is not None else text, Qt.UserRole + 1)
        self.setEditable(False)


def ip_key(ip: str) -> int:
    try:
        a, b, c, d = (int(x) for x in ip.split("."))
        return (a << 24) | (b << 16) | (c << 8) | d
    except ValueError:
        return 0


class ResultTable(QTableView):
    def __init__(self, headers: list[str], parent=None):
        super().__init__(parent)
        self.model_ = QStandardItemModel(0, len(headers), self)
        self.model_.setHorizontalHeaderLabels(headers)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model_)
        self.proxy.setSortRole(Qt.UserRole + 1)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.setModel(self.proxy)
        self.setSortingEnabled(True)
        self.setSelectionBehavior(QTableView.SelectRows)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.horizontalHeader().setStretchLastSection(True)
        self.setContextMenuPolicy(Qt.CustomContextMenu)

    def clear_rows(self):
        self.model_.removeRows(0, self.model_.rowCount())

    def add_row(self, values: list, keys: list | None = None) -> int:
        items = []
        for i, v in enumerate(values):
            key = keys[i] if keys and i < len(keys) and keys[i] is not None else str(v)
            items.append(NumericItem("" if v is None else str(v), key))
        self.model_.appendRow(items)
        return self.model_.rowCount() - 1

    def set_row(self, row: int, values: list, keys: list | None = None):
        for i, v in enumerate(values):
            it = self.model_.item(row, i)
            it.setText("" if v is None else str(v))
            key = keys[i] if keys and i < len(keys) and keys[i] is not None else str(v)
            it.setData(key, Qt.UserRole + 1)

    def color_row(self, row: int, color: QColor | None):
        for c in range(self.model_.columnCount()):
            it = self.model_.item(row, c)
            if it:
                it.setForeground(color if color else QColor())

    def selected_source_rows(self) -> list[int]:
        rows = {self.proxy.mapToSource(i).row() for i in self.selectionModel().selectedRows()}
        return sorted(rows)

    def cell(self, row: int, col: int) -> str:
        it = self.model_.item(row, col)
        return it.text() if it else ""

    def visible_rows_as_dicts(self) -> list[dict]:
        headers = [self.model_.headerData(c, Qt.Horizontal) for c in range(self.model_.columnCount())]
        out = []
        for r in range(self.proxy.rowCount()):
            src = self.proxy.mapToSource(self.proxy.index(r, 0)).row()
            out.append({h: self.cell(src, c) for c, h in enumerate(headers)})
        return out


class Sparkline(QWidget):
    """Petit graphe de latence pour l'onglet Ping."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.values: list[float | None] = []
        self.setMinimumHeight(90)

    def push(self, v: float | None):
        self.values.append(v)
        self.values = self.values[-120:]
        self.update()

    def reset(self):
        self.values = []
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect().adjusted(6, 6, -6, -6)
        p.fillRect(self.rect(), self.palette().base())
        vals = [v for v in self.values if v is not None]
        if not self.values:
            p.setPen(self.palette().text().color())
            p.drawText(r, Qt.AlignCenter, "Latence (ms)")
            return
        top = max(vals) * 1.2 if vals else 1
        top = max(top, 1)
        n = max(len(self.values) - 1, 1)
        prev = None
        pen = QPen(QColor("#2f81f7"), 2)
        for i, v in enumerate(self.values):
            x = r.left() + r.width() * i / n
            if v is None:
                p.setPen(QPen(QColor("#d1242f"), 2))
                p.drawLine(int(x), r.top(), int(x), r.bottom())
                prev = None
                continue
            y = r.bottom() - r.height() * v / top
            if prev:
                p.setPen(pen)
                p.drawLine(int(prev[0]), int(prev[1]), int(x), int(y))
            prev = (x, y)
        p.setPen(self.palette().text().color())
        p.drawText(r, Qt.AlignTop | Qt.AlignLeft, f"max {top / 1.2:.0f} ms")
