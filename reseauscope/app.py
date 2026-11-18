"""Point d'entrée de l'application ReseauScope."""
from __future__ import annotations

import sys


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt
    try:
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    except Exception:
        pass
    app = QApplication(sys.argv)
    app.setApplicationName("ReseauScope")
    app.setOrganizationName("ReseauScope")
    from PySide6.QtGui import QIcon
    from .core.oui import resource_path
    import os
    ico = resource_path("reseauscope", "assets", "reseauscope.ico")
    if os.path.exists(ico):
        app.setWindowIcon(QIcon(ico))
    from .gui.main_window import MainWindow
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
