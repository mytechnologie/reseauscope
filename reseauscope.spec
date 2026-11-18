# -*- mode: python ; coding: utf-8 -*-
# PyInstaller : construit ReseauScope.exe (un seul fichier, sans console).
from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ['run.py'],
    pathex=[],
    binaries=[],
    datas=[('reseauscope/data/oui.tsv.gz', 'reseauscope/data'),
           ('reseauscope/assets/reseauscope.ico', 'reseauscope/assets')],
    hiddenimports=collect_submodules('reseauscope'),
    hookspath=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'PySide6.QtWebEngineCore',
              'PySide6.QtQuick', 'PySide6.QtQml', 'PySide6.Qt3DCore', 'PySide6.QtMultimedia'],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='ReseauScope',
    debug=False, bootloader_ignore_signals=False, strip=False, upx=True,
    runtime_tmpdir=None, console=False, disable_windowed_traceback=False,
    icon='reseauscope/assets/reseauscope.ico',
    version='version_info.txt',
)
