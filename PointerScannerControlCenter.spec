# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['PointerScannerControlCenter.pyw'],
    pathex=[],
    binaries=[],
    datas=[('pattern_database.json', '.'), ('logo.jpg', '.'), ('app_icon.ico', '.'), ('plugins', 'plugins'), ('manifests', 'manifests')],
    hiddenimports=['pefile', 'PIL', 'PIL.Image', 'PIL.ImageTk', 'windnd', 'plugin_engine', 'ScannerEngine'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PointerScannerControlCenter',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['app_icon.ico'],
)
