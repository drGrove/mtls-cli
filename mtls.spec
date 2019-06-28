# -*- mode: python -*-

block_cipher = None

import PyInstaller.config

a = Analysis(
    ['mtls/cli.py', 'mtls/mtls.py'],
    pathex=[
        './env/lib/python3.7/site-packages',
        'mtls'
    ],
    binaries=[],
    datas=[
        ('share/password_word_list', '.')
    ],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='mtls',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True
)
