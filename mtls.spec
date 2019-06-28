# -*- mode: python -*-
import os
import sys
import importlib

block_cipher = None

import PyInstaller.config

# Longer paths precede shorter paths for path-stripping.
env_paths = []
if 'VIRTUAL_ENV' in os.environ:
  env_paths.append(
    os.path.join(
        os.environ['VIRTUAL_ENV'],
        'lib',
        'python3.6',
        'site-packages'
    )
  )
  env_paths.append(
    os.path.join(
        os.environ['VIRTUAL_ENV'],
        'lib',
        'python3.7',
        'site-packages'
    )
  )

env_paths.append('.')

a = Analysis([
       'bin/mtls'
    ],
    pathex=env_paths,
    datas=[
        ('mtls/share/password_word_list', 'mtls/share')
    ],
    hookspath=None,
    runtime_hooks=None,
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
