# -*- mode: python ; coding: utf-8 -*-
#
# Kept in step with the CI build command in .github/workflows/release.yml.
# A local build that differs from the released one is how an unelevated release
# ships next to an elevated .exe on the maintainer's own machine, which is
# exactly what happened before v2.0.5:
#   * uac_admin=True here vs no --uac-admin in CI
#   * name 'Interceptify-v2' here vs 'Interceptify' in CI
# so `dist\` held a stale, elevated binary that looked like the release.
#
#   pyinstaller --noconfirm Interceptify-v2.spec

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('extensions', 'extensions')],
    # main.py imports these lazily from its subcommand dispatcher, so the .exe
    # can run the scheduler and the self-heal itself. Without them the packaged
    # app cannot own its own autostart and the deployment splits in two.
    hiddenimports=['selfheal', 'install_tasks', 'websocket'],
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
    name='Interceptify',
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
    # asInvoker. Everything Interceptify writes belongs to the logged-in user;
    # requesting admin bought no capability and created a high-integrity process
    # launched from a user-writable directory.
    uac_admin=False,
    manifest='interceptify.manifest',
    # Windows file properties. An unsigned, self-updating .exe with blank
    # Details gives the user nothing at all to check.
    version='version_info.txt',
)
