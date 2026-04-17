"""
Windows system proxy registry management.

Sets / unsets the per-user WinINET proxy at
``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings`` and
tells WinINET to pick up the change immediately via ``InternetSetOption``.

Previous values are saved so they can be restored when the user toggles OFF.
"""

from __future__ import annotations

import ctypes
import json
import logging
from ctypes import wintypes
from pathlib import Path

import winreg

log = logging.getLogger("interceptify")

REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# WinINET option codes — signal other processes that proxy settings changed
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

DEFAULT_PROXY = "127.0.0.1:8080"
DEFAULT_OVERRIDE = "<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;*.local"


# ---------------------------------------------------------------------------
# Low-level registry helpers
# ---------------------------------------------------------------------------

def _read(name: str):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ) as k:
            val, _ = winreg.QueryValueEx(k, name)
            return val
    except FileNotFoundError:
        return None


def _write(name: str, value, value_type=winreg.REG_SZ) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, value_type, value)


def _delete(name: str) -> None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
    except FileNotFoundError:
        pass


def _notify_wininet() -> None:
    """Tell WinINET (and browsers/apps using it) that proxy settings changed."""
    try:
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]
        internet_set_option.restype = wintypes.BOOL
        internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as e:
        log.warning("InternetSetOption refresh failed: %s", e)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def snapshot_current() -> dict:
    """Capture current proxy-related registry values so we can restore them."""
    return {
        "ProxyEnable": _read("ProxyEnable"),
        "ProxyServer": _read("ProxyServer"),
        "ProxyOverride": _read("ProxyOverride"),
    }


def save_snapshot(path: Path, snap: dict) -> None:
    path.write_text(json.dumps(snap, indent=2, default=str), encoding="utf-8")


def load_snapshot(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def enable(server: str = DEFAULT_PROXY, override: str = DEFAULT_OVERRIDE) -> None:
    """Turn the system proxy ON, pointing at ``server``."""
    _write("ProxyEnable", 1, winreg.REG_DWORD)
    _write("ProxyServer", server)
    _write("ProxyOverride", override)
    _notify_wininet()


def disable() -> None:
    """Turn the system proxy OFF (leaves ProxyServer string in place but disabled)."""
    _write("ProxyEnable", 0, winreg.REG_DWORD)
    _notify_wininet()


def restore(snap: dict) -> None:
    """Restore a snapshot taken by ``snapshot_current()``."""
    if snap.get("ProxyEnable") is None:
        _delete("ProxyEnable")
    else:
        _write("ProxyEnable", int(snap["ProxyEnable"]), winreg.REG_DWORD)

    for key in ("ProxyServer", "ProxyOverride"):
        val = snap.get(key)
        if val is None:
            _delete(key)
        else:
            _write(key, val)

    _notify_wininet()
