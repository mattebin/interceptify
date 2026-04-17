"""
Installs mitmproxy's CA certificate into the Windows Trusted Root store.

mitmproxy auto-generates its CA on first launch at ``~/.mitmproxy/``. This
module wraps ``certutil -addstore`` so Interceptify can install/re-install
the cert without shelling out to UAC every time (the app is already elevated).
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

log = logging.getLogger("interceptify")

MITMPROXY_DIR = Path.home() / ".mitmproxy"
CA_CERT_PATH = MITMPROXY_DIR / "mitmproxy-ca-cert.cer"
# Fallback — some mitmproxy versions write only the PEM
CA_PEM_PATH = MITMPROXY_DIR / "mitmproxy-ca-cert.pem"


def find_ca() -> Path | None:
    for p in (CA_CERT_PATH, CA_PEM_PATH):
        if p.exists():
            return p
    return None


def install_ca() -> tuple[bool, str]:
    """
    Install the mitmproxy CA into the Windows Trusted Root store.

    Returns (success, human-readable message). The caller is expected to
    already be running elevated.
    """
    cert = find_ca()
    if cert is None:
        return False, (
            "mitmproxy CA not found. Start the proxy once to generate it, "
            "then run Install certificate again."
        )

    try:
        result = subprocess.run(
            ["certutil", "-addstore", "-f", "ROOT", str(cert)],
            capture_output=True,
            text=True,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
    except FileNotFoundError:
        return False, "certutil.exe not found on PATH (unexpected on Windows)."

    if result.returncode == 0:
        return True, "mitmproxy CA installed into Trusted Root store."
    return False, f"certutil failed ({result.returncode}): {result.stderr.strip() or result.stdout.strip()}"


def remove_ca() -> tuple[bool, str]:
    """Remove the mitmproxy CA by its Subject CN. Used on uninstall/cleanup."""
    try:
        result = subprocess.run(
            ["certutil", "-delstore", "ROOT", "mitmproxy"],
            capture_output=True,
            text=True,
            creationflags=0x08000000,
        )
    except FileNotFoundError:
        return False, "certutil.exe not found."
    if result.returncode == 0:
        return True, "mitmproxy CA removed from Trusted Root store."
    return False, f"certutil failed ({result.returncode})."
