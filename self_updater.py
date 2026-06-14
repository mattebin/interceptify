"""
Self-update for Interceptify.

Polls https://api.github.com/repos/<REPO>/releases/latest and compares the
latest release tag to the running version. If newer, the tray exposes an
"Install update" menu item that downloads the new exe and swaps it in via a
tiny batch helper (the running process can't overwrite its own .exe on
Windows).

Integrity (v2): the downloaded exe is verified before it is ever executed:
  - the asset URL host must be GitHub (github.com / *.githubusercontent.com),
  - the byte count must match the release-reported asset size,
  - if the release publishes a SHA-256 (an ``Interceptify.exe.sha256`` /
    ``SHA256SUMS.txt`` asset, or a ``SHA256: <hex>`` line in the release body),
    the download must match it or the update is refused (fail closed).
Because the swapped binary is relaunched with Administrator rights, skipping
this check would mean any tampered/MITM'd asset becomes admin-level RCE.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger("interceptify")

REPO = "mattebin/interceptify"
LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
USER_AGENT = "Interceptify-updater"

# Update assets may only be fetched from GitHub-controlled hosts.
SHA256_ASSET_NAMES = (
    "interceptify.exe.sha256",
    "interceptify.exe.sha256.txt",
    "sha256sums.txt",
    "sha256sums",
)


@dataclass
class Release:
    tag: str
    name: str
    html_url: str
    body: str
    exe_asset_url: Optional[str]
    exe_asset_size: int
    exe_asset_sha256: Optional[str] = None


def _host_allowed(url: str) -> bool:
    """True only for GitHub-controlled hosts that serve releases/assets."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return host == "github.com" or host.endswith(".githubusercontent.com")


def _fetch_text(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _parse_sha256(text: str, want_name: Optional[str] = None) -> Optional[str]:
    """Extract a 64-hex SHA-256 from a checksum file or release body.

    Prefers a line that also names the target file (e.g. a SHA256SUMS line),
    then a ``sha256: <hex>`` marker, then any standalone 64-hex token.
    """
    if not text:
        return None
    if want_name:
        for line in text.splitlines():
            if want_name.lower() in line.lower():
                m = re.search(r"\b([0-9a-fA-F]{64})\b", line)
                if m:
                    return m.group(1).lower()
    m = re.search(r"sha-?256[\s:=]*([0-9a-fA-F]{64})", text, re.I)
    if m:
        return m.group(1).lower()
    m = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    return m.group(1).lower() if m else None


def parse_version(s: str) -> tuple[int, ...]:
    """v1.4.0 -> (1, 4, 0). Unparseable -> (0,) so it always loses comparisons."""
    if not s:
        return (0,)
    m = re.match(r"v?(\d+(?:\.\d+)*)", s.strip())
    if not m:
        return (0,)
    return tuple(int(x) for x in m.group(1).split("."))


def get_latest_release() -> Optional[Release]:
    try:
        req = urllib.request.Request(LATEST_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
    except Exception as e:
        log.warning("Update check failed: %s", e)
        return None

    exe_url, exe_size = None, 0
    sha_url = None
    for a in data.get("assets", []):
        name = a.get("name", "").lower()
        if name == "interceptify.exe":
            exe_url = a.get("browser_download_url")
            exe_size = int(a.get("size", 0))
        elif name in SHA256_ASSET_NAMES and sha_url is None:
            sha_url = a.get("browser_download_url")

    # Resolve the expected SHA-256: dedicated checksum asset first, then the
    # release body. Either is acceptable; absence is tolerated (size-only).
    exe_sha: Optional[str] = None
    if sha_url and _host_allowed(sha_url):
        try:
            exe_sha = _parse_sha256(_fetch_text(sha_url), want_name="interceptify.exe")
        except Exception as e:
            log.warning("Could not fetch SHA-256 asset: %s", e)
    if not exe_sha:
        exe_sha = _parse_sha256(data.get("body", "") or "", want_name="interceptify.exe")

    return Release(
        tag=data.get("tag_name", ""),
        name=data.get("name", ""),
        html_url=data.get("html_url", ""),
        body=data.get("body", ""),
        exe_asset_url=exe_url,
        exe_asset_size=exe_size,
        exe_asset_sha256=exe_sha,
    )


def is_newer(latest_tag: str, current_version: str) -> bool:
    return parse_version(latest_tag) > parse_version(current_version)


def download_asset(url: str, dest: Path, expected_size: int = 0,
                   expected_sha256: Optional[str] = None, timeout: int = 180) -> str:
    """Stream-download a release asset to ``dest`` and verify its integrity.

    Raises (and removes the partial file) on an untrusted host, a size
    mismatch, a SHA-256 mismatch, or when no SHA-256 can be resolved at all
    (fail-closed — an admin-level exe must be integrity-verified before it is
    swapped in). Returns the file's SHA-256 hex.
    """
    if not _host_allowed(url):
        raise ValueError(f"Refusing to download update from untrusted host: {url}")

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    tmp = dest.with_suffix(dest.suffix + ".part")
    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(req, timeout=timeout) as r, tmp.open("wb") as f:
        while True:
            chunk = r.read(64 * 1024)
            if not chunk:
                break
            f.write(chunk)
            digest.update(chunk)
            total += len(chunk)

    hexdigest = digest.hexdigest()
    if expected_size and total != expected_size:
        tmp.unlink(missing_ok=True)
        raise ValueError(f"Update size mismatch: got {total} bytes, expected {expected_size}")
    if expected_sha256:
        if hexdigest != expected_sha256.lower():
            tmp.unlink(missing_ok=True)
            raise ValueError("Update SHA-256 mismatch -- refusing to install (possible tampering)")
        log.info("Update SHA-256 verified: %s", hexdigest)
    else:
        tmp.unlink(missing_ok=True)
        raise ValueError(
            "No published SHA-256 for this release -- refusing to install. "
            "An admin-level exe must be integrity-verified; publish an "
            "Interceptify.exe.sha256 asset (or a SHA-256 in the release body) "
            "to enable updates."
        )
    tmp.replace(dest)
    return hexdigest


def write_updater_bat(bat_path: Path, current_pid: int, new_exe: Path,
                      target_exe: Path) -> None:
    """
    Write a small batch script that:
      1. Waits for the running Interceptify PID to exit (so the exe unlocks)
      2. Moves the new exe over the current one
      3. Relaunches Interceptify
      4. Deletes itself
    """
    script = f"""@echo off
setlocal
set PID={current_pid}
:waitloop
tasklist /FI "PID eq %PID%" 2>NUL | findstr %PID% >NUL
if not errorlevel 1 (
    ping -n 2 127.0.0.1 >NUL
    goto waitloop
)
move /Y "{new_exe}" "{target_exe}" >NUL 2>&1
if errorlevel 1 (
    echo Failed to replace exe -- new build left at "{new_exe}"
    pause
    exit /b 1
)
start "" "{target_exe}"
del "%~f0"
"""
    bat_path.write_text(script, encoding="utf-8")
