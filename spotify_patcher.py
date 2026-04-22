"""
Minimal Spotify desktop client patcher.

Spotify ships its UI as an Electron/CEF app whose HTML + JS + CSS are packed
into ``%APPDATA%\\Spotify\\Apps\\xpui.spa`` (a ZIP archive). We inject a
single ``<script>`` reference into ``index.html`` and drop our own JS file
next to it. That JS is our ad-handler.

Flow:
    patch()   -> backup + inject
    unpatch() -> restore from backup
    is_patched() -> detect marker

Spotify auto-updates will re-download xpui.spa and wipe our patch; the tray
menu exposes a "Re-patch" button for that case. Not much we can do beyond
that without a background watcher — and you asked for own-our-own so that's
the deliberate tradeoff.
"""

from __future__ import annotations

import logging
import os
import shutil
import zipfile
from pathlib import Path

log = logging.getLogger("interceptify")


def spotify_xpui_path() -> Path:
    appdata = os.environ.get("APPDATA", "")
    return Path(appdata) / "Spotify" / "Apps" / "xpui.spa"


BACKUP_SUFFIX = ".interceptify-backup"
INJECTED_SCRIPT_NAME = "interceptify-adblock.js"
MARKER = "<!-- INTERCEPTIFY_PATCHED -->"

# Where our adblock JS lives in this project
def _my_adblock_path() -> Path:
    from main import ROOT  # lazy to avoid circular imports at module load
    return ROOT / "extensions" / "adblock.js"


# ---------------------------------------------------------------------------

def is_installed() -> bool:
    return spotify_xpui_path().exists()


def enable_devtools() -> None:
    """Flip the Spotify prefs flag that allows Ctrl+Shift+I to open DevTools."""
    prefs = Path(os.environ.get("APPDATA", "")) / "Spotify" / "prefs"
    if not prefs.exists():
        return
    try:
        text = prefs.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    flag = 'app.browser.enable-developer-mode="true"'
    if flag in text:
        return
    if not text.endswith("\n"):
        text += "\n"
    text += flag + "\n"
    try:
        prefs.write_text(text, encoding="utf-8")
        log.info("Enabled Spotify DevTools (Ctrl+Shift+I)")
    except Exception as e:
        log.warning("Could not write Spotify prefs: %s", e)


def is_patched() -> bool:
    p = spotify_xpui_path()
    if not p.exists():
        return False
    try:
        with zipfile.ZipFile(p, "r") as z:
            if INJECTED_SCRIPT_NAME not in z.namelist():
                return False
            html = z.read("index.html").decode("utf-8", errors="replace")
            return MARKER in html
    except Exception:
        return False


def is_spotify_running() -> bool:
    """Best-effort check so we can warn the user before patching."""
    try:
        import subprocess
        r = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq Spotify.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, creationflags=0x08000000,
        )
        return "Spotify.exe" in (r.stdout or "")
    except Exception:
        return False


def kill_spotify() -> None:
    """Kill all Spotify processes. Required before rewriting xpui.spa."""
    import subprocess
    subprocess.run(
        ["taskkill", "/F", "/IM", "Spotify.exe"],
        capture_output=True, creationflags=0x08000000,
    )


def spotify_exe_path() -> Path:
    """Best-effort: find the Spotify.exe binary so we can relaunch it."""
    candidates = [
        Path(os.environ.get("APPDATA", "")) / "Spotify" / "Spotify.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WindowsApps" / "Spotify.exe",
    ]
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]


def launch_spotify() -> bool:
    """Start Spotify detached from our process. Returns True if launch attempted."""
    exe = spotify_exe_path()
    if not exe.exists():
        return False
    try:
        import subprocess
        # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP so Spotify outlives us
        subprocess.Popen(
            [str(exe)], close_fds=True,
            creationflags=0x00000008 | 0x00000200,
        )
        return True
    except Exception as e:
        log.warning("launch_spotify failed: %s", e)
        return False


# ---------------------------------------------------------------------------

def patch(show_badge: bool = True) -> tuple[bool, str]:
    """
    Inject our ad-handler JS into Spotify's xpui.spa. Idempotent.

    ``show_badge`` — when False, the small status dot in Spotify's top bar
    is suppressed (the ad blocker itself still runs).

    Returns (ok, human-readable message).
    """
    xpui = spotify_xpui_path()
    if not xpui.exists():
        return False, f"Spotify not found at {xpui}. Install desktop Spotify from spotify.com."

    adblock_src = _my_adblock_path()
    if not adblock_src.exists():
        return False, f"Missing {adblock_src} — reinstall Interceptify."

    # Backup once
    backup = xpui.with_suffix(xpui.suffix + BACKUP_SUFFIX)
    if not backup.exists():
        try:
            shutil.copy2(xpui, backup)
            log.info("Backed up xpui.spa -> %s", backup.name)
        except Exception as e:
            return False, f"Backup failed: {e}"

    # Rebuild: always start from backup so we re-patch cleanly after Spotify updates
    try:
        # If Spotify updated xpui.spa, refresh the backup reference to the new version
        # ONLY if the current xpui has no marker (i.e. isn't our previous patch).
        with zipfile.ZipFile(xpui, "r") as z:
            html_current = z.read("index.html").decode("utf-8", errors="replace")
        if MARKER not in html_current:
            # Spotify overwrote our patch — refresh backup to this new pristine version
            shutil.copy2(xpui, backup)
            log.info("Spotify updated xpui — refreshed backup to new pristine version")

        tmp = xpui.with_suffix(".spa.tmp")
        with zipfile.ZipFile(backup, "r") as src, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as dst:
            for info in src.infolist():
                data = src.read(info.filename)
                if info.filename == "index.html":
                    html = data.decode("utf-8")
                    # Inline the JS directly so we bypass any CSP / file-allowlist
                    # restrictions Spotify's resource handler may apply to
                    # arbitrarily-named script files.
                    js_body = adblock_src.read_text(encoding="utf-8")
                    # Bake in the show-badge preference at patch time; the JS
                    # reads window.__INTERCEPTIFY_SHOW_BADGE.
                    prelude = f"window.__INTERCEPTIFY_SHOW_BADGE = {str(bool(show_badge)).lower()};\n"
                    inject = (
                        f"{MARKER}\n"
                        f"<script data-interceptify=\"inline\">\n"
                        f"// @interceptify-adblock inlined\n"
                        f"{prelude}"
                        f"{js_body}\n"
                        f"</script>\n"
                    )
                    if "</body>" in html:
                        html = html.replace("</body>", inject + "</body>", 1)
                    else:
                        html += "\n" + inject
                    data = html.encode("utf-8")
                dst.writestr(info, data)
            # Add our JS file
            dst.writestr(INJECTED_SCRIPT_NAME, adblock_src.read_bytes())

        tmp.replace(xpui)
        enable_devtools()
        return True, "Spotify patched. Restart Spotify to activate."
    except PermissionError as e:
        return False, f"Permission denied — quit Spotify first. ({e})"
    except Exception as e:
        log.exception("Patch failed")
        return False, f"Patch failed: {e}"


def unpatch() -> tuple[bool, str]:
    """Restore xpui.spa from backup."""
    xpui = spotify_xpui_path()
    backup = xpui.with_suffix(xpui.suffix + BACKUP_SUFFIX)
    if not backup.exists():
        return False, "No backup found — nothing to restore."
    try:
        shutil.copy2(backup, xpui)
        return True, "Spotify restored to original. Restart Spotify."
    except PermissionError as e:
        return False, f"Permission denied — quit Spotify first. ({e})"
    except Exception as e:
        return False, f"Restore failed: {e}"
