"""
Interceptify v2 - Windows tray app that patches Spotify's xpui.spa to block
ads in the desktop client.

Why xpui-only and not the old mitmproxy pipeline:
    Spotify 1.2.88+ stopped using the Windows system proxy. All API and
    audio traffic now goes direct (TCP + QUIC), so mitmproxy can't see it.
    The client-side patch is the only working layer on modern Spotify.

What the patch does (extensions/adblock.js, inlined into Spotify's index.html;
tunables in extensions/adblock.config.json, injected as window.__INTERCEPTIFY_CONFIG):
    - L1: hooks Spotify's in-stream ad provider (found by source-string scan,
      not a hard-coded webpack module id) and neutralises ad payloads pre-paint.
    - L2: classifies short manifests as ads and 404s their audio segments.
    - L3: an explicit ad-state machine (IDLE/SUSPECTED/CONFIRMED/SKIPPING/
      COOLDOWN). The play queue is only advanced through ONE gated choke point
      while a real ad is painted; weak/lingering signals only mute. A post-ad
      cooldown + now-playing verification guarantee a real song is never skipped.
    - Mutes via Spotify's volume button + per-context WebAudio gain, state-tracked
      so it never fights the user's manual mute and always restores.

The tray app's runtime job is small: own the patch lifecycle, monitor Spotify
auto-updates and re-apply the patch when it gets wiped, and integrity-verified
self-update from GitHub releases.
"""

from __future__ import annotations

import atexit
import ctypes
import json
import logging
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Optional

from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as Item, Menu

import self_updater
import spotify_patcher

# Optional personal modules - present in some local installs only. Public
# builds never ship these; importing optionally keeps main.py portable.
try:
    import update_watcher  # type: ignore
    HAS_UPDATE_WATCHER = True
except ImportError:
    update_watcher = None  # type: ignore
    HAS_UPDATE_WATCHER = False


APP_NAME = "Interceptify"
APP_VERSION = "2.0.4"  # bump in lockstep with the GitHub tag

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("interceptify")


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


def is_frozen_build() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundled_root() -> Path:
    """Where PyInstaller-bundled data lives at runtime (sys._MEIPASS one-file)."""
    return Path(getattr(sys, "_MEIPASS", str(app_root())))


def ensure_bundled_default(name: str) -> None:
    target = ROOT / name
    if target.exists():
        return
    src = bundled_root() / name
    if not src.exists() or src == target:
        return
    try:
        if src.is_dir():
            import shutil
            shutil.copytree(src, target)
        else:
            target.write_bytes(src.read_bytes())
        log.info("Seeded %s from bundle", name)
    except Exception as e:
        log.warning("Could not seed %s: %s", name, e)


ROOT = app_root()
CONFIG_PATH = ROOT / "config.json"

# First-run: copy editable defaults out of the PyInstaller bundle
ensure_bundled_default("extensions")


# ---------------------------------------------------------------------------
# Elevation
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{sys.argv[0]}"', None, 1
    )
    if rc <= 32:
        ctypes.windll.user32.MessageBoxW(
            None,
            f"{APP_NAME} requires Administrator privileges to write Spotify's xpui.spa.",
            APP_NAME,
            0x10,
        )
    sys.exit(0)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "show_badge": True,
    "debug_capture": False,
}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except Exception:
            pass
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass
    return cfg


def save_config(cfg: dict) -> None:
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception as e:
        log.warning("save_config failed: %s", e)


# ---------------------------------------------------------------------------
# Icon
# ---------------------------------------------------------------------------

def make_icon(active: bool) -> Image.Image:
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    fill = (46, 160, 67, 255) if active else (120, 120, 120, 255)
    border = (20, 90, 40, 255) if active else (60, 60, 60, 255)
    d.rounded_rectangle((6, 6, size - 6, size - 6), radius=14, fill=fill, outline=border, width=3)
    if active:
        d.line((18, 34, 28, 44), fill="white", width=6)
        d.line((28, 44, 48, 22), fill="white", width=6)
    else:
        d.line((18, 18, 46, 46), fill="white", width=6)
        d.line((46, 18, 18, 46), fill="white", width=6)
    return img


# ---------------------------------------------------------------------------
# Tray application
# ---------------------------------------------------------------------------

class InterceptifyApp:
    def __init__(self) -> None:
        self.cfg = load_config()
        self.icon: Optional[pystray.Icon] = None
        self._latest_release: Optional[self_updater.Release] = None
        self._update_in_progress = False

        # Optional personal feature: Spotify-update watcher that re-applies the
        # patch after a Spotify auto-update. Activates only if the local
        # update_watcher.py is present (public builds never ship it).
        self._spotify_watcher = None
        if HAS_UPDATE_WATCHER:
            try:
                self._spotify_watcher = update_watcher.UpdateWatcher(
                    xpui_path=spotify_patcher.spotify_xpui_path(),
                    is_patched_fn=spotify_patcher.is_patched,
                    on_update=self._on_spotify_update,
                    poll_sec=int(self.cfg.get("watcher_poll_sec", 300)),
                )
            except Exception as e:
                log.warning("update_watcher init failed: %s", e)

        atexit.register(self._on_exit)

    # ---- Helpers ---------------------------------------------------------

    def notify(self, msg: str, title: str = APP_NAME) -> None:
        log.info("NOTIFY: %s", msg)
        try:
            if self.icon is not None:
                self.icon.notify(msg, title)
        except Exception as e:
            log.warning("Notify failed: %s -- %s", e, msg)

    def _is_active(self) -> bool:
        """Active = Spotify is currently patched."""
        try:
            return spotify_patcher.is_patched()
        except Exception:
            return False

    def refresh_icon(self) -> None:
        if self.icon is None:
            return
        active = self._is_active()
        self.icon.icon = make_icon(active)
        if active:
            state = "blocking Spotify ads"
        elif spotify_patcher.is_installed():
            state = "idle - Spotify not patched"
        else:
            state = "Spotify not installed"
        title = f"{APP_NAME}: {state}"
        if self._latest_release is not None:
            title += f"  -  Update {self._latest_release.tag} available"
        self.icon.title = title[:127]
        try:
            self.icon.menu = self.build_menu()
        except Exception:
            pass

    # ---- Patch lifecycle ------------------------------------------------

    def _current_show_badge(self) -> bool:
        return bool(self.cfg.get("show_badge", True))

    def _current_debug_capture(self) -> bool:
        return bool(self.cfg.get("debug_capture", False))

    def _spotify_debug_port(self) -> int:
        return 9222 if self._current_debug_capture() else 0

    def patch_spotify(self, *_args) -> None:
        def worker():
            if not spotify_patcher.is_installed():
                self.notify("Spotify not found. Install from spotify.com (desktop, not Store).")
                return
            if spotify_patcher.is_spotify_running():
                self.notify("Closing Spotify to apply patch...")
                spotify_patcher.kill_spotify()
                time.sleep(2)
            ok, msg = spotify_patcher.patch(
                show_badge=self._current_show_badge(),
                debug_capture=self._current_debug_capture(),
            )
            log.info("patch_spotify: ok=%s msg=%s", ok, msg)
            self.notify(msg)
            if ok:
                spotify_patcher.launch_spotify(remote_debug_port=self._spotify_debug_port())
            self.refresh_icon()
        threading.Thread(target=worker, daemon=True).start()

    def unpatch_spotify(self, *_args) -> None:
        def worker():
            if spotify_patcher.is_spotify_running():
                self.notify("Closing Spotify to restore original...")
                spotify_patcher.kill_spotify()
                time.sleep(2)
            ok, msg = spotify_patcher.unpatch()
            log.info("unpatch_spotify: ok=%s msg=%s", ok, msg)
            self.notify(msg)
            if ok:
                spotify_patcher.launch_spotify(remote_debug_port=self._spotify_debug_port())
            self.refresh_icon()
        threading.Thread(target=worker, daemon=True).start()

    def toggle(self, *_args) -> None:
        if self._is_active():
            self.unpatch_spotify()
        else:
            self.patch_spotify()

    def toggle_show_badge(self, *_args) -> None:
        def worker():
            new_val = not self._current_show_badge()
            self.cfg["show_badge"] = new_val
            save_config(self.cfg)
            if not spotify_patcher.is_installed() or not spotify_patcher.is_patched():
                self.notify(f"Status dot {'shown' if new_val else 'hidden'} (re-patch to apply).")
                return
            was_running = spotify_patcher.is_spotify_running()
            if was_running:
                spotify_patcher.kill_spotify()
                time.sleep(2)
            ok, msg = spotify_patcher.patch(
                show_badge=new_val,
                debug_capture=self._current_debug_capture(),
            )
            if ok:
                spotify_patcher.launch_spotify(remote_debug_port=self._spotify_debug_port())
                self.notify(f"Status dot {'shown' if new_val else 'hidden'}. Spotify relaunched.")
            else:
                self.notify(msg)
        threading.Thread(target=worker, daemon=True).start()

    def toggle_debug_capture(self, *_args) -> None:
        def worker():
            new_val = not self._current_debug_capture()
            self.cfg["debug_capture"] = new_val
            save_config(self.cfg)
            if not spotify_patcher.is_installed() or not spotify_patcher.is_patched():
                self.notify(f"Debug capture {'ON' if new_val else 'OFF'} (re-patch to apply).")
                self.refresh_icon()
                return
            was_running = spotify_patcher.is_spotify_running()
            if was_running:
                self.notify(f"Turning debug capture {'ON' if new_val else 'OFF'}; restarting Spotify...")
                spotify_patcher.kill_spotify()
                time.sleep(2)
            ok, msg = spotify_patcher.patch(
                show_badge=self._current_show_badge(),
                debug_capture=new_val,
            )
            if ok:
                spotify_patcher.launch_spotify(remote_debug_port=9222 if new_val else 0)
                self.notify(f"Debug capture {'ON' if new_val else 'OFF'}. Spotify relaunched.")
            else:
                self.notify(msg)
            self.refresh_icon()
        threading.Thread(target=worker, daemon=True).start()

    # ---- Self-update -----------------------------------------------------

    def _set_latest_release(self, rel: Optional["self_updater.Release"]) -> None:
        if (self._latest_release and self._latest_release.tag) == (rel and rel.tag):
            return
        self._latest_release = rel
        self.refresh_icon()

    def _poll_for_updates_loop(self) -> None:
        first = True
        while True:
            time.sleep(60 if first else 6 * 3600)
            first = False
            try:
                if not is_frozen_build():
                    self._set_latest_release(None)
                    continue
                rel = self_updater.get_latest_release()
                if rel and self_updater.is_newer(rel.tag, APP_VERSION):
                    if self._latest_release is None or self._latest_release.tag != rel.tag:
                        log.info("Update available: %s (current %s)", rel.tag, APP_VERSION)
                        self._set_latest_release(rel)
                        self.notify(
                            f"Update {rel.tag} available. Click 'Install update' in the tray menu.",
                        )
                else:
                    self._set_latest_release(None)
            except Exception as e:
                log.warning("Update poll failed: %s", e)

    def install_update(self, *_args) -> None:
        if self._update_in_progress:
            self.notify("Update already in progress.")
            return
        rel = self._latest_release
        if rel is None:
            self.notify("No update pending.")
            return
        if not self_updater.is_newer(rel.tag, APP_VERSION):
            self._set_latest_release(None)
            self.notify("Already on the latest Interceptify version.")
            return
        if not is_frozen_build():
            self._set_latest_release(None)
            self.notify("Source mode: git pull to update.")
            return
        if not rel.exe_asset_url:
            self.notify(f"Latest release {rel.tag} has no Interceptify.exe asset.")
            return
        self._update_in_progress = True
        self.notify(f"Installing {rel.tag}...")
        threading.Thread(target=self._perform_update, args=(rel,), daemon=True).start()

    def _perform_update(self, rel: "self_updater.Release") -> None:
        try:
            self.notify(f"Downloading {rel.tag}...")
            new_exe = ROOT / "Interceptify.exe.new"
            try:
                self_updater.download_asset(
                    rel.exe_asset_url, new_exe,
                    expected_size=rel.exe_asset_size,
                    expected_sha256=rel.exe_asset_sha256,
                )
            except Exception as e:
                self.notify(f"Update rejected: {e}")
                return
            target_exe = Path(sys.executable).resolve()
            bat = ROOT / "_interceptify_update.bat"
            try:
                self_updater.write_updater_bat(
                    bat, current_pid=os.getpid(),
                    new_exe=new_exe.resolve(), target_exe=target_exe,
                )
            except Exception as e:
                self.notify(f"Updater script failed: {e}")
                return
            self.notify(f"Installing {rel.tag} - the app will restart in a few seconds.")
            subprocess.Popen(
                ["cmd", "/c", str(bat)],
                creationflags=0x00000008 | 0x00000200,
                close_fds=True,
            )
        except Exception as e:
            self.notify(f"Updater launch failed: {e}")
            return
        finally:
            self._update_in_progress = False
        try:
            self.icon.stop()
        except Exception:
            pass
        os._exit(0)

    # ---- Personal: Spotify-update watcher (optional) -------------------

    def _on_spotify_update(self, event: dict) -> None:
        """Called by update_watcher when xpui.spa changes on disk (personal feature)."""
        if not event.get("wiped"):
            return
        auto = bool(self.cfg.get("auto_repatch_spotify", False))
        if auto:
            was_running = spotify_patcher.is_spotify_running()
            if was_running:
                spotify_patcher.kill_spotify()
                time.sleep(2)
            ok, _msg = spotify_patcher.patch(
                show_badge=self._current_show_badge(),
                debug_capture=self._current_debug_capture(),
            )
            if ok and was_running:
                spotify_patcher.launch_spotify(remote_debug_port=self._spotify_debug_port())
            self.notify(
                f"Spotify auto-updated and wiped Interceptify's patch. "
                f"Auto-repatch {'succeeded' if ok else 'FAILED'}.",
                title="Spotify updated - patch re-applied",
            )
        else:
            self.notify(
                "Spotify auto-updated and removed Interceptify's patch. "
                "Right-click the tray icon -> Patch Spotify to re-apply.",
                title="Spotify updated - ad-block wiped",
            )
        self.refresh_icon()

    def toggle_auto_repatch(self, *_args) -> None:
        new_val = not bool(self.cfg.get("auto_repatch_spotify", False))
        self.cfg["auto_repatch_spotify"] = new_val
        save_config(self.cfg)
        self.notify(f"Auto re-patch after Spotify updates: {'ON' if new_val else 'OFF'}")

    # ---- Run at Windows startup ----------------------------------------

    _RUN_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
    _RUN_VALUE_NAME = "Interceptify"

    def _autostart_command(self) -> str:
        if getattr(sys, "frozen", False):
            return f'"{sys.executable}"'
        py = sys.executable
        if py.lower().endswith("python.exe"):
            pyw = py[:-10] + "pythonw.exe"
            if Path(pyw).exists():
                py = pyw
        return f'"{py}" "{Path(__file__).resolve()}"'

    def _is_autostart_enabled(self) -> bool:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._RUN_REG_PATH, 0, winreg.KEY_READ) as k:
                val, _ = winreg.QueryValueEx(k, self._RUN_VALUE_NAME)
                return bool(val)
        except (FileNotFoundError, OSError):
            return False

    def toggle_autostart(self, *_args) -> None:
        import winreg
        currently_on = self._is_autostart_enabled()
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._RUN_REG_PATH, 0,
                                winreg.KEY_SET_VALUE) as k:
                if currently_on:
                    try:
                        winreg.DeleteValue(k, self._RUN_VALUE_NAME)
                    except FileNotFoundError:
                        pass
                    self.notify("Auto-start at Windows login: OFF")
                else:
                    winreg.SetValueEx(k, self._RUN_VALUE_NAME, 0, winreg.REG_SZ,
                                      self._autostart_command())
                    self.notify("Auto-start at Windows login: ON")
        except Exception as e:
            self.notify(f"Auto-start toggle failed: {e}")
        self.refresh_icon()

    # ---- Exit ----------------------------------------------------------

    def quit_app(self, *_args) -> None:
        if self.icon is not None:
            self.icon.stop()

    def _on_exit(self) -> None:
        # Stop the optional Spotify-update watcher cleanly
        if self._spotify_watcher is not None:
            try:
                self._spotify_watcher.stop()
            except Exception:
                pass

    # ---- Menu ----------------------------------------------------------

    def build_menu(self) -> Menu:
        active = self._is_active()
        toggle_label = (
            "Unpatch Spotify (stop blocking ads)"
            if active else
            "Patch Spotify (start blocking ads)"
        )
        update_label = (
            f"Install update {self._latest_release.tag}"
            if self._latest_release else
            "Install update"
        )
        items = [
            Item(toggle_label, self.toggle, default=True),
            Item(
                update_label, self.install_update,
                visible=lambda item: self._latest_release is not None,
            ),
            Menu.SEPARATOR,
            Item(
                "Show status dot in Spotify",
                self.toggle_show_badge,
                checked=lambda item: self._current_show_badge(),
            ),
            Item(
                "Debug capture mode",
                self.toggle_debug_capture,
                checked=lambda item: self._current_debug_capture(),
            ),
        ]
        if HAS_UPDATE_WATCHER:
            items.append(Item(
                "Auto re-patch after Spotify updates",
                self.toggle_auto_repatch,
                checked=lambda item: bool(self.cfg.get("auto_repatch_spotify", False)),
            ))
        items.extend([
            Menu.SEPARATOR,
            Item(
                "Run at Windows startup",
                self.toggle_autostart,
                checked=lambda item: self._is_autostart_enabled(),
            ),
            Menu.SEPARATOR,
            Item("Exit", self.quit_app),
        ])
        return Menu(*items)

    def run(self) -> None:
        active = self._is_active()
        self.icon = pystray.Icon(
            APP_NAME,
            icon=make_icon(active),
            title=f"{APP_NAME}: starting...",
            menu=self.build_menu(),
        )
        # Initial tooltip + start the self-update poll
        threading.Thread(target=self._poll_for_updates_loop, daemon=True).start()
        if self._spotify_watcher is not None:
            try:
                self._spotify_watcher.start()
            except Exception as e:
                log.warning("Could not start Spotify-update watcher: %s", e)
        # Refresh tooltip once icon exists
        threading.Thread(target=lambda: (time.sleep(0.5), self.refresh_icon()), daemon=True).start()
        self.icon.run()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if not is_admin():
        relaunch_as_admin()
        return
    InterceptifyApp().run()


if __name__ == "__main__":
    main()
