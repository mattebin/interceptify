"""
Interceptify — Windows tray app that runs an embedded mitmproxy to block
ads inside the Spotify desktop app (and any other app you add a filter for).

High-level flow:
    1. On Toggle ON we:
         * start a mitmproxy DumpMaster in a background thread
         * snapshot + write the WinINET system-proxy registry values
         * install mitmproxy's CA into the Trusted Root store (once)
    2. On Toggle OFF we reverse all three.

Keeping each concern in its own module (``proxy_addon``, ``cert_manager``,
``system_proxy``) makes the tray wiring here readable.
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Optional

from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as Item, Menu

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

import cert_manager
import spotify_patcher
import system_proxy
from proxy_addon import BlockerAddon

APP_NAME = "Interceptify"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("interceptify")


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


def bundled_root() -> Path:
    """
    Where PyInstaller-bundled data files live at runtime.

    With ``--onefile`` the bundle is extracted to ``sys._MEIPASS``. From source
    we just use the script directory.
    """
    return Path(getattr(sys, "_MEIPASS", str(app_root())))


def ensure_bundled_default(name: str) -> None:
    """Copy a bundled default file into the exe's directory if missing on disk."""
    target = ROOT / name
    if target.exists():
        return
    src = bundled_root() / name
    if src.exists() and src != target:
        try:
            target.write_bytes(src.read_bytes())
            log.info("Seeded %s from bundle", name)
        except Exception as e:
            log.warning("Could not seed %s: %s", name, e)


ROOT = app_root()
CONFIG_PATH = ROOT / "config.json"
PROXY_SNAPSHOT_PATH = ROOT / "proxy_snapshot.json"
FILTERS_DIR = ROOT / "filters"
BLOCKED_LOG = ROOT / "blocked.log"
BYPASS_PATH = ROOT / "bypass.txt"

# First-run: copy editable defaults out of the PyInstaller bundle
ensure_bundled_default("bypass.txt")


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
            f"{APP_NAME} requires Administrator privileges to install its certificate.",
            APP_NAME,
            0x10,
        )
    sys.exit(0)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"cert_installed": False}


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


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
# Proxy lifecycle — mitmproxy DumpMaster runs on its own asyncio loop thread
# ---------------------------------------------------------------------------

def _bypass_to_ignore_regex(host: str) -> str:
    """
    Convert a bypass.txt entry to a mitmproxy ignore_hosts regex.

    mitmproxy's ignore_hosts patterns are regexes matched (with re.search)
    against ``host:port``. When matched, the connection is tunneled raw —
    no TLS interception, no decryption — so cert-pinning clients work fine.

    Examples:
      api.anthropic.com  -> r"(^|\\.)api\\.anthropic\\.com:"
      *.openai.com       -> r"(^|\\.)openai\\.com:"
    """
    import re as _re
    h = host.strip().lower()
    if h.startswith("*."):
        h = h[2:]
    return r"(^|\.)" + _re.escape(h) + r":"


class ProxyRunner:
    """Owns the DumpMaster and the thread running its event loop."""

    def __init__(self, addon: BlockerAddon):
        self.addon = addon
        self.master: Optional[DumpMaster] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None
        self._started = threading.Event()
        self._start_error: Optional[BaseException] = None
        self._ignore_hosts: list[str] = []

    def start(self, bypass_hosts: Optional[list[str]] = None) -> bool:
        if self.thread and self.thread.is_alive():
            return True
        self._ignore_hosts = [_bypass_to_ignore_regex(h) for h in (bypass_hosts or [])]
        log.info("Proxy ignore_hosts patterns: %d", len(self._ignore_hosts))
        self._started.clear()
        self._start_error = None
        self.thread = threading.Thread(target=self._run, name="mitmproxy", daemon=True)
        self.thread.start()
        # Wait up to 10s for startup
        self._started.wait(timeout=10)
        return self._start_error is None and self.master is not None

    async def _amain(self) -> None:
        # mitmproxy 10+ requires a running event loop at the moment DumpMaster
        # is instantiated, so we do everything inside this coroutine.
        self.loop = asyncio.get_running_loop()
        opts = Options(
            listen_host=PROXY_HOST,
            listen_port=PROXY_PORT,
            ssl_insecure=True,
        )
        # ignore_hosts: when host:port matches any regex, mitmproxy tunnels
        # the connection raw without TLS interception. Essential for
        # cert-pinning clients (Anthropic SDK, OpenAI SDK, banking apps).
        if self._ignore_hosts:
            opts.update(ignore_hosts=self._ignore_hosts)
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.master.addons.add(self.addon)
        self._started.set()
        await self.master.run()

    def _run(self) -> None:
        try:
            asyncio.run(self._amain())
        except BaseException as e:
            self._start_error = e
            self._started.set()
            try:
                log.error("Proxy crashed: %r", e)
            except Exception:
                pass

    def stop(self) -> None:
        if self.master and self.loop:
            try:
                # master.shutdown() is a coroutine in mitmproxy 10+
                asyncio.run_coroutine_threadsafe(self.master.shutdown(), self.loop)
            except Exception as e:
                log.warning("Shutdown signal failed: %s", e)
        if self.thread:
            self.thread.join(timeout=5)
        self.master = None
        self.loop = None
        self.thread = None


# ---------------------------------------------------------------------------
# Tray application
# ---------------------------------------------------------------------------

def self_heal_stale_proxy() -> None:
    """
    If the previous run crashed (or was killed) with the proxy still active,
    the Windows registry is left pointing at 127.0.0.1:8080 with no proxy
    process listening — which breaks internet. Detect that on startup and
    restore the saved snapshot silently.
    """
    snap_file = PROXY_SNAPSHOT_PATH
    if not snap_file.exists():
        return
    current = system_proxy.snapshot_current()
    pointing_at_us = (
        current.get("ProxyEnable") == 1
        and str(current.get("ProxyServer", "")).startswith(f"{PROXY_HOST}:{PROXY_PORT}")
    )
    if not pointing_at_us:
        return
    log.warning("Stale proxy state from previous session detected — restoring")
    snap = system_proxy.load_snapshot(snap_file)
    if snap:
        try:
            system_proxy.restore(snap)
        except Exception as e:
            log.error("Restore failed, clearing proxy: %s", e)
            system_proxy.disable()
    try:
        snap_file.unlink()
    except OSError:
        pass


class InterceptifyApp:
    def __init__(self) -> None:
        self.cfg = load_config()
        self.active = False
        self.addon = BlockerAddon(ROOT)
        self.runner = ProxyRunner(self.addon)
        self.icon: Optional[pystray.Icon] = None
        # Crash / kill safety — always run on interpreter exit regardless of
        # how we got there (clean tray Exit, Ctrl+C, unhandled exception).
        import atexit
        atexit.register(self._emergency_restore)

    def _emergency_restore(self) -> None:
        """Last-ditch cleanup so we never leave the user with broken internet."""
        if not self.active:
            return
        log.warning("Emergency cleanup — restoring system proxy on exit")
        try:
            self.turn_off()
        except Exception as e:
            log.error("turn_off failed in emergency cleanup: %s", e)
            # Fallback: brute-force restore from snapshot file
            try:
                snap = system_proxy.load_snapshot(PROXY_SNAPSHOT_PATH)
                if snap:
                    system_proxy.restore(snap)
                else:
                    system_proxy.disable()
            except Exception as e2:
                log.error("Fallback restore failed: %s", e2)

    # -- helpers -----------------------------------------------------------

    def notify(self, msg: str, title: str = APP_NAME) -> None:
        # Always log too — Windows toast notifications are unreliable on some
        # setups (Focus Assist, missing Action Center prefs, etc.).
        log.info("NOTIFY: %s", msg)
        try:
            if self.icon is not None:
                self.icon.notify(msg, title)
        except Exception as e:
            log.warning("Notify failed: %s — %s", e, msg)

    def refresh_icon(self) -> None:
        if self.icon is not None:
            self.icon.icon = make_icon(self.active)
            self.icon.title = f"{APP_NAME}: {'ON' if self.active else 'OFF'}"

    # -- actions -----------------------------------------------------------

    def turn_on(self) -> None:
        # Load bypass list up front — it's used both by the proxy itself
        # (ignore_hosts → true TCP passthrough for cert-pinning clients)
        # and by the Windows system proxy (ProxyOverride → WinINET apps
        # skip the proxy entirely).
        bypass = system_proxy.load_bypass_file(BYPASS_PATH)
        log.info("Loaded %d bypass host(s) from %s", len(bypass), BYPASS_PATH.name)

        # 1. Start the proxy with ignore_hosts baked in
        if not self.runner.start(bypass_hosts=bypass):
            self.notify("Failed to start proxy — check logs.")
            return

        # 2. Snapshot current proxy settings, then enable ours
        snap = system_proxy.snapshot_current()
        system_proxy.save_snapshot(PROXY_SNAPSHOT_PATH, snap)
        system_proxy.enable(f"{PROXY_HOST}:{PROXY_PORT}", bypass_hosts=bypass)

        # 3. Install CA once (mitmproxy generates it the first time it starts)
        if not self.cfg.get("cert_installed"):
            self.notify("Installing mitmproxy CA into Trusted Root (required for HTTPS interception)...")
            ok, msg = cert_manager.install_ca()
            self.notify(msg)
            if ok:
                self.cfg["cert_installed"] = True
                save_config(self.cfg)

        self.active = True
        self.refresh_icon()
        self.notify("Blocking ON — proxy listening on 127.0.0.1:8080")

    def turn_off(self) -> None:
        # Restore proxy settings first so the user regains connectivity even
        # if proxy shutdown hangs.
        snap = system_proxy.load_snapshot(PROXY_SNAPSHOT_PATH)
        if snap is not None:
            system_proxy.restore(snap)
        else:
            system_proxy.disable()

        self.runner.stop()

        self.active = False
        self.refresh_icon()
        self.notify("Blocking OFF — system proxy restored")

    def toggle(self, *_args) -> None:
        threading.Thread(target=self._toggle_worker, daemon=True).start()

    def _toggle_worker(self) -> None:
        if self.active:
            self.turn_off()
        else:
            self.turn_on()

    def install_cert(self, *_args) -> None:
        def worker():
            cert = cert_manager.find_ca()
            log.info("Install certificate clicked. CA path: %s", cert)
            ok, msg = cert_manager.install_ca()
            log.info("Install certificate result: ok=%s msg=%s", ok, msg)
            self.notify(msg)
            if ok:
                self.cfg["cert_installed"] = True
                save_config(self.cfg)
        threading.Thread(target=worker, daemon=True).start()

    def uninstall_cert(self, *_args) -> None:
        """Remove the mitmproxy CA from the Windows Trusted Root store."""
        def worker():
            # Make sure we're not actively intercepting when the cert disappears
            if self.active:
                self.turn_off()
            ok, msg = cert_manager.remove_ca()
            log.info("Uninstall certificate result: ok=%s msg=%s", ok, msg)
            self.notify(msg)
            if ok:
                self.cfg["cert_installed"] = False
                save_config(self.cfg)
        threading.Thread(target=worker, daemon=True).start()

    def open_filters(self, *_args) -> None:
        try:
            os.startfile(str(FILTERS_DIR))  # type: ignore[attr-defined]
        except Exception as e:
            self.notify(f"Could not open filters folder: {e}")

    # -- Spotify client-side patch ----------------------------------------

    def _current_show_badge(self) -> bool:
        return bool(self.cfg.get("show_badge", True))

    def patch_spotify(self, *_args) -> None:
        """Inject Interceptify's ad-handler JS into Spotify's xpui.spa."""
        def worker():
            if not spotify_patcher.is_installed():
                self.notify("Spotify not found. Install from spotify.com (desktop, not Store).")
                return
            was_running = spotify_patcher.is_spotify_running()
            if was_running:
                spotify_patcher.kill_spotify()
                import time; time.sleep(2)
            ok, msg = spotify_patcher.patch(show_badge=self._current_show_badge())
            log.info("patch_spotify: ok=%s msg=%s", ok, msg)
            # Auto-relaunch if we had to kill it, so the user doesn't have to
            if ok and was_running:
                if spotify_patcher.launch_spotify():
                    self.notify("Spotify patched and relaunched.")
                    return
            self.notify(msg)
        threading.Thread(target=worker, daemon=True).start()

    def toggle_show_badge(self, *_args) -> None:
        """Flip the show-badge preference and re-patch Spotify to apply."""
        def worker():
            new_val = not self._current_show_badge()
            self.cfg["show_badge"] = new_val
            save_config(self.cfg)
            if not spotify_patcher.is_installed():
                self.notify(f"Badge preference saved ({'on' if new_val else 'off'}). Spotify not installed.")
                return
            was_running = spotify_patcher.is_spotify_running()
            if was_running:
                spotify_patcher.kill_spotify()
                import time; time.sleep(2)
            ok, msg = spotify_patcher.patch(show_badge=new_val)
            log.info("toggle_show_badge -> %s: %s", new_val, msg)
            if ok and was_running and spotify_patcher.launch_spotify():
                self.notify(f"Status dot {'shown' if new_val else 'hidden'}. Spotify relaunched.")
                return
            if ok:
                self.notify(f"Status dot {'shown' if new_val else 'hidden'}. Restart Spotify to apply.")
            else:
                self.notify(msg)
        threading.Thread(target=worker, daemon=True).start()

    def unpatch_spotify(self, *_args) -> None:
        """Restore Spotify's original xpui.spa from backup."""
        def worker():
            was_running = spotify_patcher.is_spotify_running()
            if was_running:
                spotify_patcher.kill_spotify()
                import time; time.sleep(2)
            ok, msg = spotify_patcher.unpatch()
            log.info("unpatch_spotify: ok=%s msg=%s", ok, msg)
            if ok and was_running and spotify_patcher.launch_spotify():
                self.notify("Spotify restored and relaunched.")
                return
            self.notify(msg)
        threading.Thread(target=worker, daemon=True).start()

    def open_bypass(self, *_args) -> None:
        """Open bypass.txt — hosts that should never be intercepted."""
        try:
            if not BYPASS_PATH.exists():
                BYPASS_PATH.write_text(
                    "# One host per line. Wildcards with * supported.\n",
                    encoding="utf-8",
                )
            os.startfile(str(BYPASS_PATH))  # type: ignore[attr-defined]
            self.notify("Edit bypass.txt, then toggle OFF/ON to apply.")
        except Exception as e:
            self.notify(f"Could not open bypass.txt: {e}")

    def capture_ad(self, *_args) -> None:
        """
        Learn-mode: the user just heard/saw an ad. Pause it, click this, and we
        promote ad-shaped requests from the last 30s of traffic into
        ``filters/spotify-learned.txt`` (deduped, persisted, reloaded live).
        Commit that file to git to share your finds.
        """
        def worker():
            added, rules, path = self.addon.capture_candidates(app="spotify", window_sec=30)
            if added == 0:
                self.notify(
                    "No new ad-shaped requests in the last 30s. "
                    "Try clicking sooner after the ad starts, or check blocked.log."
                )
                return
            preview = "\n".join(rules[:5])
            more = f"\n(+{added - 5} more)" if added > 5 else ""
            self.notify(f"Captured {added} new rule(s) into {path.name}:\n{preview}{more}")
        threading.Thread(target=worker, daemon=True).start()

    def reload_filters(self, *_args) -> None:
        try:
            self.addon.engine.reload()
            self.notify(f"Filters reloaded — {len(self.addon.engine.rules)} rules active")
        except Exception as e:
            self.notify(f"Reload failed: {e}")

    def view_blocked(self, *_args) -> None:
        self.notify(self.addon.summary())
        # Also open the raw log for detail
        try:
            if BLOCKED_LOG.exists():
                os.startfile(str(BLOCKED_LOG))  # type: ignore[attr-defined]
        except Exception as e:
            log.warning("Open log failed: %s", e)

    def quit_app(self, *_args) -> None:
        if self.active:
            self.turn_off()
        if self.icon is not None:
            self.icon.stop()

    # -- menu --------------------------------------------------------------

    def build_menu(self) -> Menu:
        return Menu(
            Item("Toggle", self.toggle, default=True),
            Menu.SEPARATOR,
            Item("🎵 Ad is playing — capture now", self.capture_ad),
            Item("Reload filters", self.reload_filters),
            Menu.SEPARATOR,
            Item("Patch Spotify (client-side ad block)", self.patch_spotify),
            Item("Unpatch Spotify", self.unpatch_spotify),
            Item(
                "Show status dot in Spotify",
                self.toggle_show_badge,
                checked=lambda item: self._current_show_badge(),
            ),
            Menu.SEPARATOR,
            Item("Install certificate", self.install_cert),
            Item("Uninstall certificate", self.uninstall_cert),
            Item("Open filter rules", self.open_filters),
            Item("Open bypass list", self.open_bypass),
            Item("View blocked requests", self.view_blocked),
            Menu.SEPARATOR,
            Item("Exit", self.quit_app),
        )

    def run(self) -> None:
        self.icon = pystray.Icon(
            APP_NAME,
            icon=make_icon(False),
            title=f"{APP_NAME}: OFF",
            menu=self.build_menu(),
        )
        self.icon.run()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if not is_admin():
        relaunch_as_admin()
        return
    # Heal before constructing the app so any stale proxy state is gone first
    self_heal_stale_proxy()
    app = InterceptifyApp()
    try:
        app.run()
    finally:
        # Belt-and-braces on top of the atexit hook
        app._emergency_restore()


if __name__ == "__main__":
    main()
