"""
HostsBlock Pro — Windows tray app that runs an embedded mitmproxy to block
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
import system_proxy
from proxy_addon import BlockerAddon

APP_NAME = "HostsBlock Pro"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("hostsblock")


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent


ROOT = app_root()
CONFIG_PATH = ROOT / "config.json"
PROXY_SNAPSHOT_PATH = ROOT / "proxy_snapshot.json"
FILTERS_DIR = ROOT / "filters"
BLOCKED_LOG = ROOT / "blocked.log"


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

class ProxyRunner:
    """Owns the DumpMaster and the thread running its event loop."""

    def __init__(self, addon: BlockerAddon):
        self.addon = addon
        self.master: Optional[DumpMaster] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None
        self._started = threading.Event()
        self._start_error: Optional[BaseException] = None

    def start(self) -> bool:
        if self.thread and self.thread.is_alive():
            return True
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

class HostsBlockProApp:
    def __init__(self) -> None:
        self.cfg = load_config()
        self.active = False
        self.addon = BlockerAddon(ROOT)
        self.runner = ProxyRunner(self.addon)
        self.icon: Optional[pystray.Icon] = None

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
        # 1. Start the proxy
        if not self.runner.start():
            self.notify("Failed to start proxy — check logs.")
            return

        # 2. Snapshot current proxy settings, then enable ours
        snap = system_proxy.snapshot_current()
        system_proxy.save_snapshot(PROXY_SNAPSHOT_PATH, snap)
        system_proxy.enable(f"{PROXY_HOST}:{PROXY_PORT}")

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

    def open_filters(self, *_args) -> None:
        try:
            os.startfile(str(FILTERS_DIR))  # type: ignore[attr-defined]
        except Exception as e:
            self.notify(f"Could not open filters folder: {e}")

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
            Item("Install certificate", self.install_cert),
            Item("Open filter rules", self.open_filters),
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
    HostsBlockProApp().run()


if __name__ == "__main__":
    main()
