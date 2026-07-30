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
import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
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
APP_VERSION = "2.0.5"  # bump in lockstep with the GitHub tag

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


def sync_bundled_extensions() -> Optional[str]:
    """Keep the injected payload in step with this executable.

    Returns None on success, or a message describing why the on-disk payload is
    NOT the one this build ships.

    The old behaviour copied ``extensions/`` out of the bundle only when the
    directory did not already exist. Combined with an updater that replaces just
    the .exe, that meant a successful update could leave the app permanently
    injecting the *previous* release's JavaScript - the version string moved, the
    thing doing the actual work did not.

    Three files, three different owners:

      adblock.js               code. Belongs to the release; overwritten.
      adblock.config.json      SHIPPED defaults. Also belongs to the release, so
                               it is overwritten too. It holds Spotify-build
                               specific module ids, selectors and regexes, and
                               those are the values a release exists to fix. The
                               previous "merge new keys, never touch existing
                               ones" rule meant a corrected `instreamModuleFallbackId`
                               could never reach anyone who already had the file.
      adblock.config.local.json  the USER's overrides, and the machine-specific
                               keys self-heal discovers. Never overwritten, and
                               merged on top of the shipped defaults at patch
                               time, so a release fix lands without discarding
                               local knowledge.

    The shipped file's sha is stamped in `.shipped-config.sha256` when we write
    it, which is what makes "the user edited this" distinguishable from "this is
    just the last release's copy". Content alone cannot tell those apart, and the
    first attempt at this migration guessed - it treated every difference as a
    user override, so a release correcting a build-volatile key recorded that
    correction as a local override of itself and the fix never took effect.
    """
    src_dir = bundled_root() / "extensions"
    dst_dir = ROOT / "extensions"
    if not src_dir.is_dir() or src_dir == dst_dir:
        return None
    dst_dir.mkdir(parents=True, exist_ok=True)

    src_js, dst_js = src_dir / "adblock.js", dst_dir / "adblock.js"
    try:
        if src_js.is_file():
            new = src_js.read_bytes()
            if (not dst_js.exists()) or dst_js.read_bytes() != new:
                dst_js.write_bytes(new)
                log.info("Payload updated from bundle (%s)", APP_VERSION)
    except Exception as e:
        # This is not a warning. Every downstream integrity check compares the
        # live patch against this external file, so a failed sync leaves the
        # patcher and the self-heal agreeing with each other about a payload that
        # is not the one in the build. Refusing to patch is the honest outcome.
        log.error("Could not sync adblock.js: %s", e)
        return (f"The payload on disk could not be updated to this build ({APP_VERSION}): {e}. "
                f"Patching is disabled until {dst_js} is writable.")

    src_cfg = src_dir / "adblock.config.json"
    dst_cfg = dst_dir / "adblock.config.json"
    local_cfg = dst_dir / "adblock.config.local.json"
    # Records the sha of the shipped config THIS install last wrote. It is what
    # makes "the user edited it" distinguishable from "it is simply the previous
    # release's file", which is a distinction the content alone cannot make.
    stamp = dst_dir / ".shipped-config.sha256"
    try:
        if not src_cfg.is_file():
            return None
        new_bytes = src_cfg.read_bytes()
        new_sha = hashlib.sha256(new_bytes).hexdigest()

        if not dst_cfg.exists():
            dst_cfg.write_bytes(new_bytes)
            stamp.write_text(new_sha, encoding="utf-8")
            log.info("Seeded adblock.config.json from bundle")
            return None

        # An unparseable shipped config is quarantined and replaced rather than
        # tolerated. It used to warn and continue, and the patcher would then
        # inject an effectively empty config while everything reported success.
        try:
            json.loads(dst_cfg.read_text(encoding="utf-8"))
        except Exception as e:
            bad = dst_dir / f"adblock.config.corrupt-{time.strftime('%Y%m%d-%H%M%S')}.json"
            dst_cfg.replace(bad)
            dst_cfg.write_bytes(new_bytes)
            stamp.write_text(new_sha, encoding="utf-8")
            log.error("adblock.config.json was not valid JSON (%s). Quarantined as %s and "
                      "restored the shipped defaults.", e, bad.name)
            return None

        cur_bytes = dst_cfg.read_bytes()
        cur_sha = hashlib.sha256(cur_bytes).hexdigest()
        if cur_sha == new_sha:
            stamp.write_text(new_sha, encoding="utf-8")
            return None

        known = stamp.read_text(encoding="utf-8").strip() if stamp.exists() else None
        if known == cur_sha:
            # Untouched since we wrote it. Nothing to preserve, so take the new
            # defaults wholesale. The previous code diffed the two files and
            # treated EVERY difference as a user override, which meant a release
            # that corrected a module id, a selector or a gate key was recorded
            # as a local override of itself and could never take effect.
            dst_cfg.write_bytes(new_bytes)
            stamp.write_text(new_sha, encoding="utf-8")
            log.info("Shipped adblock.config.json updated from bundle")
            return None

        # Modified, or from before this install started stamping. We cannot tell
        # a deliberate edit from a stale release's file, and guessing in either
        # direction is a way to be wrong silently - keep the old values and the
        # fix never lands; drop them and the user's work disappears. So: install
        # the new defaults (the fix lands), and set the old file aside intact
        # under a name that says what it is.
        keep = dst_dir / f"adblock.config.superseded-{time.strftime('%Y%m%d-%H%M%S')}.json"
        keep.write_bytes(cur_bytes)
        dst_cfg.write_bytes(new_bytes)
        stamp.write_text(new_sha, encoding="utf-8")
        log.warning("adblock.config.json had been modified. The new shipped defaults are now "
                    "active and your previous file is kept at %s — copy anything you meant to "
                    "change into adblock.config.local.json, which is never overwritten.",
                    keep.name)
    except Exception as e:
        # Fatal, exactly like the payload above, and for exactly the same reason.
        # The config is half of what gets injected - slot ids, selectors, module
        # ids, gate patterns - and this was the only half whose sync failure was
        # advisory. A newer build could therefore inject an OLDER config while
        # every internal check agreed with itself, which is the failure the
        # injected-config fingerprint was added to catch. Better to refuse to
        # patch than to patch with values this build does not ship.
        log.error("Could not sync adblock.config.json: %s", e)
        return (f"The config on disk could not be updated to this build ({APP_VERSION}): {e}. "
                f"Patching is disabled until {dst_cfg} is writable.")
    return None


ROOT = app_root()
CONFIG_PATH = ROOT / "config.json"

# Every start, not just the first: an update that changes the payload has to
# reach the payload on disk, because that is the file the patcher injects. A
# failure here is fatal to patching rather than advisory - see the docstring.
spotify_patcher.PAYLOAD_SYNC_ERROR = sync_bundled_extensions()


# ---------------------------------------------------------------------------
# Privileges
#
# Interceptify runs as the invoking user. It used to demand Administrator and
# self-elevate on launch, which was both unnecessary and actively harmful:
# Spotify's xpui.spa, its prefs and our own config are all owned by the logged-in
# user with full control, so elevation bought no capability at all. What it did
# buy was a privilege-escalation shape - a high-integrity process launched from a
# directory that grants BUILTIN\Users:(M), so anything able to write there gets
# its code run elevated.
#
# The honest replacement is a writability preflight: check the one file we
# actually need to modify and say precisely what is wrong when we cannot.
# ---------------------------------------------------------------------------

def xpui_write_problem() -> Optional[str]:
    """Why we could not patch, or None if the path is writable.

    Opening for append is the real test. Checking an ACL, or checking whether we
    happen to be admin, answers a different question than "can this process
    modify this file" - which is the only question that matters here.
    """
    xpui = spotify_patcher.spotify_xpui_path()
    if not xpui.exists():
        return None                      # not installed is a separate condition
    try:
        with open(xpui, "ab"):
            pass
        return None
    except PermissionError:
        if spotify_patcher.is_spotify_running():
            return "Spotify has xpui.spa open. Close Spotify and try again."
        return (f"No write access to {xpui}. Interceptify runs as you, not as "
                f"Administrator, so this file must be writable by your account.")
    except OSError as e:
        return f"Cannot open {xpui}: {e}"


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
        self._autostart_cache: Optional[tuple[bool, float]] = None

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
            # The writability preflight that replaced the admin gate. It was
            # written and documented and then never actually called, so the
            # honest error it exists to produce ("Spotify has xpui.spa open",
            # "this file is not writable by your account") had no way to reach
            # anyone - they got whatever the failing write happened to raise.
            problem = xpui_write_problem()
            if problem:
                log.warning("patch_spotify: refused, %s", problem)
                self.notify(problem)
                return
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
        # Refuse to update into a split deployment. The updater replaces this
        # .exe and nothing else, so if autostart still launches a source
        # checkout, the update lands here while the OTHER install keeps
        # re-patching Spotify with its own older payload at every logon. Moving
        # one of two halves forward is worse than not updating: the version
        # string advances and the code that runs does not.
        warn = self._deployment_warning()
        if warn:
            self.notify("Update blocked. " + warn)
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
                    expected_sha256=rel.exe_asset_sha256,
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
    #
    # This used to write an HKCU\...\Run value while install_tasks.py registered
    # a scheduled task for the same thing. Both switched on meant two trays and
    # two self-heals, each patching xpui.spa with whatever payload its own copy
    # of the tree held, and the survivor was whichever finished last. There is
    # one autostart mechanism now, and this menu item drives it.

    # pystray evaluates every `checked=` callback each time the menu is drawn,
    # and answering this honestly costs four `schtasks /query` subprocesses. Read
    # straight through, right-clicking the tray icon would stall for a
    # noticeable fraction of a second. Cached briefly and invalidated whenever
    # we are the ones who changed it, so the menu stays instant without ever
    # showing a state we know to be stale.
    _AUTOSTART_TTL = 10.0

    def _is_autostart_enabled(self, fresh: bool = False) -> bool:
        now = time.monotonic()
        if not fresh and self._autostart_cache is not None:
            value, at = self._autostart_cache
            if now - at < self._AUTOSTART_TTL:
                return value
        try:
            import install_tasks
            value = all(not install_tasks.wrong_with(install_tasks.describe(n), cmd, trg)
                        for n, cmd, _, trg in install_tasks.tasks())
        except Exception:
            value = False
        self._autostart_cache = (value, now)
        return value

    def toggle_autostart(self, *_args) -> None:
        try:
            import install_tasks
            if self._is_autostart_enabled(fresh=True):
                install_tasks.remove()
                self.notify("Auto-start at Windows login: OFF")
            else:
                rc = install_tasks.install()
                self.notify("Auto-start at Windows login: ON" if rc == 0 else
                            "Auto-start could not be fully registered - see the log.")
        except Exception as e:
            self.notify(f"Auto-start toggle failed: {e}")
        self._autostart_cache = None       # we just changed it; never serve the old answer
        self.refresh_icon()

    def _deployment_warning(self) -> Optional[str]:
        """Autostart entries that belong to the other deployment model.

        A packaged .exe that self-updates while a source checkout still owns the
        logon tasks leaves the old source re-patching Spotify with its own
        payload, forever. The updater only moves one of the two forward.
        """
        try:
            import install_tasks
            foreign = install_tasks.foreign_deployment_tasks()
        except Exception:
            return None
        if not foreign:
            return None
        return ("Autostart is registered for a different Interceptify install "
                f"({', '.join(n for n, _ in foreign)}). It can re-patch Spotify with an "
                "older payload. Use 'Run at Windows startup' to re-register it for this one.")

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

        # Say the two things that make this build lie about itself, at the one
        # moment someone is looking at it.
        def _startup_warnings() -> None:
            time.sleep(2.0)
            if spotify_patcher.PAYLOAD_SYNC_ERROR:
                self.notify(spotify_patcher.PAYLOAD_SYNC_ERROR)
            warn = self._deployment_warning()
            if warn:
                log.warning("%s", warn)
                self.notify(warn)
        threading.Thread(target=_startup_warnings, daemon=True).start()
        self.icon.run()


# ---------------------------------------------------------------------------
# Entry point
#
# The packaged build is the whole application, not just the tray: it carries the
# self-heal and the scheduler too, reached as subcommands. Before this, the .exe
# contained neither, so a packaged install could only get autostart by pointing
# scheduled tasks at a source checkout - two deployments, two payloads, and an
# updater that moves only one of them.
# ---------------------------------------------------------------------------

def _attach_parent_console() -> None:
    """Give a subcommand somewhere to print.

    The .exe is built windowed, which is right for a tray app and for the silent
    scheduled runs - but it also means every `print()` in --selfheal and
    --install-tasks went nowhere. `Interceptify.exe --install-tasks --status`
    produced no output at all and looked like it had done nothing. Attaching to
    the console that launched us costs nothing when there isn't one.
    """
    if not getattr(sys, "frozen", False):
        return
    try:
        import ctypes
        ATTACH_PARENT_PROCESS = -1
        if not ctypes.windll.kernel32.AttachConsole(ATTACH_PARENT_PROCESS):
            return
        for stream, mode in (("stdout", "w"), ("stderr", "w")):
            try:
                setattr(sys, stream, open("CONOUT$", mode, encoding="utf-8", errors="replace"))
            except OSError:
                pass
    except Exception:
        pass


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        _attach_parent_console()
    if argv and argv[0] == "--selfheal":
        import selfheal
        return selfheal.main(argv[1:])
    if argv and argv[0] == "--install-tasks":
        import install_tasks
        return install_tasks.main(argv[1:])
    if argv and argv[0] in ("--version", "-V"):
        print(f"{APP_NAME} {APP_VERSION}")
        return 0
    InterceptifyApp().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
