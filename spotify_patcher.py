"""
Minimal Spotify desktop client patcher.

Spotify ships its UI as an Electron/CEF app whose HTML + JS + CSS are packed
into ``%APPDATA%\\Spotify\\Apps\\xpui.spa`` (a ZIP archive). We inline our
ad-handler JS (``extensions/adblock.js``) into ``index.html`` and bake the
runtime tunables (``extensions/adblock.config.json``) into
``window.__INTERCEPTIFY_CONFIG`` immediately before it.

Flow:
    patch()   -> backup + inject (inline adblock.js + config prelude)
    unpatch() -> restore from backup
    is_patched() -> detect marker

Spotify auto-updates re-download xpui.spa and wipe the patch; the tray menu
re-applies it (optionally automatically, via the local update watcher).
"""

from __future__ import annotations

import logging
import os
import shutil
import time
import zipfile
from pathlib import Path

import patch_lock

log = logging.getLogger("interceptify")


def spotify_xpui_path() -> Path:
    appdata = os.environ.get("APPDATA", "")
    return Path(appdata) / "Spotify" / "Apps" / "xpui.spa"


BACKUP_SUFFIX = ".interceptify-backup"
MARKER = "<!-- INTERCEPTIFY_PATCHED -->"

# Set by main.py when the payload on disk could not be brought up to this
# build's version. Every integrity check downstream compares the live patch
# against that external file, so a failed sync makes the patcher and the
# self-heal agree with each other about code that is not in this build. Patching
# is refused rather than performed with a payload nobody chose.
PAYLOAD_SYNC_ERROR: str | None = None

# The payload is inlined into index.html between these sentinels, and NOTHING
# else is written into the archive. There used to be a second copy added as a
# loose `interceptify-adblock.js` member, which Spotify never loads - and the
# integrity check hashed that dead copy instead of the script that actually
# runs. One copy, one hash, no way for the two to disagree.
BEGIN_SENTINEL = "// @interceptify-adblock begin"
END_SENTINEL = "// @interceptify-adblock end"

# Where our adblock JS lives in this project.
def _root() -> Path:
    """The install directory.

    Prefers main.ROOT, which resolves to the .exe's own directory in a frozen
    build - not the same place as this module, which PyInstaller unpacks into a
    temp dir. Falls back to this file's directory so the module can be imported
    on its own, which is what lets the patch/unpatch round-trip run in CI
    without the tray's GUI dependencies.
    """
    try:
        from main import ROOT  # lazy: avoids a circular import at module load
        return ROOT
    except Exception:
        return Path(__file__).resolve().parent


def _my_adblock_path() -> Path:
    return _root() / "extensions" / "adblock.js"


def _my_adblock_config_path() -> Path:
    """Shipped defaults. Owned by the release and replaced on every update."""
    return _root() / "extensions" / "adblock.config.json"


def _my_adblock_local_config_path() -> Path:
    """The user's overrides and whatever self-heal has discovered on THIS
    machine. Never overwritten by an update, and merged on top of the shipped
    defaults."""
    return _root() / "extensions" / "adblock.config.local.json"


class ConfigError(Exception):
    """The effective config could not be built, so we must not patch.

    Silently falling back to `{}` here is worse than failing. Every
    build-volatile value - selectors, module ids, gate-key patterns, ad URL
    signals - lives in that file, so an unparseable config means injecting a
    payload with nothing but its compiled-in defaults while the app reports a
    successful patch. That is a blocker dressed as a warning.
    """


def _read_config_file(p: Path) -> dict:
    import json
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception as e:
        raise ConfigError(f"{p.name} is not valid JSON ({e})") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{p.name} does not contain a JSON object")
    # Any leading-underscore key is an editor's note, not a tunable. Only
    # "_comment" used to be stripped, so a second note would have been injected
    # into the page as though it were configuration.
    return {k: v for k, v in data.items() if not k.startswith("_")}


def load_adblock_config() -> dict:
    """Shipped defaults with the local overrides merged on top.

    Two files, because they answer to different owners. The shipped file holds
    Spotify-build-specific module ids, selectors and regexes - exactly the values
    a release exists to correct - so it must be replaceable. The local file holds
    the user's choices and the keys self-heal discovered here, so it must
    survive. Keeping both in one file meant a release fix could never reach
    anyone who already had it.
    """
    cfg = _read_config_file(_my_adblock_config_path())
    cfg.update(_read_config_file(_my_adblock_local_config_path()))
    return cfg


def effective_config_sha() -> str:
    """sha256 of the merged config that would actually be injected.

    Lets callers answer "has anything about the block changed since then?"
    without caring which of the two files moved.
    """
    import hashlib
    import json
    return hashlib.sha256(
        json.dumps(load_adblock_config(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def config_problem() -> str | None:
    """Why the effective config cannot be built, or None if it can."""
    try:
        load_adblock_config()
        return None
    except ConfigError as e:
        return str(e)


def _load_adblock_config_json() -> str:
    """The merged tunables as a compact JSON string, injected as
    ``window.__INTERCEPTIFY_CONFIG``. adblock.js shallow-merges it over its
    built-in defaults, so a Spotify-update fix is a JSON edit + re-patch rather
    than a code change."""
    import json
    return json.dumps(load_adblock_config(), separators=(",", ":"))


# ---------------------------------------------------------------------------

def is_installed() -> bool:
    return spotify_xpui_path().exists()


_DEVTOOLS_FLAG = 'app.browser.enable-developer-mode="true"'


def _spotify_prefs_path() -> Path:
    return Path(os.environ.get("APPDATA", "")) / "Spotify" / "prefs"


def _devtools_owned_marker() -> Path:
    """Records that WE added the developer-mode flag.

    Without it, "remove the flag on a normal patch" silently turns off a setting
    the user may have enabled themselves, for their own reasons, and they get no
    say and no notice. We only undo our own change.
    """
    return _root() / ".interceptify-devtools-owned"


def enable_devtools() -> None:
    """Flip the Spotify prefs flag that allows Ctrl+Shift+I to open DevTools.

    Debug-only: callers gate this behind debug-capture mode so a normal patch
    does not permanently alter Spotify's security posture.
    """
    prefs = _spotify_prefs_path()
    if not prefs.exists():
        return
    try:
        text = prefs.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    if _DEVTOOLS_FLAG in text:
        return                       # already on, and not by us: leave it alone
    if not text.endswith("\n"):
        text += "\n"
    text += _DEVTOOLS_FLAG + "\n"
    try:
        prefs.write_text(text, encoding="utf-8")
        try:
            _devtools_owned_marker().write_text("1", encoding="utf-8")
        except OSError:
            pass
        log.info("Enabled Spotify DevTools (Ctrl+Shift+I)")
    except Exception as e:
        log.warning("Could not write Spotify prefs: %s", e)


def disable_devtools() -> None:
    """Remove the developer-mode prefs flag **if Interceptify added it**.

    This used to strip the flag unconditionally on every non-debug patch, so a
    user who had turned developer mode on themselves lost it the next time
    Interceptify ran, with no notice. A tool that cleans up after itself is
    right; one that also cleans up after you is not.
    """
    marker = _devtools_owned_marker()
    if not marker.exists():
        return
    prefs = _spotify_prefs_path()
    if not prefs.exists():
        return
    try:
        text = prefs.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    if _DEVTOOLS_FLAG not in text:
        marker.unlink(missing_ok=True)
        return
    kept = [ln for ln in text.splitlines() if ln.strip() != _DEVTOOLS_FLAG]
    try:
        prefs.write_text(("\n".join(kept) + "\n") if kept else "", encoding="utf-8")
        marker.unlink(missing_ok=True)
        log.info("Removed the Spotify developer-mode flag Interceptify had set")
    except Exception as e:
        log.warning("Could not write Spotify prefs: %s", e)


def _index_html(xpui: Path) -> str:
    with zipfile.ZipFile(xpui, "r") as z:
        return z.read("index.html").decode("utf-8", errors="replace")


def strip_injection(html: str) -> str:
    """index.html with every Interceptify block removed.

    Needed to build an honest backup. The backup is meant to be pristine
    Spotify, but it was created by copying whatever was on disk - so patching a
    client that some *earlier* Interceptify build had already patched stored a
    patched archive as the baseline. "Restore original" then restored the old
    payload, permanently, and the fingerprint compared the live payload against
    a backup that was never clean.

    That is not hypothetical: it is the 2026-07-16 incident, where a stale build
    re-patched with an April payload. Removing our own block is deterministic
    because the injection is delimited: it runs from the marker to the end of
    the script tag that follows it.
    """
    while True:
        i = html.find(MARKER)
        if i < 0:
            return html
        end = html.find("</script>", i)
        if end < 0:
            # A marker with no closing tag means the file was truncated or hand
            # edited. Dropping the rest would mangle Spotify, so leave it and
            # let the caller's verification fail loudly instead.
            return html
        html = html[:i] + html[end + len("</script>"):]


def _payload_in_html(html: str) -> str | None:
    i = html.find(BEGIN_SENTINEL)
    j = html.find(END_SENTINEL, i + 1) if i >= 0 else -1
    if i < 0 or j < 0:
        return None
    return html[i + len(BEGIN_SENTINEL):j]


def inline_payload_of(path: Path) -> str | None:
    """The JS the given archive would execute, or None if it is not patched."""
    if not path.exists():
        return None
    try:
        return _payload_in_html(_index_html(path))
    except Exception:
        return None


def inline_payload() -> str | None:
    """The JS Spotify actually executes, or None if we are not patched.

    This is the only source of truth for "what is running". Anything that hashes
    a file on our side, or a spare copy inside the archive, is measuring
    something that is merely *supposed* to match.
    """
    return inline_payload_of(spotify_xpui_path())


def _sha_payload(body: str | None) -> str | None:
    if body is None:
        return None
    import hashlib
    return hashlib.sha256(body.strip("\r\n").encode("utf-8")).hexdigest()


def inline_payload_sha_of(path: Path) -> str | None:
    return _sha_payload(inline_payload_of(path))


def inline_payload_sha() -> str | None:
    """sha256 of the executing payload, comparable to the sha of our own file."""
    return _sha_payload(inline_payload())


# --- the CONFIG Spotify is actually running ------------------------------
#
# The payload is only half of what gets injected. The other half is the merged
# config, written into the page as a `window.__INTERCEPTIFY_CONFIG` prelude at
# patch time - so editing a config FILE changes nothing about the running client
# until a re-patch happens.
#
# Nothing measured that. The fingerprint compared payload hashes only, which
# means: change a slot id, a selector, a module id or a gate pattern in the
# sidecar, and every check still reports healthy while Spotify keeps running the
# old values indefinitely. Worse, "the block changed" - the precondition for
# clearing a recorded ad delivery - was computed from the sidecar too, so an
# edit that never reached the page could retire a real failure.
#
# A config that is published but not injected is the same class of bug as a knob
# that is read but never published: it looks applied and is not.

_CONFIG_ASSIGN = "window.__INTERCEPTIFY_CONFIG ="


def _config_in_html(html: str) -> dict | None:
    """The config object the patched page assigns, parsed, or None.

    Parsed with raw_decode rather than matched with a regex: several published
    values are themselves regex sources containing braces, quotes and
    semicolons, so any "find the closing brace" pattern is guessing. raw_decode
    reads exactly one JSON value and reports where it ended.
    """
    i = html.find(MARKER)
    j = html.find(BEGIN_SENTINEL, i + 1) if i >= 0 else -1
    if i < 0 or j < 0:
        return None
    region = html[i:j]
    k = region.find(_CONFIG_ASSIGN)
    if k < 0:
        return None
    import json
    try:
        obj, _ = json.JSONDecoder().raw_decode(region[k + len(_CONFIG_ASSIGN):].lstrip())
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def _sha_config(cfg: dict | None) -> str | None:
    """Canonical hash of a config mapping.

    Identical normalisation to effective_config_sha(), so the two are genuinely
    comparable quantities rather than two hashes that merely look alike.
    """
    if cfg is None:
        return None
    import hashlib
    import json
    return hashlib.sha256(
        json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def inline_config_of(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return _config_in_html(_index_html(path))
    except Exception:
        return None


def inline_config_sha_of(path: Path) -> str | None:
    return _sha_config(inline_config_of(path))


def inline_config_sha() -> str | None:
    """sha256 of the config Spotify is actually running."""
    return inline_config_sha_of(spotify_xpui_path())


def verify_patched_archive(path: Path) -> str | None:
    """None if `path` is a sound, correctly-patched xpui.spa, else why not.

    Run on the TEMP file, before it replaces Spotify's live archive. The check
    used to run only afterwards, so a bad rewrite had already been installed by
    the time it was detected - patch() returned failure while Spotify was left
    holding the broken archive.

    "Exactly one" is checked, not just "at least one". Two stacked injections is
    a real state - it is what a re-patch of an already-patched client produces if
    the strip step ever regresses - and it is invisible to a marker test: the
    page would run two payloads, both installing hooks, and every presence check
    would still say yes.
    """
    try:
        with zipfile.ZipFile(path, "r") as z:
            bad = z.testzip()
            if bad is not None:
                return f"archive is corrupt at member {bad}"
            names = set(z.namelist())
            if "index.html" not in names:
                return "no index.html in the rebuilt archive"
            html = z.read("index.html").decode("utf-8", errors="replace")
    except Exception as e:
        return f"rebuilt archive is not readable as a ZIP: {e}"

    n_marker = html.count(MARKER)
    n_begin = html.count(BEGIN_SENTINEL)
    n_end = html.count(END_SENTINEL)
    if n_marker != 1 or n_begin != 1 or n_end != 1:
        return (f"expected exactly one injection, found marker x{n_marker}, "
                f"sentinels x{n_begin}/{n_end}")
    # The prelude lives between the marker and the payload. Counting its globals
    # across the whole document would only count the payload READING them, which
    # it does several times - so look at the region that is supposed to contain
    # exactly one assignment, and count there.
    prelude = html[html.find(MARKER):html.find(BEGIN_SENTINEL)]
    if prelude.count("window.__INTERCEPTIFY_CONFIG =") != 1:
        return (f"expected exactly one config prelude, found "
                f"{prelude.count('window.__INTERCEPTIFY_CONFIG =')}")

    live, ours = _sha_payload(_payload_in_html(html)), our_payload_sha()
    if live is None:
        return "the payload sentinels are missing from index.html"
    if live != ours:
        return f"payload hash mismatch (archive={live}, expected={ours})"
    # The prelude has to parse back to the config we meant to inject. Counting
    # the assignment only proves a string is present; it says nothing about
    # whether the object survived serialisation intact, and the config is half
    # of what determines the block's behaviour.
    live_cfg = _config_in_html(html)
    if live_cfg is None:
        return "the config prelude is present but does not parse back to a JSON object"
    want_cfg = effective_config_sha()
    got_cfg = _sha_config(live_cfg)
    if got_cfg != want_cfg:
        return f"config hash mismatch (archive={got_cfg}, expected={want_cfg})"
    return None


def _backup_stamp_path(backup: Path) -> Path:
    return backup.with_name(backup.name + ".sha256")


def backup_problem(xpui: Path, backup: Path) -> str | None:
    """Why the backup cannot be trusted as this install's baseline, or None.

    A backup is only a valid restore target for the archive it was taken from,
    and until now nothing recorded which one that was. Stamping its hash when we
    write it means a backup that was swapped, truncated or left over from an
    older Spotify is a detectable condition rather than a silent downgrade
    waiting for the next unpatch.
    """
    if not backup.exists():
        return "no backup exists"
    stamp = _backup_stamp_path(backup)
    if not stamp.exists():
        return None                      # pre-stamp backup: unknown, not wrong
    try:
        want = stamp.read_text(encoding="utf-8").strip()
        import hashlib
        got = hashlib.sha256(backup.read_bytes()).hexdigest()
    except Exception as e:
        return f"could not verify the backup: {e}"
    if want != got:
        return (f"the backup has changed since Interceptify wrote it "
                f"(recorded {want[:16]}, found {got[:16]})")
    return None


def our_payload_sha() -> str | None:
    """sha256 of the payload we would inject, computed identically."""
    try:
        import hashlib
        src = _my_adblock_path().read_text(encoding="utf-8")
        return hashlib.sha256(src.strip("\r\n").encode("utf-8")).hexdigest()
    except Exception:
        return None


def is_patched() -> bool:
    p = spotify_xpui_path()
    if not p.exists():
        return False
    try:
        return MARKER in _index_html(p)
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


def kill_spotify(timeout: float = 10.0) -> bool:
    """Stop Spotify and wait until it is really gone. True if it exited.

    Asks politely first: /F on a running Spotify loses whatever it had not yet
    flushed, and the only thing we actually need is for it to release xpui.spa.
    Escalates to a forced kill only if it is still there.

    Callers used to `taskkill /F` then `time.sleep(2)` and start rewriting the
    archive. Two seconds is a guess, and on a slow or busy machine the guess is
    wrong in the one direction that matters: the file is still open and the
    rewrite fails, or worse, half-succeeds.
    """
    import subprocess
    for force in (False, True):
        if not is_spotify_running():
            return True
        cmd = ["taskkill", "/IM", "Spotify.exe"] + (["/F"] if force else [])
        subprocess.run(cmd, capture_output=True, creationflags=0x08000000)
        deadline = time.monotonic() + (timeout / 2.0)
        while time.monotonic() < deadline:
            if not is_spotify_running():
                return True
            time.sleep(0.25)
    still = is_spotify_running()
    if still:
        log.warning("Spotify still running after kill + %.0fs wait", timeout)
    return not still


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


def launch_spotify(remote_debug_port: int = 0) -> bool:
    """
    Start Spotify detached from our process.

    Spotify is an Electron app. Passing ``--remote-debugging-port=N`` makes
    its renderer expose a Chrome DevTools Protocol endpoint on localhost:N,
    so we can attach DevTools from a local Chromium browser even though
    Spotify removed the Ctrl+Shift+I shortcut on recent builds.
    Set ``remote_debug_port=0`` (the default) to disable — remote debugging is
    opt-in (debug mode) because a CDP endpoint can drive Spotify's
    authenticated renderer.
    """
    exe = spotify_exe_path()
    if not exe.exists():
        return False
    try:
        import subprocess
        args = [str(exe)]
        if remote_debug_port:
            args.append(f"--remote-debugging-port={remote_debug_port}")
            # Bind to loopback and allow ONLY this port's local DevTools
            # origins. Never "*": a wildcard lets any local process — or, via
            # DNS-rebinding, any web page the user visits — connect to the CDP
            # endpoint and run code in Spotify's logged-in session.
            args.append("--remote-debugging-address=127.0.0.1")
            args.append(
                f"--remote-allow-origins=http://127.0.0.1:{remote_debug_port},"
                f"http://localhost:{remote_debug_port}"
            )
        # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP so Spotify outlives us
        subprocess.Popen(
            args, close_fds=True,
            creationflags=0x00000008 | 0x00000200,
        )
        return True
    except Exception as e:
        log.warning("launch_spotify failed: %s", e)
        return False


# ---------------------------------------------------------------------------

def patch(show_badge: bool = True, debug_capture: bool = False) -> tuple[bool, str]:
    """
    Inject our ad-handler JS into Spotify's xpui.spa. Idempotent.

    ``show_badge`` — when False, the small status dot in Spotify's top bar
    is suppressed (the ad blocker itself still runs).

    Returns (ok, human-readable message).
    """
    if PAYLOAD_SYNC_ERROR:
        return False, PAYLOAD_SYNC_ERROR

    bad = config_problem()
    if bad:
        return False, (f"Refusing to patch: {bad}. Fix or delete that file — patching with an "
                       f"empty config would inject a payload with none of the Spotify-specific "
                       f"selectors, module ids or gate keys, and report success.")

    xpui = spotify_xpui_path()
    if not xpui.exists():
        return False, f"Spotify not found at {xpui}. Install desktop Spotify from spotify.com."

    adblock_src = _my_adblock_path()
    if not adblock_src.exists():
        return False, f"Missing {adblock_src} — reinstall Interceptify."

    with patch_lock.exclusive(timeout=60) as got_lock:
        if not got_lock:
            return False, "Another Interceptify process is patching Spotify right now."
        return _patch_locked(xpui, adblock_src, show_badge, debug_capture)


def _write_unpatched_copy(src: Path, dst: Path) -> None:
    """Copy `src` to `dst` with any Interceptify injection removed."""
    tmp = dst.with_name(dst.name + f".{os.getpid()}.tmp")
    try:
        with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                data = zin.read(info.filename)
                if info.filename == "index.html":
                    data = strip_injection(data.decode("utf-8", errors="replace")).encode("utf-8")
                zout.writestr(info, data)
        with zipfile.ZipFile(tmp, "r") as z:
            if z.testzip() is not None or "index.html" not in z.namelist():
                raise RuntimeError("reconstructed baseline is not a sound archive")
        tmp.replace(dst)
        _stamp_backup(dst)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _install_backup(src: Path, backup: Path) -> None:
    """Adopt `src` as the pristine baseline, atomically and only if it is sound.

    `shutil.copy2` straight onto the backup path is a torn write waiting to
    happen: the moment it is interrupted, the user's only route back to an
    unmodified Spotify is a truncated ZIP. Stage, check, then rename.
    """
    tmp = backup.with_name(backup.name + f".{os.getpid()}.tmp")
    try:
        shutil.copy2(src, tmp)
        with zipfile.ZipFile(tmp, "r") as z:
            if z.testzip() is not None or "index.html" not in z.namelist():
                raise RuntimeError("refusing to store an unsound archive as the baseline")
        tmp.replace(backup)
        _stamp_backup(backup)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _stamp_backup(backup: Path) -> None:
    """Record the backup's hash so a later swap or truncation is detectable."""
    try:
        import hashlib
        _backup_stamp_path(backup).write_text(
            hashlib.sha256(backup.read_bytes()).hexdigest(), encoding="utf-8")
    except Exception as e:
        log.warning("Could not stamp the backup: %s", e)


def _patch_locked(xpui: Path, adblock_src: Path,
                  show_badge: bool, debug_capture: bool) -> tuple[bool, str]:
    # Backup once, and never store a patched archive as the pristine baseline.
    backup = xpui.with_suffix(xpui.suffix + BACKUP_SUFFIX)
    if not backup.exists():
        try:
            if MARKER in _index_html(xpui):
                _write_unpatched_copy(xpui, backup)
                log.warning("xpui.spa was ALREADY patched (by this or an older build) and no "
                            "backup existed — reconstructed a clean baseline for %s", backup.name)
            else:
                _install_backup(xpui, backup)
                log.info("Backed up xpui.spa -> %s", backup.name)
        except Exception as e:
            return False, f"Backup failed: {e}"

    # Rebuild: always start from backup so we re-patch cleanly after Spotify updates
    tmp = xpui.with_name(f"xpui.spa.{os.getpid()}.tmp")
    try:
        # If Spotify updated xpui.spa, refresh the backup reference to the new version
        # ONLY if the current xpui has no marker (i.e. isn't our previous patch).
        if MARKER not in _index_html(xpui):
            # Spotify overwrote our patch — refresh backup to this new pristine version
            _install_backup(xpui, backup)
            log.info("Spotify updated xpui — refreshed backup to new pristine version")

        # A per-process temp name. The fixed "xpui.spa.tmp" was shared by every
        # patcher, so a concurrent run could rename this file out from under the
        # ZIP writer and leave a truncated archive. The lock above makes that
        # unreachable; the unique name means a stale temp from a killed run can
        # never be adopted as if it were ours.
        with zipfile.ZipFile(backup, "r") as src, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as dst:
            seen_index = False
            for info in src.infolist():
                data = src.read(info.filename)
                if info.filename == "index.html":
                    seen_index = True
                    html = data.decode("utf-8")
                    # Inline the JS directly so we bypass any CSP / file-allowlist
                    # restrictions Spotify's resource handler may apply to
                    # arbitrarily-named script files.
                    js_body = adblock_src.read_text(encoding="utf-8").strip("\r\n")
                    # Bake runtime preferences at patch time. The JS reads
                    # these globals before installing hooks.
                    prelude = (
                        f"window.__INTERCEPTIFY_SHOW_BADGE = {str(bool(show_badge)).lower()};\n"
                        f"window.__INTERCEPTIFY_DEBUG_CAPTURE = {str(bool(debug_capture)).lower()};\n"
                        f"window.__INTERCEPTIFY_CONFIG = {_load_adblock_config_json()};\n"
                    )
                    # The sentinels delimit exactly the bytes we hash, so the
                    # integrity check measures the running script and not a
                    # stand-in for it. The prelude sits outside them because it
                    # is per-install settings, not payload code.
                    inject = (
                        f"{MARKER}\n"
                        f"<script data-interceptify=\"inline\">\n"
                        f"{prelude}"
                        f"{BEGIN_SENTINEL}\n"
                        f"{js_body}\n"
                        f"{END_SENTINEL}\n"
                        f"</script>\n"
                    )
                    if "</body>" in html:
                        html = html.replace("</body>", inject + "</body>", 1)
                    else:
                        html += "\n" + inject
                    data = html.encode("utf-8")
                dst.writestr(info, data)
        if not seen_index:
            # Writing a patched archive with no index.html to patch would produce
            # a Spotify that starts fine and blocks nothing, which is the failure
            # mode hardest to notice.
            raise RuntimeError("index.html not present in xpui.spa; refusing to install a no-op patch")

        # VERIFY BEFORE REPLACING. The check used to run only after the temp file
        # had already become Spotify's live archive, so a rewrite that produced a
        # corrupt or wrongly-patched bundle was installed first and reported as a
        # failure second - patch() returned False while the user was left with the
        # broken client. Nothing reaches xpui.spa until it has been proven sound.
        why = verify_patched_archive(tmp)
        if why is not None:
            return False, f"Refused to install the patch: {why}. Spotify is untouched."

        tmp.replace(xpui)
        tmp = None

        # Post-replace verification. The pre-check proved the bytes we built; this
        # proves the bytes that landed. If the two disagree the rename itself went
        # wrong, and the only safe end state is the pristine backup - not a
        # half-patched archive left behind by a function that returned False.
        why = verify_patched_archive(xpui)
        if why is not None:
            try:
                _restore_from_backup(xpui, backup)
                return False, (f"Patch verification failed after writing ({why}); "
                               f"restored Spotify's original xpui.spa.")
            except Exception as e:
                return False, (f"Patch verification failed after writing ({why}) AND the "
                               f"rollback failed ({e}). Restore manually from {backup.name}.")

        # DevTools prefs flag is debug-only; a normal patch leaves Spotify's
        # defaults untouched (and clears the flag only if WE set it earlier).
        if debug_capture:
            enable_devtools()
        else:
            disable_devtools()
        return True, "Spotify patched. Restart Spotify to activate."
    except PermissionError as e:
        return False, f"Permission denied — quit Spotify first. ({e})"
    except Exception as e:
        log.exception("Patch failed")
        return False, f"Patch failed: {e}"
    finally:
        if tmp is not None and tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _restore_from_backup(xpui: Path, backup: Path) -> None:
    """Put the pristine archive back, atomically, and only if it is sound.

    Copying the backup directly over xpui.spa can tear, and a torn restore is
    worse than the patch it was undoing: Spotify will not start and the backup
    is what it was supposed to be rescued by.
    """
    tmp = xpui.with_name(f"xpui.spa.restore.{os.getpid()}.tmp")
    try:
        shutil.copy2(backup, tmp)
        with zipfile.ZipFile(tmp, "r") as z:
            if z.testzip() is not None or "index.html" not in z.namelist():
                raise RuntimeError("the backup is not a sound archive")
        tmp.replace(xpui)
        tmp = None
    finally:
        if tmp is not None and tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def unpatch() -> tuple[bool, str]:
    """Restore xpui.spa from backup, but only when the live file is our patch.

    Restoring unconditionally can roll Spotify *backward*. If Spotify updated
    itself and wiped the patch, the live xpui.spa is new and the backup is from
    the previous version; copying the backup over it downgrades the UI to code
    that no longer matches the rest of the install. The backup is only a valid
    restore target for the archive it was taken from, so an unpatched live file
    means there is nothing of ours to undo.
    """
    xpui = spotify_xpui_path()
    backup = xpui.with_suffix(xpui.suffix + BACKUP_SUFFIX)
    if not backup.exists():
        return False, "No backup found — nothing to restore."

    with patch_lock.exclusive(timeout=60) as got_lock:
        if not got_lock:
            return False, "Another Interceptify process is patching Spotify right now."
        if not xpui.exists():
            return False, "Spotify is not installed."
        why = backup_problem(xpui, backup)
        if why:
            return False, (f"Refusing to restore: {why}. Restoring an archive we cannot vouch "
                           f"for can leave Spotify unable to start, and the backup is the thing "
                           f"that was supposed to rescue it.")
        if not is_patched():
            # Not an error: this is the normal state after a Spotify update.
            disable_devtools()
            return True, ("Spotify was already unpatched (it likely updated itself). "
                          "Left the current version in place.")
        try:
            _restore_from_backup(xpui, backup)
            disable_devtools()
            if is_patched():
                return False, "Restore ran but the patch marker is still present."
            return True, "Spotify restored to original. Restart Spotify."
        except PermissionError as e:
            return False, f"Permission denied — quit Spotify first. ({e})"
        except Exception as e:
            return False, f"Restore failed: {e}"
