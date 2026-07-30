"""
Interceptify SELF-HEAL — automated detect -> repair -> VERIFY loop.

WHY THIS EXISTS
---------------
Spotify's desktop client silently auto-updates and there is **no upstream push /
feed** to subscribe to. Every update rewrites `%APPDATA%\\Spotify\\Apps\\xpui.spa`,
which is exactly the file we patch, so the ad-block is wiped. Worse, a *stale*
patch can be re-applied by some other build (this really happened 2026-07-16: the
old v1 app re-patched with its April payload and ads came back) — a plain
"did the version change?" check would NOT have caught that.

So we do not watch for updates. We watch for **drift**: any state where what is
actually live on this machine is not the payload we ship, or where the block does
not verify. Detection is a local fingerprint (cheap, runs often):

  1. Spotify version      -> `%APPDATA%\\Spotify\\prefs` : app.last-launched-version
  2. xpui.spa SHA-256     -> the bundle we patch (changes on every Spotify update)
  3. patch present?       -> is our payload inlined in index.html
  4. live payload SHA     -> the INLINED (executing) payload vs the one we ship
  5. last verified marker -> did the block PASS verification for this exact combo

Any mismatch => run the repair+verify cycle. It only stops when verification
PASSES, so "fixed" is measured, never assumed.

VERIFICATION (the part that makes "fixed" a fact)
-------------------------------------------------
`window.__interceptify.selftest()` forces ad breaks to become DUE — the real
scheduler trigger, empirically validated: with the block OFF this delivers ads
within seconds (4 ads + "Spotify - Reklam" on 1.2.94), with it ON it delivers
none. The verdict is THREE-valued, because "no ads appeared" is not one fact:

    FAIL     the gate proof broke, or something ad-shaped was observed
             (adsDelivered / adUiFrames / a reactive skip or mute). A positive
             observation is meaningful whatever else was going on.
    UNKNOWN  the gate proof held, but no audio streamed during the window. With
             nothing playing, zero ads is entailed by the silence rather than by
             the block, so it is not a pass. Reported as exit code 4.
    PASS     the gate proof held AND playback actually ran AND nothing
             ad-shaped happened.

The reactive-action term now comes from always-on counters in the payload. It
used to be computed from the debug sniffer buffer, which is only populated when
DEBUG_CAPTURE is on — and this script always patches with it OFF, so the term
was structurally zero and contributed nothing to the verdict.

A PASS also requires every block layer to be ATTACHED at the end of the window
(REQUIRED_LAYERS). A run once reported PASS while its own health said fetch,
l1Chunk and adGate were all missing: the gate-toggle proof was passing through a
connector reached by one route, and nothing required the rest of the advertised
multi-layer block to exist. Health is read AFTER the window now, not the instant
CDP attaches — the old reading happened before the lazily-loaded ads chunk had
even arrived, so it described a moment unrelated to the verdict.

SELF-REPAIR
-----------
If verification fails, we re-discover what moved instead of giving up:
  * ad-gate key renamed -> dump the live ad-state keys, try every plausible
    boolean "ad" flag, keep whichever one makes verification PASS, and persist a
    matching pattern into extensions/adblock.config.local.json (the LOCAL file:
    what was discovered here is machine knowledge, and the shipped defaults are
    replaced by every update).
  * connector moved     -> rescan window.__webpack_modules__ by method signature.
Each candidate is proven by re-running the same verification, so a repair is only
accepted when it demonstrably blocks ads.

READ-ONLY vs DISRUPTIVE
-----------------------
`--verify` is a genuine status check: files on disk, plus the live payload's own
health if a debug session already happens to be open. It never patches, never
restarts Spotify and never opens a CDP port. It used to call the full selftest,
which is the opposite of read-only — that path toggles Spotify's ad gate, writes
scheduler state, drives the break timer and starts playback if nothing is
streaming. All of that now lives behind `--selftest`, which says what it does.

USAGE
    python selfheal.py --once      # cheap check; full repair+verify only on drift
    python selfheal.py --force     # always run the full repair+verify cycle
    python selfheal.py --verify    # READ-ONLY status; changes nothing
    python selfheal.py --selftest  # DISRUPTIVE causal proof; needs a debug session
    python selfheal.py --selftest --restart   # ...or relaunch Spotify to get one
    python selfheal.py --install-task         # register the scheduled tasks

Packaged builds reach the same entry point as `Interceptify.exe --selfheal ...`,
so the .exe owns its own scheduling instead of pointing tasks at a source tree.

EXIT CODES
    0  verified blocking
    2  NOT verified — something is broken, see the report
    3  verified now, but ad(s) reached the user since the last run
    4  unproven — the gate proof held but nothing was playing to test it
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import logging.handlers
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# The INSTALL directory, which in a frozen build is not where this module lives.
# PyInstaller unpacks a onefile bundle into a temp directory and deletes it on
# exit, so deriving ROOT from __file__ would put the state file, the report and
# the log somewhere that ceases to exist - and a self-heal that cannot remember
# it verified would re-verify, and therefore restart Spotify, on every single
# scheduled run.
if getattr(sys, "frozen", False):
    ROOT = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import spotify_patcher  # noqa: E402

APPDATA = Path(os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming")))
SPOTIFY_DIR = APPDATA / "Spotify"
XPUI = SPOTIFY_DIR / "Apps" / "xpui.spa"
PREFS = SPOTIFY_DIR / "prefs"
OUR_PAYLOAD = ROOT / "extensions" / "adblock.js"
# Repairs are MACHINE knowledge - the gate key Spotify uses on this build, on
# this install. They go in the local override file, never in the shipped
# defaults: the shipped file is replaced by every update, so a discovery written
# there is erased by the next release, and a release's own corrections would in
# turn be overwritten by whatever this machine last guessed.
OUR_CONFIG = ROOT / "extensions" / "adblock.config.local.json"
STATE_FILE = ROOT / "selfheal.state.json"
REPORT_FILE = ROOT / "selfheal.report.json"
LOG_FILE = ROOT / "selfheal.log"
CDP_PORT = 9333  # deliberately not 9222, so a manual debug session never collides

# Layers that must be attached for any verdict better than FAIL. A run reported
# PASS while its own health said fetch, l1Chunk and adGate were all missing: the
# gate-toggle proof was passing on a connector reached by one route, and nothing
# required the rest of the advertised multi-layer block to exist at all.
#
# instreamApi is deliberately NOT here. It only materialises once Spotify hands
# over an in-stream ad object, so requiring it would mean a session with no ads
# could never pass - which is the session the block is supposed to produce.
# Real listening that must be observed on the CHANGED block before a delivery can
# be retired. Wall-clock alone lets a machine that was asleep for a day satisfy
# the window, and a sleeping machine has produced no ad opportunities at all.
# Deliberately modest: this is a floor under "we actually used it", not an
# attempt to prove absence, which is not provable for server-scheduled ads.
DELIVERY_MIN_OBSERVED_S = 30 * 60

REQUIRED_LAYERS = ("fetch", "xhr", "l1Chunk", "l1Provider", "adsConnector", "adGate")

# How long an unresolved ad delivery stays unresolved once something about the
# block has actually changed. A structural self-test passing is NOT evidence
# that a real delivery failure is fixed - it cannot schedule an ad, so it can
# only ever prove the plumbing. What counts is time spent with the new code and
# no further deliveries. 24h of real use, at minimum.
DELIVERY_CLEAR_AFTER_S = 24 * 3600

# Rotated, not unbounded. Four scheduled runs a day writing to one file forever
# is a log that eventually costs more than it tells you, and nothing was ever
# going to prune it.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    handlers=[
        logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("selfheal")


# --------------------------------------------------------------------------
# Diagnostic files — bounded, and never deleted behind the user's back
# --------------------------------------------------------------------------

DIAGNOSTIC_GLOBS = (
    # NOT necessarily redacted. These globs predate the redactor, and describing
    # them as redacted in a comment is how three captures holding a full Spotify
    # access_token sat here for six weeks looking handled. `--redact-captures`
    # is what makes the claim true; `credentials_in()` is what checks it.
    "capture_*.json",                       # CDP snapshots (detailed)
    "netlog_*.jsonl",                       # request logs
    "selfheal.log.*",                        # rotated logs
    "extensions/adblock.config.superseded-*.json",
    "extensions/adblock.config.corrupt-*.json",
)


def diagnostic_files() -> list[Path]:
    out: list[Path] = []
    for pattern in DIAGNOSTIC_GLOBS:
        out.extend(sorted(ROOT.glob(pattern)))
    return out


# How long a diagnostic artifact is kept. Retention was unbounded: every capture
# ever taken stayed until someone remembered to run --scrub. Files nobody has
# looked at for a month are not evidence, they are an ever-growing pile of
# detailed records of what the user listened to.
DIAGNOSTIC_MAX_AGE_S = 30 * 24 * 3600


def redact_captures() -> int:
    """Run every diagnostic file through the redactor and REPORT what is left.

    Deliberately reports the after-count rather than assuming success: the
    redactor is a set of patterns, and a pattern that misses is exactly the
    failure this is meant to catch.
    """
    import redact
    files = diagnostic_files()
    if not files:
        print("no diagnostic files")
        return 0
    dirty = clean = 0
    for f in files:
        try:
            before, after = redact.redact_file(f)
        except Exception as e:
            print(f"  {f.name}: could not redact ({e})")
            dirty += 1
            continue
        if before:
            print(f"  {f.name}: {before} credential(s) redacted, {after} remaining")
            clean += 1
            if after:
                dirty += 1
    print(f"\n{clean} file(s) cleaned; {dirty} still reporting credentials")
    return 1 if dirty else 0


def prune_diagnostics() -> int:
    """Drop diagnostic artifacts past the AGE bound, and log every removal.

    Age only, on purpose. scrub() deliberately refuses to delete captures in the
    background, and the reason is good: a capture is evidence, and sweeping it
    away automatically destroys the record of an incident at the moment it
    becomes interesting. A month-old file is not that. Pruning by COUNT would
    be - eleven captures taken while chasing one bug would start eating the
    earliest ones, which are usually the informative ones.

    So: unbounded retention is fixed without quietly reversing that decision.
    Deleting anything newer stays a --scrub, where a human is present.
    """
    removed = []
    now = time.time()
    for f in diagnostic_files():
        try:
            if now - f.stat().st_mtime > DIAGNOSTIC_MAX_AGE_S:
                f.unlink()
                removed.append(f.name)
        except OSError:
            pass
    if removed:
        log.info("pruned %d diagnostic file(s) older than %d days: %s",
                 len(removed), DIAGNOSTIC_MAX_AGE_S // 86400, ", ".join(removed[:6]))
    return len(removed)


def scrub(confirm: bool) -> int:
    """List diagnostic files, and delete them only when explicitly told to.

    These are redacted, but redaction is a reduction of risk and not a proof of
    safety - a capture still describes what someone was listening to and when.
    They are also evidence: deleting them automatically would throw away the
    record of an incident right when it becomes interesting. So this is a
    user-visible action, never a background sweep.
    """
    files = diagnostic_files()
    if not files:
        print("no diagnostic files")
        return 0
    total = sum(f.stat().st_size for f in files)
    for f in files:
        print(f"  {f.relative_to(ROOT)}  ({f.stat().st_size / 1024:.0f} KB)")
    print(f"\n{len(files)} file(s), {total / 1024 / 1024:.1f} MB")
    if not confirm:
        print("re-run with --scrub --yes to delete them")
        return 0
    removed = 0
    for f in files:
        try:
            f.unlink()
            removed += 1
        except OSError as e:
            print(f"  could not remove {f.name}: {e}")
    print(f"deleted {removed} file(s)")
    return 0


# --------------------------------------------------------------------------
# Detection — local fingerprint (there is no Spotify update feed to subscribe to)
# --------------------------------------------------------------------------

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def spotify_version() -> str:
    try:
        txt = PREFS.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'app\.last-launched-version="([^"]+)"', txt)
        return m.group(1) if m else "?"
    except Exception:
        return "?"


def fingerprint() -> dict:
    """Everything that must hold for the block to be live and correct."""
    fp = {
        "spotify_version": spotify_version(),
        "xpui_sha": None,
        "xpui_mtime": None,
        "patched": False,
        "live_payload_sha": None,
        "our_payload_sha": None,
        "payload_matches": False,
        # The config is injected at patch time, so editing a config FILE changes
        # nothing until a re-patch. Tracking only the payload meant a release
        # that corrects a slot id, selector, module id or gate pattern could
        # report healthy forever while Spotify kept running the old values.
        "live_config_sha": None,
        "our_config_sha": None,
        "config_matches": False,
    }
    # Both sides are hashed by spotify_patcher, with the same normalisation, so
    # "live" and "ours" are genuinely comparable quantities. They used to be
    # computed here against a spare copy of the payload stored loose in the
    # archive - a file Spotify never loads. That measured whether a bystander
    # matched, not whether the running code did.
    fp["our_payload_sha"] = spotify_patcher.our_payload_sha()
    try:
        fp["our_config_sha"] = spotify_patcher.effective_config_sha()
    except Exception as e:
        log.warning("fingerprint: config unreadable: %s", e)
    try:
        raw = XPUI.read_bytes()
        fp["xpui_sha"] = _sha(raw)
        fp["xpui_mtime"] = int(XPUI.stat().st_mtime)
        fp["live_payload_sha"] = spotify_patcher.inline_payload_sha()
        fp["live_config_sha"] = spotify_patcher.inline_config_sha()
        fp["patched"] = fp["live_payload_sha"] is not None
    except Exception as e:
        log.warning("fingerprint: %s", e)
    fp["payload_matches"] = bool(
        fp["live_payload_sha"] and fp["live_payload_sha"] == fp["our_payload_sha"]
    )
    fp["config_matches"] = bool(
        fp["live_config_sha"] and fp["live_config_sha"] == fp["our_config_sha"]
    )
    return fp


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(d: dict) -> None:
    try:
        STATE_FILE.write_text(json.dumps(d, indent=2), encoding="utf-8")
    except Exception as e:
        log.warning("save_state: %s", e)


def drift_reason(fp: dict, state: dict) -> str | None:
    """None = healthy and already verified for this exact Spotify+payload combo."""
    if not fp["patched"]:
        return "spotify is not patched (update wiped it, or never patched)"
    if not fp["payload_matches"]:
        return "live payload != the payload we ship (something re-patched with other code)"
    # Config drift is repaired by exactly the same action as payload drift - a
    # re-patch - and until this existed there was no way to ask for one. Editing
    # a config file is the documented way to fix a Spotify rebuild without
    # cutting a release, and it silently did nothing to the running client.
    if not fp["config_matches"]:
        return ("live config != the config we would inject (a config change has not "
                "reached Spotify; re-patch required)")
    # "Never verified" and "verified, then it changed" are different facts and
    # were reported as the same one. A run that ends UNRESOLVED deliberately
    # records nothing as verified, so the next run read `None != "1.2.94..."`
    # and announced a Spotify version change that had not happened - a false
    # cause, in the one output someone reads to find the real one.
    if state.get("verified_spotify_version") is None:
        return f"no verified state for spotify {fp['spotify_version']} yet"
    if state.get("verified_spotify_version") != fp["spotify_version"]:
        return (f"spotify version changed {state['verified_spotify_version']} -> "
                f"{fp['spotify_version']} (block not yet verified on it)")
    if state.get("verified_xpui_sha") != fp["xpui_sha"]:
        return "xpui.spa changed since last verification"
    if state.get("verified_payload_sha") != fp["live_payload_sha"]:
        return "payload changed since last verification"
    if state.get("verified_config_sha") != fp["live_config_sha"]:
        return "injected config changed since last verification"
    if not state.get("verified_pass"):
        return "last verification did not pass"
    return None


# --------------------------------------------------------------------------
# CDP plumbing
# --------------------------------------------------------------------------

class CDP:
    def __init__(self, port: int = CDP_PORT, timeout: int = 60):
        import websocket  # websocket-client
        self._ws = None
        self._id = 0
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=5))
                pages = [t for t in targets if t.get("type") == "page"]
                page = next((t for t in pages if "xpui" in (t.get("url") or "").lower()), None) or (pages[0] if pages else None)
                if page and page.get("webSocketDebuggerUrl"):
                    self._ws = websocket.create_connection(
                        page["webSocketDebuggerUrl"], origin=f"http://127.0.0.1:{port}", timeout=timeout
                    )
                    return
            except Exception as e:
                last = e
            time.sleep(1)
        raise RuntimeError(f"no CDP page target on {port}: {last}")

    def ev(self, expr, timeout=90):
        self._id += 1
        i = self._id
        self._ws.send(json.dumps({
            "id": i, "method": "Runtime.evaluate",
            "params": {"expression": expr, "returnByValue": True, "awaitPromise": True},
        }))
        end = time.time() + timeout
        while time.time() < end:
            m = json.loads(self._ws.recv())
            if m.get("id") == i:
                r = m.get("result", {})
                if "exceptionDetails" in r:
                    return {"__exc": str(r["exceptionDetails"].get("text"))}
                return r.get("result", {}).get("value")
        raise TimeoutError("CDP evaluate timed out")

    def close(self):
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass


def restart_spotify(debug_port: int = 0) -> None:
    # kill_spotify() now waits for the process to actually exit, so the retry
    # loop that used to sleep(1) and hope is no longer needed.
    spotify_patcher.kill_spotify()
    spotify_patcher.launch_spotify(debug_port)


def cdp_is_live(port: int = CDP_PORT) -> bool:
    """Is something already exposing CDP on this port?"""
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2).read()
        return True
    except Exception:
        return False


def wait_for_payload(cdp: CDP, timeout: int = 60) -> str | None:
    end = time.time() + timeout
    while time.time() < end:
        v = cdp.ev("(window.__interceptify&&window.__interceptify.version)||''")
        if isinstance(v, str) and v:
            return v
        time.sleep(1)
    return None


def wait_for_connector(cdp: CDP, timeout: int = 60) -> bool:
    """The ads modules live in a LAZY chunk; nudge the UI until it loads."""
    end = time.time() + timeout
    nudges = ['[data-testid="whats-new-feed-button"]', '[data-testid="user-widget-link"]', '[aria-label="Home"]']
    i = 0
    while time.time() < end:
        if cdp.ev("!!window.__interceptify_ads_connector") is True:
            return True
        cdp.ev("(()=>{const e=document.querySelector('%s');if(e)e.click();return !!e;})()" % nudges[i % len(nudges)])
        i += 1
        time.sleep(2)
    return False


# --------------------------------------------------------------------------
# Verification — the measurement that defines "fixed"
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Incident reporter — opt-in, and portable
#
# This used to hard-code one machine's personal notes directory, which is why
# the whole file had to be kept out of version control: it could not be shared
# without sharing a path from someone's home folder. That made a script running
# on a schedule the only thing here with no history and no rollback.
#
# The destination is now configuration. Unset means the reporter does nothing,
# so the default behaviour writes nothing outside the project directory.
#   INTERCEPTIFY_INCIDENT_LOG=<path>   environment, or
#   {"incident_log": "<path>"}         in config.json
# --------------------------------------------------------------------------

def _incident_log_path() -> Path | None:
    env = os.environ.get("INTERCEPTIFY_INCIDENT_LOG", "").strip()
    if env:
        return Path(env)
    try:
        cfg = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
        val = str(cfg.get("incident_log", "")).strip()
        return Path(val) if val else None
    except Exception:
        return None


VAULT_NOTE = _incident_log_path()

# Spotify is Chromium: localStorage lives in a LevelDB on disk. Reading it there
# means an incident can be collected with Spotify closed and no debug port, which
# is the whole point - the previous harvester needed a live CDP session and so
# could only run during a verification it had already decided to skip.
def _vault_append(lines: list[str]) -> None:
    """Short, append-only log so a new session (or /vault) can see what happened."""
    if not lines or VAULT_NOTE is None:
        return
    try:
        VAULT_NOTE.parent.mkdir(parents=True, exist_ok=True)
        if not VAULT_NOTE.exists():
            VAULT_NOTE.write_text(
                "---\ntags: [project, interceptify, spotify, monitoring]\nproject: Interceptify\n---\n\n"
                "# Interceptify — ad incidents & self-heal log\n\n"
                "Appended automatically by `selfheal.py` (local only). An **AD DELIVERED** line means an\n"
                "ad actually reached the client — that is a block failure worth investigating.\n\n",
                encoding="utf-8",
            )
        with VAULT_NOTE.open("a", encoding="utf-8") as f:
            for ln in lines:
                f.write(ln.rstrip() + "\n")
    except Exception as e:
        log.warning("vault append failed: %s", e)


LOCALSTORAGE_DIRS = [
    Path(os.environ.get("LOCALAPPDATA", "")) / "Spotify" / "Browser" / "Local Storage" / "leveldb",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Spotify" / "Default" / "Local Storage" / "leveldb",
]
INCIDENT_KEY = b"__interceptify_ad_incidents"


def _json_arrays_after(blob: bytes, key: bytes) -> list:
    """Every JSON array following an occurrence of `key`, brace-matched.

    LevelDB keeps superseded values, so a key appears several times; each array
    is decoded and the caller merges by timestamp.

    Brace matching rather than a per-record regex. The previous regex assumed a
    flat record and silently matched nothing the moment a nested `gate` object
    was added - the reader broke without failing, which is the worst way for a
    monitor to break. Letting json decide the shape removes that whole class.
    """
    out = []
    pos = 0
    while True:
        i = blob.find(key, pos)
        if i < 0:
            return out
        pos = i + len(key)
        j = blob.find(b"[", pos)
        if j < 0 or j - pos > 64:            # the array follows the key closely
            continue
        depth, k, in_str, esc = 0, j, False, False
        while k < len(blob) and k - j < 2_000_000:
            c = blob[k]
            if in_str:
                if esc:
                    esc = False
                elif c == 0x5C:
                    esc = True
                elif c == 0x22:
                    in_str = False
            elif c == 0x22:
                in_str = True
            elif c == 0x5B:
                depth += 1
            elif c == 0x5D:
                depth -= 1
                if depth == 0:
                    # UTF-8 only, deliberately. The key is matched as UTF-8
                    # bytes, so a UTF-16 value would never be reached here - a
                    # decode fallback for it looked thorough while being
                    # unreachable, which is the kind of code that hides a gap.
                    try:
                        v = json.loads(blob[j:k + 1].decode("utf-8"))
                        if isinstance(v, list):
                            out.append(v)
                    except Exception:
                        pass
                    break
            k += 1


def read_incidents_from_disk() -> list[dict]:
    """Every ad incident the payload has recorded, oldest first.

    Read from Spotify's LevelDB on disk, so an incident is collectable with
    Spotify closed and no debug port. The original harvester needed a live CDP
    session and could therefore only run during a verification it had already
    decided to skip.
    """
    seen: dict[int, dict] = {}
    for d in LOCALSTORAGE_DIRS:
        if not d.is_dir():
            continue
        blob = b""
        for f in sorted(d.iterdir()):
            if f.suffix.lower() in (".log", ".ldb"):
                try:
                    blob += f.read_bytes()
                except OSError:
                    pass
        if INCIDENT_KEY not in blob:
            continue
        for arr in _json_arrays_after(blob, INCIDENT_KEY):
            for rec in arr:
                if isinstance(rec, dict) and isinstance(rec.get("t"), int):
                    seen[rec["t"]] = rec      # timestamp keyed = natural dedupe
    return [seen[k] for k in sorted(seen)]


def is_expected_incident(it: dict) -> bool:
    """True when selftest opened the gate on purpose to prove its ad trigger works.

    Such an ad is the verification succeeding, not the block failing. Reporting
    it as a failure would put a false alarm in the vault on every verified run,
    which is how a log becomes something you stop reading.
    """
    return bool((it.get("gate") or {}).get("suspended"))


def _incident_line(it: dict, spotify_ver: str) -> str:
    """One vault line. The gate snapshot is taken AT DELIVERY by the payload, so
    the line says whether the block was up when the ad arrived - an incident that
    only says "an ad happened" cannot be acted on later."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime((it.get("t") or 0) / 1000))
    gate = it.get("gate") or {}
    kind = it.get("kind") or "delivered"
    ident = (f"{ts} — id=`{it.get('id')}` format={it.get('format')} "
             f"spotify={spotify_ver} payload={it.get('v')}")
    # muted/skipped mean the ad REACHED PLAYBACK - the user heard it. That is a
    # worse outcome than a delivery the gate absorbed, so it is labelled louder.
    heard = kind in ("muted", "skipped")

    if is_expected_incident(it):
        return (f"- ✅ expected ad during self-test {ident} — the verifier opened "
                f"the gate deliberately to prove its trigger fires")
    if heard:
        return (f"- 🔊 **AD REACHED PLAYBACK ({kind})** {ident} — gate closed="
                f"{gate.get('closed')} keys=`{gate.get('keys')}` "
                f"connector={gate.get('connector')} uptime={gate.get('uptimeMs')}ms — "
                f"the user HEARD this; prevention failed and only the reactive belt caught it")
    if not gate:
        return (f"- **AD DELIVERED** {ident} — no gate state recorded "
                f"(payload predates incident enrichment)")
    if gate.get("closed"):
        return (f"- 🚨 **AD DELIVERED THROUGH A CLOSED GATE** {ident} — keys="
                f"`{gate.get('keys')}` connector={gate.get('connector')} "
                f"uptime={gate.get('uptimeMs')}ms — the gate is no longer sufficient "
                f"on this Spotify build; investigate before trusting it")
    return (f"- **AD DELIVERED, gate was OPEN** {ident} — keys=`{gate.get('keys')}` "
            f"connector={gate.get('connector')} uptime={gate.get('uptimeMs')}ms — "
            f"the block was not established; check connector resolution timing")


def harvest(spotify_ver: str, state: dict) -> int:
    """Report every incident newer than the watermark. Safe to call every run."""
    try:
        items = read_incidents_from_disk()
    except Exception as e:
        log.warning("incident harvest: %s", e)
        return 0
    mark = int(state.get("incident_watermark") or 0)
    fresh = [i for i in items if int(i.get("t") or 0) > mark]
    if not fresh:
        return 0
    _vault_append([_incident_line(i, spotify_ver) for i in fresh])
    # Advance past everything seen, expected or not, so nothing is reported twice.
    state["incident_watermark"] = max(int(i["t"]) for i in fresh)
    real = [i for i in fresh if not is_expected_incident(i)]
    if real:
        log.warning("harvested %d ad incident(s), %d of them real block failures -> %s",
                    len(fresh), len(real), VAULT_NOTE)
    else:
        log.info("harvested %d expected self-test ad(s); no block failures", len(fresh))
    return len(real)


# --------------------------------------------------------------------------
# Unresolved deliveries — the one fact a structural pass may not overwrite
# --------------------------------------------------------------------------

def note_delivery_failure(state: dict, n: int, fp: dict) -> None:
    """Record that ads reached the user, durably.

    This existed only as a transient `verified_pass = False` that the very next
    structural self-test overwrote with True. So the program could log "an ad was
    delivered through a closed gate", pass a test that cannot schedule an ad, and
    show the user a green status - with the incident watermark already advanced,
    so no later run would ever look at it again.

    The block's whole promise is the thing the tripwire says failed. That has to
    outlive a test of the machinery around it.
    """
    cur = state.get("unresolved_delivery") or {}
    now = int(time.time())
    state["unresolved_delivery"] = {
        "count": int(cur.get("count", 0)) + n,
        "first_t": cur.get("first_t", now),
        "last_t": now,
        # What the block looked like when it failed. Clearing requires this to
        # have changed: "it works now" is not credible while the code, the
        # config and the outcome are all identical to when it did not.
        "payload_sha": fp.get("live_payload_sha"),
        # The config Spotify was RUNNING, not the one sitting in a file. Recording
        # the sidecar meant an edit that never reached the page counted as "the
        # block changed", which is the precondition for retiring a real delivery.
        "config_sha": fp.get("live_config_sha"),
    }


BACKFILL_WINDOW_S = 14 * 24 * 3600

# The lines harvest() writes for a real failure. Parsing our own output back is
# usually a smell, but here the incident log is the only DURABLE record: the
# payload's own store is browser localStorage, which a Spotify restart or a
# profile reset wipes - and verification restarts Spotify, so the act of
# checking destroys the evidence. The log survives both.
_FAILURE_LINE = re.compile(
    r"^- (?:🚨 \*\*AD DELIVERED THROUGH A CLOSED GATE\*\*"
    r"|🔊 \*\*AD REACHED PLAYBACK[^*]*\*\*"
    r"|\*\*AD DELIVERED)"
)
_LINE_TS = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})")


def _failures_from_incident_log(cutoff_s: float) -> list[int]:
    """Epoch seconds of each real delivery recorded in the incident log."""
    path = _incident_log_path()
    if not path or not path.exists():
        return []
    out = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not _FAILURE_LINE.match(line.strip()):
                continue
            m = _LINE_TS.search(line)
            if not m:
                continue
            try:
                t = time.mktime(time.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                continue
            if t >= cutoff_s:
                out.append(int(t))
    except Exception as e:
        log.warning("could not read the incident log for backfill: %s", e)
    return out


def backfill_delivery_failures(state: dict, fp: dict) -> int:
    """One-time: account for deliveries that were logged before this rule existed.

    Without it the fix only applies to the future, and the failures that
    prompted it stay invisible - the watermark has already moved past them, so no
    run will look at them again, and the first thing the user sees after
    installing the fix is a green status sitting on top of the exact incidents
    that proved the status could not be trusted.

    Bounded to a fortnight: older records are history, not an open fault.
    """
    if state.get("delivery_backfill_done"):
        return 0
    state["delivery_backfill_done"] = int(time.time())
    cutoff = time.time() - BACKFILL_WINDOW_S
    stamps = _failures_from_incident_log(cutoff)
    # The live store too, when it still holds anything. Same failures may appear
    # in both; take whichever count is larger rather than adding them together.
    try:
        cutoff_ms = cutoff * 1000
        live = [i for i in read_incidents_from_disk()
                if not is_expected_incident(i)
                and (i.get("t") or 0) >= cutoff_ms
                and (i.get("kind") or "delivered") in ("delivered", "muted", "skipped")]
    except Exception as e:
        log.warning("could not read the live incident store for backfill: %s", e)
        live = []
    if live and len(live) > len(stamps):
        stamps = [int((i.get("t") or 0) / 1000) for i in live]
    if not stamps:
        return 0
    note_delivery_failure(state, len(stamps), fp)
    # Dated from the incident, not from now, so the clock reflects when the
    # failure actually happened.
    state["unresolved_delivery"]["last_t"] = max(stamps)
    state["unresolved_delivery"]["first_t"] = min(stamps)
    # Provenance UNKNOWN, and marked as such. These failures happened under some
    # earlier payload we cannot identify from a log line, so recording today's
    # sha would assert something we do not know - and it would also mean "the
    # block changed" could never become true for them, leaving a flag stuck up
    # forever. A flag that never clears is one the user learns to ignore, which
    # costs more than it protects. Time alone clears a backfilled entry; a
    # failure observed live still needs a real change as well.
    state["unresolved_delivery"]["payload_sha"] = None
    state["unresolved_delivery"]["config_sha"] = None
    state["unresolved_delivery"]["backfilled"] = True
    log.warning("backfilled %d ad delivery incident(s) already on record; status stays "
                "UNRESOLVED until the block changes and %dh pass without another",
                len(stamps), DELIVERY_CLEAR_AFTER_S // 3600)
    return len(stamps)


def delivery_block(state: dict) -> dict | None:
    """The unresolved delivery, or None."""
    d = state.get("unresolved_delivery")
    return d if isinstance(d, dict) and d.get("count") else None


def note_block_change(state: dict, fp: dict) -> None:
    """Stamp WHEN the running block first differed from the one that failed.

    The clearance clock used to run from the delivery timestamp, so the 24 hours
    could elapse while the broken code was still installed - and a fix patched in
    on day ten cleared the incident instantly, with zero seconds of listening on
    the new code. "24h with no further delivery" has to mean 24h ON THE THING
    THAT IS SUPPOSED TO HAVE FIXED IT, or it measures nothing but patience.
    """
    d = delivery_block(state)
    if not d:
        return
    if not (fp.get("live_payload_sha") and fp.get("live_config_sha")):
        return                                   # unknown is not changed
    if (fp["live_payload_sha"] == d.get("payload_sha")
            and fp["live_config_sha"] == d.get("config_sha")):
        return                                   # still the code that failed
    # RE-STAMP whenever the deployed pair moves, rather than refusing because a
    # stamp already exists. Refusing bricked the record: run() calls this before
    # the repair (stamping the PRE-repair payload as the target) and again after,
    # where the second call was ignored. Clearance then requires the live hashes
    # to equal the stored target, which they never again did - so the incident
    # could not clear even if the new code was perfect. The live state hit
    # exactly this: target e538..., running 1280..., unclearable forever.
    if (fp["live_payload_sha"] == d.get("changed_to_payload")
            and fp["live_config_sha"] == d.get("changed_to_config")):
        return                                   # same target, clock keeps running
    d["changed_at"] = int(time.time())
    d["changed_to_payload"] = fp["live_payload_sha"]
    d["changed_to_config"] = fp["live_config_sha"]
    d["observed_s"] = 0                          # a new block has been observed for 0s
    log.info("the running block now differs from the one that failed; the %dh "
             "clearance window starts now, not at the delivery",
             DELIVERY_CLEAR_AFTER_S // 3600)


def note_observed_playback(state: dict, report: dict) -> None:
    """Accumulate REAL listening seen on the changed block.

    Wall-clock is not evidence: a machine that was asleep for 24 hours has
    produced exactly as many ad opportunities as one that was off. Only playback
    the user was doing counts - a window where the test had to start the music
    itself proves the plumbing, not the outcome.
    """
    d = delivery_block(state)
    if not d or not d.get("changed_at"):
        return
    final = report.get("final") or (report.get("rounds") or [{}])[-1].get("result") or {}
    if final.get("startedByTest"):
        return
    delta = final.get("streamedDelta")
    if isinstance(delta, (int, float)) and delta > 0:
        d["observed_s"] = int(d.get("observed_s", 0)) + int(delta)


READ_STREAM_TIME = (
    "(async()=>{try{const ac=window.__interceptify_ads_connector;"
    "if(!ac||typeof ac.getAdState!=='function')return -1;"
    "const s=await ac.getAdState();"
    "return parseInt(((s&&s.state)||{}).elapsed_stream_time,10)||0;}catch(e){return -1}})()"
)


def observe_playback_passively(state: dict) -> int:
    """Accumulate real listening WITHOUT repairing or restarting anything.

    The 30-minute requirement was unreachable by design: the only place
    observed_s grew was the post-repair report, and a run with a pending
    incident returns before ever getting there. So the promise "clears
    automatically after 24h with no further delivery" described a state the
    scheduler could not reach - the flag would sit up forever waiting for a
    number nothing incremented.

    This reads Spotify's own cumulative stream counter and banks the delta since
    the last look. It changes nothing: no patch, no restart, no gate write.

    Honest limit: it needs the CDP endpoint, which only exists when Spotify was
    launched with the debug port. Launch Spotify normally and no observation
    accrues - which is why the message on the pending path names
    --acknowledge-delivery rather than promising time will fix it.
    """
    d = delivery_block(state)
    if not d or not d.get("changed_at"):
        return 0
    if not cdp_is_live():
        return 0
    try:
        cdp = CDP(CDP_PORT)
        try:
            raw = cdp.ev(READ_STREAM_TIME)
        finally:
            cdp.close()
        now_t = int(raw) if isinstance(raw, (int, float)) else int(str(raw).strip())
    except Exception as e:
        log.debug("passive observation unavailable: %s", e)
        return 0
    if now_t < 0:
        return 0
    prev = d.get("stream_time_at")
    d["stream_time_at"] = now_t
    if prev is None:
        return 0                                 # first look establishes a baseline
    delta = now_t - int(prev)
    # A restart resets the counter, so a negative delta is a new session, not
    # negative listening. Re-baseline rather than subtracting.
    if delta <= 0:
        return 0
    d["observed_s"] = int(d.get("observed_s", 0)) + delta
    log.info("observed %ds of real playback on the current block (%ds of %ds needed)",
             delta, d["observed_s"], DELIVERY_MIN_OBSERVED_S)
    return delta


def clearable_reason(state: dict, fp: dict) -> str | None:
    """Why the unresolved delivery may be cleared now, or None if it may not."""
    d = delivery_block(state)
    if not d:
        return None
    # A backfilled entry has no recorded provenance, so it can only ever clear on
    # time - see backfill_delivery_failures(). Requiring a change we cannot define
    # would pin the flag up permanently.
    if d.get("backfilled"):
        elapsed = int(time.time()) - int(d.get("last_t") or 0)
        if elapsed < DELIVERY_CLEAR_AFTER_S:
            return None
        return (f"{elapsed // 3600}h have passed since the last recorded delivery "
                f"(provenance unknown, so this clears on time alone)")

    # Both sides are what Spotify is RUNNING. Comparing the sidecar config here
    # let a file edit alone satisfy "the block changed" - so a fix that was
    # never injected could clear a delivery that was never addressed.
    #
    # And UNKNOWN is not CHANGED. A missing live hash - an unpatched archive, an
    # unreadable one - used to compare unequal to the recorded hash and count as
    # a fix, so the state in which the block is not running at all was the state
    # most likely to retire a failure.
    if not (fp.get("live_payload_sha") and fp.get("live_config_sha")):
        return None
    if (fp["live_payload_sha"] == d.get("payload_sha")
            and fp["live_config_sha"] == d.get("config_sha")):
        return None                              # still the code that failed
    if fp["live_payload_sha"] != d.get("changed_to_payload") \
            or fp["live_config_sha"] != d.get("changed_to_config"):
        return None                              # changed again; the clock restarts

    # Measured from when the NEW code went in, not from when the ad played.
    since = int(d.get("changed_at") or 0)
    if not since:
        return None
    elapsed = int(time.time()) - since
    if elapsed < DELIVERY_CLEAR_AFTER_S:
        return None
    observed = int(d.get("observed_s") or 0)
    if observed < DELIVERY_MIN_OBSERVED_S:
        return None
    return (f"the running block changed {elapsed // 3600}h ago and {observed // 60} minute(s) of "
            f"real playback have been observed on it with no further delivery")


def resolve_verdict(structural_verdict: str | None, state: dict, fp: dict) -> tuple[str, int]:
    """Turn a STRUCTURAL verdict into the verdict we report, and an exit code.

    Kept as one small pure function because it encodes the rule the whole design
    turns on: a structural pass cannot overrule a recorded delivery. Inline in
    run() that rule was a couple of booleans among twenty other lines, and the
    version before it simply wrote `verified_pass = True` on a structural pass -
    so the program could log "an ad was delivered through a closed gate" and then
    show the user green.

    Exit codes: 0 pass, 2 not verified, 3 ads reached the user, 4 unproven.
    """
    pending = delivery_block(state)
    if pending:
        why = clearable_reason(state, fp)
        if not why:
            return "UNRESOLVED", 3
        # CLEAR IT HERE. Deciding a record is clearable and then leaving it in
        # place produced two components disagreeing about the same machine: run()
        # saved PASS while the record survived, and the next --verify read that
        # surviving record as FAIL. The decision and its consequence have to be
        # the same act, or "clearable" is a third state nobody handles.
        log.info("clearing the unresolved delivery flag: %s", why)
        state["cleared_delivery"] = {**pending, "cleared_t": int(time.time()), "why": why}
        state.pop("unresolved_delivery", None)
    if structural_verdict == "PASS":
        return "PASS", 0
    if structural_verdict == "UNKNOWN":
        return "UNKNOWN", 4
    return "FAIL", 2


def blocked_by_pending(fp: dict, pending: dict | None, force: bool) -> bool:
    """Should this run STOP because of an unresolved delivery?

    Only when there is nothing new to install. This predicate used to be an
    unconditional `if pending: return 3` sitting IN FRONT of the repair, so on
    any machine with a recorded failure the scheduled path could never patch
    Spotify with a newer payload or config - the one action that might actually
    resolve the failure was the one action the failure blocked. A machine that
    had heard an ad was therefore the machine least able to receive the fix.

    Extracted so the rule is testable on its own. Inline it was three conditions
    inside a forty-line function, which is how it stayed wrong across two
    reviews.
    """
    if not pending or force:
        return False
    needs_patch = (not fp.get("patched")) or (not fp.get("payload_matches")) \
        or (not fp.get("config_matches"))
    return not needs_patch


def report_update(fp: dict, state: dict, reason: str) -> None:
    """Log the DISCOVERY of a change (Spotify update / patch wiped / payload swapped)
    the moment we notice it — before any repair — so the vault shows what happened."""
    ts = time.strftime("%Y-%m-%d %H:%M")
    prev = state.get("verified_spotify_version")
    now = fp.get("spotify_version")
    if prev and now and prev != now:
        _vault_append([f"- {ts} — 🔄 **SPOTIFY UPDATED** `{prev}` -> `{now}` "
                       f"(patch wiped by the update; self-heal re-patching + verifying)"])
    elif not fp.get("patched"):
        _vault_append([f"- {ts} — 🔄 **PATCH MISSING** on spotify `{now}` — re-patching ({reason})"])
    elif not fp.get("payload_matches"):
        _vault_append([f"- {ts} — 🔄 **PAYLOAD DRIFT** on spotify `{now}` — live payload is not ours "
                       f"(something else re-patched); restoring + verifying"])
    else:
        _vault_append([f"- {ts} — 🔄 re-verifying on spotify `{now}` ({reason})"])


def report_run(verdict: str, spotify_ver: str, reason: str | None, detail: dict | None) -> None:
    """One short line per meaningful event (skips silent healthy no-ops)."""
    ts = time.strftime("%Y-%m-%d %H:%M")
    d = detail or {}
    if verdict == "PASS":
        _vault_append([f"- {ts} — self-heal **verified OK** on spotify `{spotify_ver}` "
                       f"(trigger: {reason or 'forced'}; gate=`{d.get('gateKeys')}` "
                       f"toggle={d.get('toggleProven')} reassert={d.get('reassertProven')})"])
    else:
        _vault_append([f"- {ts} — ⚠️ self-heal **NOT VERIFIED** on spotify `{spotify_ver}` "
                       f"(trigger: {reason or 'forced'}) — reasons: {d.get('reasons')}"])


def verify(cdp: CDP, duration_ms: int = 12000) -> dict:
    """Run the payload's STRUCTURAL self-test and require every layer.

    Structural is the honest word. It proves Spotify's ad switch moves both ways
    under our writes, that the core echoes them, that the block re-closes the
    gate by itself, that the delivery tripwire is armed and that every layer is
    attached. It does NOT prove an ad was prevented: ads are server-scheduled and
    nothing here can make one become due, so there is no positive control to
    compare against. A pass therefore never clears a RECORDED delivery - see
    note_delivery_failure().
    """
    def _health() -> dict:
        try:
            h = cdp.ev("JSON.stringify(window.__interceptify.health())")
            return json.loads(h) if isinstance(h, str) else {}
        except Exception:
            return {}

    raw = cdp.ev(
        "window.__interceptify.structuralSelftest({durationMs:%d}).then(r=>JSON.stringify(r))"
        % duration_ms,
        timeout=(duration_ms / 1000) * 2 + 90,
    )
    try:
        res = json.loads(raw) if isinstance(raw, str) else {"verdict": "FAIL", "error": str(raw)}
    except Exception:
        res = {"verdict": "FAIL", "error": str(raw)[:300]}
    # Health AFTER the window, not before it. The report that said PASS while
    # three layers were missing had read health the instant CDP attached - before
    # the lazily-loaded ads chunk had appeared and before gate discovery had run.
    # It was describing a moment that had nothing to do with the verdict.
    res["health"] = _health()
    layers = (res.get("health") or {}).get("layers") or {}
    missing = [k for k in REQUIRED_LAYERS if not layers.get(k)]
    if missing:
        res.setdefault("reasons", []).append(
            "block layers not installed at end of window: " + ", ".join(missing))
        res["missingLayers"] = missing
        res["verdict"] = "FAIL"
    return res


# --------------------------------------------------------------------------
# Self-repair — re-discover what moved, prove each candidate by verification
# --------------------------------------------------------------------------

DUMP_STATE_KEYS = r"""
(()=>{const ac=window.__interceptify_ads_connector;if(!ac)return 'null';
 return ac.getAdState().then(s=>{const o={};for(const k in (s.state||{}))o[k]=String(s.state[k].value);return JSON.stringify(o);}).catch(e=>'err:'+e.message);})()
"""

SCAN_CONNECTOR = r"""
(()=>{const M=window.__webpack_modules__||{};const out=[];
 for(const id of Object.keys(M)){let s='';try{const f=M[id].__intc_orig||M[id];s=Function.prototype.toString.call(f);}catch(e){continue;}
  if(s.indexOf('putState')>=0&&s.indexOf('getState')>=0&&(s.indexOf('subscribeToInStreamAds')>=0||s.indexOf('skipToNext')>=0))out.push(id);}
 return JSON.stringify(out.slice(0,40));})()
"""


def candidate_gate_keys(cdp: CDP) -> list[str]:
    """Live ad-state keys that look like a boolean ad switch."""
    raw = cdp.ev(DUMP_STATE_KEYS)
    try:
        st = json.loads(raw) if isinstance(raw, str) and raw.startswith("{") else {}
    except Exception:
        st = {}
    cands = []
    for k, v in st.items():
        if str(v).lower() in ("true", "false") and re.search(r"ad", k, re.I):
            cands.append(k)
    # most-likely first
    cands.sort(key=lambda k: (0 if re.search(r"enab", k, re.I) else 1, len(k)))
    log.info("ad-state boolean 'ad' keys: %s", cands)
    return cands



class _Missing:
    """The local config did not exist when the snapshot was taken."""
    def __repr__(self) -> str:
        return "<no local config>"


NO_CONFIG = _Missing()


def snapshot_config():
    """The config exactly as it is now, for rollback.

    Three distinct outcomes, and collapsing two of them was the bug: "the file
    did not exist" and "the file could not be read" both returned None, and
    restore_config() treats None as nothing-to-do. So on a machine with no local
    config - the normal state - a repair could write a guessed
    adblock.config.local.json, fail to prove it, "roll back" by doing nothing,
    and leave the guess behind. That file is the highest-priority config source
    and is never overwritten by a release, so an unproven guess would override
    every future shipped fix, permanently.
    """
    if not OUR_CONFIG.exists():
        return NO_CONFIG
    try:
        return OUR_CONFIG.read_text(encoding="utf-8")
    except Exception:
        return None                                  # exists but unreadable


def restore_config(snap: str | None, why: str) -> None:
    """Put the config back the way it was.

    Repair works by guessing a gate key and rewriting the config to match, then
    proving the guess by re-verifying. When no guess pans out, the guesses must
    not survive: otherwise a cycle that failed to fix anything still leaves the
    config pointing at whichever key it tried last, and the next run starts from
    a worse position than this one did.
    """
    if snap is None:
        return                                       # unreadable: nothing to restore TO
    if snap is NO_CONFIG:
        # There was no local config before this cycle, so anything here now is
        # something the repair invented and could not prove.
        try:
            if OUR_CONFIG.exists():
                OUR_CONFIG.unlink()
                log.warning("removed the local config a failed repair created (%s)", why)
        except OSError as e:
            log.error("could not remove the local config a failed repair created: %s", e)
        return
    try:
        if OUR_CONFIG.read_text(encoding="utf-8") == snap:
            return                                   # never touched, nothing to undo
        OUR_CONFIG.write_text(snap, encoding="utf-8")
        log.warning("rolled back %s (%s)", OUR_CONFIG.name, why)
    except Exception as e:
        log.error("could not roll back %s: %s", OUR_CONFIG.name, e)


def persist_gate_pattern(key: str) -> None:
    """Teach the config the discovered key so the repair survives restarts."""
    try:
        cfg = json.loads(OUR_CONFIG.read_text(encoding="utf-8"))
    except Exception:
        cfg = {}
    pats = cfg.get("adGateKeyPatterns") or []
    new = "^" + re.escape(key) + "$"
    if new not in pats:
        pats.insert(0, new)
    cfg["adGateKeyPatterns"] = pats
    # The fallback must follow too, otherwise a stale/renamed fallback keeps
    # pointing the block at a key that does not exist. Previously-known keys are
    # kept behind the new one rather than discarded: if this guess is wrong, the
    # key that used to work is still reachable instead of erased.
    old_fallbacks = [k for k in (cfg.get("adGateFallbackKeys") or []) if k != key]
    cfg["adGateFallbackKeys"] = [key] + old_fallbacks
    OUR_CONFIG.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    log.info("persisted ad-gate key %r (pattern %s) into adblock.config.json", key, new)


# --------------------------------------------------------------------------
# The cycle
# --------------------------------------------------------------------------

def repair_and_verify(max_rounds: int = 3, duration_ms: int = 12000) -> dict:
    report = {"ts": int(time.time()), "rounds": [], "verdict": "FAIL"}
    config_before = snapshot_config()
    for rnd in range(1, max_rounds + 1):
        log.info("=== round %d: stop -> patch -> launch -> verify ===", rnd)
        # Stop Spotify FIRST. It holds xpui.spa open, so patching a running
        # client fails on a lock - and this loop used to patch anyway, fail every
        # round, then kill and relaunch Spotify in the cleanup path. From a
        # scheduled task that reads as: interrupts playback, changes nothing.
        if not spotify_patcher.kill_spotify():
            report["rounds"].append({"round": rnd, "error": "could not stop Spotify; it holds xpui.spa open"})
            continue
        ok, msg = spotify_patcher.patch(debug_capture=False)
        log.info("patch: %s %s", ok, msg)
        if not ok:
            report["rounds"].append({"round": rnd, "error": f"patch failed: {msg}"})
            continue
        restart_spotify(CDP_PORT)
        cdp = None
        try:
            cdp = CDP(CDP_PORT)
            ver = wait_for_payload(cdp)
            got_conn = wait_for_connector(cdp)
            log.info("payload=%s connector=%s", ver, got_conn)
            res = verify(cdp, duration_ms)
            log.info("verify: %s", json.dumps(res)[:400])
            # Incidents are harvested from disk once per run(), not here: they
            # must be collected whether or not a verification ever happens.
            entry = {"round": rnd, "payload": ver, "connector": got_conn, "result": res}

            verdict = res.get("verdict")
            if verdict == "PASS":
                report["rounds"].append(entry)
                report["verdict"] = "PASS"
                report["final"] = res
                break

            if verdict == "UNKNOWN":
                # The gate proof held; the run simply could not corroborate it
                # because no audio streamed. Nothing is known to be broken, so
                # repairing would mean rewriting a working config to chase a
                # result the round was never able to produce. Stop and say so.
                report["rounds"].append(entry)
                report["verdict"] = "UNKNOWN"
                report["final"] = res
                log.warning("UNVERIFIED: gate proof passed but nothing was playing; "
                            "no repair attempted (nothing indicates a fault)")
                break

            # --- self-repair: find what moved -----------------------------
            # A candidate can only be proven by the payload actually USING it, so
            # we persist it to the config and let the NEXT round re-patch + verify.
            # (Writing the key from here while the payload still holds the old
            # config proves nothing — that was the bug this loop had.)
            repairs = []
            if not got_conn:
                mods = cdp.ev(SCAN_CONNECTOR)
                repairs.append({"connector_candidates": mods})
                log.warning("connector not found; module candidates: %s", mods)
            elif not res.get("gateFromBaseline") or not res.get("toggleProven"):
                log.warning("ad-gate not usable -> re-discovering from Spotify's live ad state")
                tried = report.setdefault("tried_keys", [])
                cands = [k for k in candidate_gate_keys(cdp) if k not in tried]
                if cands:
                    pick = cands[0]
                    tried.append(pick)
                    persist_gate_pattern(pick)
                    repairs.append({"persisted_gate_key": pick, "will_verify_next_round": True})
                    log.info("  adopted gate key %r -> re-patching and verifying next round", pick)
                else:
                    repairs.append({"error": "no untried gate-key candidates left"})
                    log.error("  no untried gate-key candidates left")
            entry["repairs"] = repairs
            report["rounds"].append(entry)
        except Exception as e:
            log.error("round %d failed: %s", rnd, e)
            report["rounds"].append({"round": rnd, "error": str(e)})
        finally:
            if cdp:
                cdp.close()

    # A cycle that did not reach PASS has no proven config change to keep.
    if report["verdict"] != "PASS":
        restore_config(config_before, f"cycle ended {report['verdict']} — no candidate was proven")

    # leave the user on a clean, non-debug Spotify
    try:
        spotify_patcher.kill_spotify()
        spotify_patcher.patch(debug_capture=False)
        restart_spotify(0)
    except Exception as e:
        log.warning("final clean relaunch: %s", e)

    REPORT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def status_only() -> dict:
    """What is true right now, without changing any of it.

    This is what "--verify" should always have been. The old implementation
    called the full selftest, which opens the ad gate, writes into Spotify's
    scheduler state, tries to make an ad break come due, and - since the
    convergence fix - starts playback itself. A status check that does all that
    is not a status check; it is a repair with a reassuring name, and running it
    to answer "is this working?" changes the answer.

    Everything here is a read: files on disk, and, if a debug session happens to
    be open already, the payload's own health snapshot. It never patches, never
    restarts Spotify, and never opens a CDP port.
    """
    fp = fingerprint()
    state = load_state()
    out = {
        "verdict": "UNKNOWN",
        "readOnly": True,
        "fingerprint": fp,
        "drift": drift_reason(fp, state),
        "lastVerdict": state.get("last_verdict"),
        "lastRun": state.get("last_run"),
        "reasons": [],
    }
    # First, because it is the only signal here that is about the user's actual
    # experience rather than about our own machinery.
    pending = delivery_block(state)
    if pending:
        out["unresolvedDelivery"] = pending
        out["verdict"] = "FAIL"
        out["reasons"].append(
            f"{pending['count']} ad(s) reached the user (first "
            f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(pending['first_t']))}) and that is "
            f"not established as fixed. A structural self-test passing does not clear this: it "
            f"cannot schedule an ad, so it proves the machinery and not the outcome.")
    try:
        import install_tasks
        foreign = install_tasks.foreign_deployment_tasks()
        if foreign:
            out["splitDeployment"] = [n for n, _ in foreign]
            out["reasons"].append(
                "autostart is registered for a different Interceptify install, which can "
                "re-patch Spotify with an older payload: " + ", ".join(n for n, _ in foreign))
    except Exception as e:
        out["reasons"].append(f"could not read the autostart registration: {e}")

    if not cdp_is_live():
        out["reasons"].append(
            f"no CDP endpoint on 127.0.0.1:{CDP_PORT}, so the live payload could not be asked "
            f"how it is doing. This reports the on-disk state only. `--selftest` proves the "
            f"block causally, but it restarts Spotify and interrupts playback.")
        # A sound on-disk state is not a passing verdict, and saying so is the
        # point: the files being right has never been what proves ads are blocked.
        # Never UPGRADE a verdict here: a pending delivery already set FAIL, and
        # "we could not reach the payload" must not soften it to UNKNOWN.
        sound = fp["patched"] and fp["payload_matches"] and fp["config_matches"]
        if out["verdict"] != "FAIL":
            out["verdict"] = "UNKNOWN" if sound else "FAIL"
        if not fp["patched"]:
            out["reasons"].append("Spotify is not patched")
        elif not fp["payload_matches"]:
            out["reasons"].append("the live payload is not the one this build ships")
        elif not fp["config_matches"]:
            out["reasons"].append("the live config is not the one this build would inject; "
                                  "a config change has not reached Spotify (re-patch required)")
        return out

    cdp = CDP(CDP_PORT)
    try:
        health = cdp.ev("JSON.stringify(window.__interceptify.health())")
        out["health"] = json.loads(health) if isinstance(health, str) else {}
    except Exception as e:
        out["reasons"].append(f"could not read live health: {e}")
        out["health"] = {}
    finally:
        cdp.close()

    missing = [k for k in REQUIRED_LAYERS if not (out.get("health", {}).get("layers") or {}).get(k)]
    if missing:
        out["verdict"] = "FAIL"
        out["reasons"].append("attached but these layers are not installed: " + ", ".join(missing))
    elif pending:
        pass                                     # already FAIL, and for a better reason
    elif not fp["config_matches"]:
        out["verdict"] = "FAIL"
        out["reasons"].append("every layer is attached, but Spotify is running an older injected "
                              "config than this build would inject (re-patch required)")
    elif fp["patched"] and fp["payload_matches"]:
        out["reasons"].append("every layer is attached; this is a snapshot, not the causal proof "
                              "(`--selftest` provides that)")
    return out


def selftest_now(duration_ms: int = 12000, allow_restart: bool = False) -> dict:
    """The DISRUPTIVE verification. It changes Spotify to prove the block works.

    Concretely, it opens the ad gate and closes it again, writes to the ad
    scheduler's state, drives the break timer, and starts playback if nothing is
    streaming - because a window with no audio cannot exercise the thing under
    test. Anyone running this should expect their playback to be interrupted.
    """
    restarted = False
    if not cdp_is_live():
        if not allow_restart:
            return {
                "verdict": "UNKNOWN",
                "reasons": [f"no CDP endpoint on 127.0.0.1:{CDP_PORT}; the selftest needs one. "
                            f"Re-run with --restart to relaunch Spotify for the check "
                            f"(this stops playback)."],
                "restarted": False,
            }
        spotify_patcher.kill_spotify()
        spotify_patcher.patch(debug_capture=False)
        restart_spotify(CDP_PORT)
        restarted = True

    # CDP is constructed INSIDE the guard. It used to be built on the line
    # before, so a failed connection raised past the cleanup and left Spotify
    # running with the debug port open - a CDP endpoint can drive the logged-in
    # session, so the one case where cleanup matters most was the case that
    # skipped it.
    cdp = None
    try:
        cdp = CDP(CDP_PORT)
        wait_for_payload(cdp)
        wait_for_connector(cdp)
        res = verify(cdp, duration_ms)
        res["restarted"] = restarted
        return res
    finally:
        if cdp is not None:
            try:
                cdp.close()
            except Exception:
                pass
        if restarted:
            # Do not leave the debug port listening.
            try:
                restart_spotify(0)
            except Exception as e:
                log.error("could not restore a non-debug Spotify: %s", e)


def run(force: bool = False, duration_ms: int = 12000) -> int:
    try:
        prune_diagnostics()
    except Exception as e:
        log.warning("diagnostic pruning: %s", e)
    fp = fingerprint()
    state = load_state()
    reason = drift_reason(fp, state)
    log.info("spotify=%s patched=%s payload_match=%s config_match=%s",
             fp["spotify_version"], fp["patched"], fp["payload_matches"], fp["config_matches"])

    # ALWAYS harvest first. An ad getting through is exactly the case where the
    # fingerprint is unchanged and the health check says "nothing to do", so
    # anything downstream of that branch can never see one.
    # Backfill BEFORE harvesting. harvest() appends this run's findings to the
    # incident log, and the backfill reads that same log - so the other order
    # counts the same deliveries twice, once as new and once as history.
    backfill_delivery_failures(state, fp)   # one-time, for deliveries logged
                                            # before this rule existed
    n = harvest(fp["spotify_version"], state)
    save_state(state)          # persist the watermark even when nothing was a
                               # failure, or expected self-test ads re-report
                               # on every run forever

    # An ad reaching the user IS drift, whatever the files say. The fingerprint
    # only sees the patch on disk; it cannot see a block that is present and no
    # longer working, which is precisely the failure worth repairing.
    if n:
        # Durable, not transient. See note_delivery_failure().
        note_delivery_failure(state, n, fp)
        save_state(state)
        if reason is None:
            reason = f"{n} ad(s) reached the user since the last run"
        state["verified_pass"] = False      # force a real re-verification

    # Stamp the moment the running block first differs from the one that failed.
    # Everything about clearance is measured from here, not from the delivery.
    note_block_change(state, fp)
    save_state(state)

    # An unresolved delivery outranks everything below. The files can be
    # perfect, the structural test can pass, and the user still heard an ad.
    pending = delivery_block(state)
    if pending:
        why_clear = clearable_reason(state, fp)
        if why_clear:
            log.info("clearing the unresolved delivery flag: %s", why_clear)
            state.pop("unresolved_delivery", None)
            save_state(state)
            pending = None
        elif reason is None:
            reason = (f"{pending['count']} ad(s) have reached the user and the failure is "
                      f"not established as fixed")

    # A second Interceptify install owning the autostart is drift that no
    # fingerprint can see: the files here are exactly right, and a different
    # copy re-patches over them at the next logon with its own payload. Verifying
    # this one proves nothing about what will be running tomorrow.
    try:
        import install_tasks
        foreign = install_tasks.foreign_deployment_tasks()
    except Exception as e:
        log.warning("could not read the autostart registration: %s", e)
        foreign = []
    if foreign:
        log.error("SPLIT DEPLOYMENT: %s run a different Interceptify install and can "
                  "re-patch Spotify with an older payload. Run install_tasks to re-register "
                  "autostart for this one.", ", ".join(n for n, _ in foreign))
        state["verified_pass"] = False
        save_state(state)
        return 2

    if reason is None and not force:
        log.info("healthy — already verified; no new ad incidents")
        return 0
    # An unresolved delivery does NOT outrank installing newer code. This return
    # sat in front of the repair unconditionally, so on a machine with a recorded
    # failure the scheduled path could never patch Spotify with the fix - the one
    # thing that might actually resolve the failure was the one thing blocked by
    # it. The stop is right only when there is nothing new to install.
    if pending and not force and not blocked_by_pending(fp, pending, force):
        log.warning("%d unresolved delivery incident(s), but the running block is not this "
                    "build (patched=%s payload=%s config=%s) - installing it anyway; the "
                    "incident stays open and the clearance window starts from this patch.",
                    pending["count"], fp["patched"], fp["payload_matches"], fp["config_matches"])
    elif blocked_by_pending(fp, pending, force):
        # Repairing again changes nothing on its own, and re-running the
        # structural test would only re-prove the plumbing. Say what is true and
        # stop, rather than performing a check whose passing would be misread.
        # Bank whatever real listening happened since the last look. Read-only:
        # no patch, no restart, no gate write. Without this the 30-minute
        # requirement was unreachable, because the only place observed_s grew
        # was after a repair - which this branch returns before ever reaching.
        try:
            observe_playback_passively(state)
            save_state(state)
        except Exception as e:
            log.warning("passive observation: %s", e)
        base = int(pending.get("changed_at") or pending.get("last_t") or 0)
        observed = int(pending.get("observed_s") or 0)
        earliest = time.strftime("%Y-%m-%d %H:%M",
                                 time.localtime(base + DELIVERY_CLEAR_AFTER_S))
        # State the BOTH conditions rather than promising time alone. Observation
        # needs the CDP endpoint, which only exists when Spotify was launched
        # with the debug port - so on a normally-launched client the honest
        # answer is that this clears when you say it does.
        log.error("UNRESOLVED: %d ad(s) reached the user (%s to %s). Re-running the structural "
                  "test would only re-prove the plumbing, so there is nothing to re-verify here. "
                  "Needs BOTH: no further delivery until %s, AND %d more seconds of observed "
                  "playback on this block (%d/%d so far; observation requires Spotify to be "
                  "running with the debug port). Otherwise clear it yourself with "
                  "--acknowledge-delivery.",
                  pending["count"],
                  time.strftime("%Y-%m-%d %H:%M", time.localtime(pending["first_t"])),
                  time.strftime("%Y-%m-%d %H:%M", time.localtime(pending["last_t"])),
                  earliest, max(0, DELIVERY_MIN_OBSERVED_S - observed),
                  observed, DELIVERY_MIN_OBSERVED_S)
        return 3
    log.info("ACTION NEEDED: %s", reason or "forced")
    try:
        report_update(fp, state, reason or "forced run")
    except Exception as e:
        log.warning("vault update report: %s", e)
    report = repair_and_verify(duration_ms=duration_ms)
    fp2 = fingerprint()
    # Resolved against the POST-repair fingerprint: a repair that genuinely
    # changed the payload or the config starts the 24h clock, it does not stop it.
    note_block_change(state, fp2)
    note_observed_playback(state, report)
    save_state(state)
    verdict, exit_code = resolve_verdict(report.get("verdict"), state, fp2)
    passed = verdict == "PASS"
    if verdict == "UNRESOLVED" and report.get("verdict") == "PASS":
        log.warning("structural verification PASSED, but %d ad(s) reached the user and that "
                    "is not established as fixed — reporting UNRESOLVED, not PASS",
                    state["unresolved_delivery"]["count"])
    state.update({
        "verified_pass": passed,
        "verified_spotify_version": fp2["spotify_version"] if passed else None,
        "verified_xpui_sha": fp2["xpui_sha"] if passed else None,
        "verified_payload_sha": fp2["live_payload_sha"] if passed else None,
        "verified_config_sha": fp2["live_config_sha"] if passed else None,
        "last_run": int(time.time()),
        "last_reason": reason,
        "last_verdict": verdict,
        "last_structural_verdict": report.get("verdict"),
    })
    save_state(state)
    final = report.get("final") or (report.get("rounds") or [{}])[-1].get("result") or {}
    try:
        report_run(report.get("verdict", "FAIL"), fp2["spotify_version"], reason, final)
    except Exception as e:
        log.warning("vault report: %s", e)
    if verdict == "UNRESOLVED":
        # Exit 3 whether or not the structural test passed. The scheduled task
        # records the day it mattered, not a clean run.
        # State BOTH conditions. "Clears automatically after 24h" was the claim
        # everywhere, and it was not true: observation only accrues while the
        # CDP endpoint is up, so on a normally-launched Spotify the honest
        # answer is that this clears when the user says it does.
        d = state["unresolved_delivery"]
        observed = int(d.get("observed_s") or 0)
        log.error("UNRESOLVED: structural verdict %s, but %d ad(s) reached the user and the "
                  "failure is not established as fixed. Needs %dh with no further delivery on "
                  "THIS block AND %ds more observed playback (%d/%d); observation requires "
                  "Spotify running with the debug port, so otherwise clear it with "
                  "--acknowledge-delivery.",
                  report.get("verdict"), d["count"], DELIVERY_CLEAR_AFTER_S // 3600,
                  max(0, DELIVERY_MIN_OBSERVED_S - observed), observed, DELIVERY_MIN_OBSERVED_S)
        return exit_code
    if passed:
        log.info("VERIFIED: gate proof held under real playback; 0 delivered, "
                 "0 ad-UI frames, 0 reactive skip/mute")
        return 0
    if report.get("verdict") == "UNKNOWN":
        # Distinct from failure on purpose. Reporting this as either success or
        # breakage would be a claim the run did not earn; the state file already
        # records verified_pass=False, so the next run retries.
        log.warning("UNPROVEN — gate proof held but nothing was playing. See %s", REPORT_FILE)
        return 4
    log.error("NOT VERIFIED — see %s", REPORT_FILE)
    return 2


# --------------------------------------------------------------------------
# Scheduled task
#
# Morning + night + at logon, defined once in install_tasks.py. Each run is the
# CHEAP check: read the Spotify version + hash xpui.spa and compare to the last
# verified state — milliseconds, no Spotify restart, exits immediately when
# nothing changed. The expensive repair+verify cycle only runs when that differs.
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Interceptify self-healing verifier")
    ap.add_argument("--once", action="store_true", help="check for drift; repair+verify only if needed")
    ap.add_argument("--force", action="store_true", help="always run the full repair+verify cycle")
    ap.add_argument("--verify", action="store_true",
                    help="report status without changing anything (read-only)")
    ap.add_argument("--selftest", action="store_true",
                    help="DISRUPTIVE: prove the block causally. Toggles Spotify's ad gate, "
                         "writes scheduler state and starts playback if nothing is streaming.")
    ap.add_argument("--restart", action="store_true",
                    help="allow --selftest to relaunch Spotify with a debug port (stops playback)")
    ap.add_argument("--scrub", action="store_true",
                    help="list the diagnostic files on disk (captures, netlogs, rotated logs)")
    ap.add_argument("--yes", action="store_true", help="with --scrub, actually delete them")
    ap.add_argument("--redact-captures", action="store_true",
                    help="strip credentials from the diagnostic files in place and report "
                         "what is left (these artifacts predate the redactor)")
    ap.add_argument("--acknowledge-delivery", action="store_true",
                    help="clear the unresolved-delivery flag. Only you can decide the ads "
                         "have stopped; no self-test here can establish it.")
    ap.add_argument("--fingerprint", action="store_true", help="print the detection fingerprint and exit")
    ap.add_argument("--install-task", action="store_true", help="register the silent scheduled tasks")
    ap.add_argument("--uninstall-task", action="store_true", help="remove the scheduled tasks")
    ap.add_argument("--duration-ms", type=int, default=12000)
    a = ap.parse_args(argv)

    # Task registration lives in install_tasks.py and nowhere else. This module
    # used to carry its own copy, which built a different command line from a
    # different code path - so which autostart you got depended on which script
    # you happened to run, and only one of the two knew about deployment splits.
    if a.uninstall_task:
        import install_tasks
        return install_tasks.main(["--remove"])
    if a.install_task:
        import install_tasks
        return install_tasks.main([])

    if a.redact_captures:
        return redact_captures()

    if a.scrub:
        return scrub(a.yes)

    if a.acknowledge_delivery:
        st = load_state()
        d = delivery_block(st)
        if not d:
            print("no unresolved delivery to acknowledge")
            return 0
        st.pop("unresolved_delivery", None)
        st["acknowledged_delivery"] = {**d, "acknowledged_t": int(time.time())}
        save_state(st)
        print(f"acknowledged {d['count']} delivery incident(s); status can go green again")
        return 0

    if a.fingerprint:
        print(json.dumps({"fingerprint": fingerprint(), "state": load_state(),
                          "drift": drift_reason(fingerprint(), load_state())}, indent=2))
        return 0
    if a.verify:
        res = status_only()
        print(json.dumps(res, indent=2))
        return {"PASS": 0, "UNKNOWN": 4}.get(res.get("verdict"), 2)
    if a.selftest:
        res = selftest_now(a.duration_ms, allow_restart=a.restart)
        print(json.dumps(res, indent=2))
        return {"PASS": 0, "UNKNOWN": 4}.get(res.get("verdict"), 2)
    return run(force=a.force, duration_ms=a.duration_ms)


if __name__ == "__main__":
    sys.exit(main())
