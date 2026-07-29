"""
Exercise the PACKAGED build the way a user's machine would, against a disposable
Spotify.

The .exe is a different program from the source tree in every way that has
already bitten this project: its own root directory, its own bundled copies of
the payload and config, its own module graph, and a windowed subsystem with no
stdout. Testing main.py proves none of that. Two real defects were found here
rather than in the source:

  * selfheal derived its paths from __file__, which under PyInstaller is the
    temp directory the bundle unpacks into and deletes on exit. State, report
    and log would have vanished after every run, so a packaged self-heal would
    have re-verified - and therefore restarted Spotify - on every schedule.
  * every print() in the subcommands went nowhere, so
    `Interceptify.exe --install-tasks --status` looked like it did nothing.

What this covers: the dispatcher, extension sync next to the .exe, path
resolution, the read-only guarantee of --verify against a real archive, and
deployment reporting.

What it does NOT cover, deliberately: the patch -> restart -> verify -> rollback
cycle. That path stops and relaunches Spotify by process name, so running it
here would kill the real client on the machine doing the testing. It needs a VM
or a container with its own Spotify, and until it has run there, the packaged
repair cycle is unproven - say so rather than implying otherwise.

Run:  python tests/test_frozen_cycle.py dist/Interceptify.exe
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"   :: {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def build_fake_spotify(appdata: Path) -> Path:
    xpui = appdata / "Spotify" / "Apps" / "xpui.spa"
    xpui.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(xpui, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.html", "<html><body><div>ORIGINAL</div></body></html>")
        z.writestr("xpui.js", "console.log('spotify ui');")
    (appdata / "Spotify" / "prefs").write_text(
        'app.last-launched-version="1.2.94.583.g60394bd5"\n', encoding="utf-8")
    return xpui


def run(exe: Path, args: list[str], appdata: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ, APPDATA=str(appdata))
    return subprocess.run([str(exe), *args], capture_output=True, text=True, env=env, timeout=180)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("[FAIL] usage: test_frozen_cycle.py <path to Interceptify.exe>")
        return 1
    src_exe = Path(argv[1])
    if not src_exe.is_file():
        print(f"[FAIL] {src_exe} does not exist")
        return 1

    # Copy the exe somewhere disposable: it writes its sidecars next to itself,
    # and that is one of the things being checked.
    work = Path(tempfile.mkdtemp(prefix="interceptify-frozen-"))
    exe = work / "install" / "Interceptify.exe"
    exe.parent.mkdir(parents=True)
    shutil.copy2(src_exe, exe)
    appdata = work / "appdata"
    xpui = build_fake_spotify(appdata)
    before = hashlib.sha256(xpui.read_bytes()).hexdigest()

    r = run(exe, ["--version"], appdata)
    check("1. the packaged dispatcher runs a subcommand instead of the tray",
          r.returncode == 0 and "Interceptify" in r.stdout, f"rc={r.returncode} out={r.stdout!r}")

    ext = exe.parent / "extensions"
    check("2. the bundled payload is written next to the .exe, not into the temp bundle",
          (ext / "adblock.js").is_file() and (ext / "adblock.config.json").is_file(),
          f"{[p.name for p in exe.parent.iterdir()]}")

    r = run(exe, ["--selfheal", "--verify"], appdata)
    try:
        report = json.loads(r.stdout[r.stdout.index("{"):r.stdout.rindex("}") + 1])
    except Exception:
        report = None
    check("3. --verify produces a readable report from the packaged build",
          isinstance(report, dict) and "verdict" in report,
          f"rc={r.returncode} stdout={r.stdout[:200]!r}")
    check("3b. ...and reports the disposable Spotify as unpatched",
          bool(report) and report.get("fingerprint", {}).get("patched") is False,
          json.dumps(report or {})[:200])

    after = hashlib.sha256(xpui.read_bytes()).hexdigest()
    check("4. --verify is read-only: Spotify's archive is byte-for-byte unchanged",
          before == after, f"{before[:16]} -> {after[:16]}")

    check("5. state lives next to the .exe, so it survives the process exiting",
          (exe.parent / "selfheal.log").is_file(),
          f"{[p.name for p in exe.parent.iterdir()]}")

    r = run(exe, ["--install-tasks", "--status"], appdata)
    check("6. the packaged task installer reports the FROZEN deployment",
          "deployment: frozen" in r.stdout, f"rc={r.returncode} out={r.stdout[:200]!r}")
    check("6b. ...and points its commands at the .exe, not at a source checkout",
          "--selfheal" in r.stdout or "NOT REGISTERED" in r.stdout, r.stdout[:200])

    print()
    print("NOT covered here: patch -> restart -> verify -> rollback from the packaged")
    print("build. That path stops Spotify by process name, so it needs a disposable")
    print("machine, not a disposable APPDATA. It remains unproven.")
    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print("frozen build: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
