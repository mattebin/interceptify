"""
The real update, end to end, with the real exe.

Every other updater test runs pieces. This one runs the thing itself: the
packaged tray, started the way Windows starts it, finds a newer release on
GitHub, downloads it, swaps itself and comes back. Nothing is stubbed.

To have something to update FROM, the same source is built once more with a
low version number (in a temporary copy, the working tree is not touched). That
exe carries this commit's updater, which is the code the next release will run
on every PC.

Passes only if:
  * the exe in the folder becomes the published release, byte for byte
  * the tray is running again afterwards, from that folder
  * the update script cleaned up after itself
  * no console or Terminal window appeared at any moment

It needs the network, a desktop session and no other Interceptify running, so
it runs in the release pipeline, before anything is published.

    python tests/test_real_update.py
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import self_updater  # noqa: E402
from test_updater_script import visible_console_windows  # noqa: E402

NOWIN = 0x08000000
OLD_VERSION = "0.0.1"
FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"   :: {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build_old_exe(work: Path) -> Path:
    """This commit, built with a low version number, in a copy."""
    src = work / "src"
    shutil.copytree(ROOT, src, ignore=shutil.ignore_patterns(".git", "dist", "build", "__pycache__", "recon"))
    main_py = src / "main.py"
    text = main_py.read_text(encoding="utf-8")
    patched, n = re.subn(r'^APP_VERSION = "[^"]+"', f'APP_VERSION = "{OLD_VERSION}"', text, count=1, flags=re.M)
    assert n == 1, "APP_VERSION line not found"
    main_py.write_text(patched, encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--log-level", "ERROR",
                        "--distpath", str(work / "dist"), "--workpath", str(work / "build"), "Interceptify-v2.spec"],
                       cwd=str(src), capture_output=True, text=True, creationflags=NOWIN)
    exe = work / "dist" / "Interceptify.exe"
    assert r.returncode == 0 and exe.exists(), (r.stdout + r.stderr)[-800:]
    return exe


def trays_in(folder: Path) -> list[int]:
    """Process ids of Interceptify.exe running from this folder."""
    cmd = ("Get-CimInstance Win32_Process -Filter \"Name='Interceptify.exe'\" | "
           "ForEach-Object { '{0}|{1}' -f $_.ProcessId, $_.ExecutablePath }")
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                       capture_output=True, text=True, creationflags=NOWIN)
    out = []
    for line in r.stdout.splitlines():
        pid, _, path = line.partition("|")
        if path and Path(path).parent.resolve() == folder.resolve():
            out.append(int(pid))
    return out


def main() -> int:
    if os.name != "nt":
        print("Windows only")
        return 0
    rel = self_updater.get_latest_release()
    if rel is None or not rel.exe_asset_sha256:
        print("[FAIL] could not read the latest release from GitHub")
        return 1
    print(f"latest release: {rel.tag}")

    work = Path(tempfile.mkdtemp(prefix="interceptify-real-update-"))
    old_exe = build_old_exe(work)
    inst = work / "Användare åäö" / "Interceptify"
    inst.mkdir(parents=True)
    exe = inst / "Interceptify.exe"
    shutil.copy2(old_exe, exe)
    (inst / "config.json").write_text(json.dumps({"auto_update": True}), encoding="utf-8")
    old_sha = sha(exe)

    before = visible_console_windows()
    windows: dict = {}
    stop = threading.Event()

    def watch() -> None:
        while not stop.is_set():
            for h, what in visible_console_windows().items():
                if h not in before:
                    windows[h] = what
            time.sleep(0.02)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    swapped_after = None
    try:
        subprocess.Popen([str(exe)], cwd=str(inst), close_fds=True)
        time.sleep(8)
        check("1. the tray starts and stays running", bool(trays_in(inst)), "it exited: is another Interceptify running?")
        t0 = time.time()
        # the tray looks for a release one minute after it starts
        while not FAILURES and time.time() - t0 < 300:
            try:
                if sha(exe) == rel.exe_asset_sha256.lower():
                    swapped_after = round(time.time() - t0)
                    break
            except OSError:
                pass                      # mid-swap
            time.sleep(1)
        check(f"2. the exe was replaced by the published {rel.tag}, byte for byte",
              swapped_after is not None, f"still the old build: {sha(exe) == old_sha}")
        back = []
        t1 = time.time()
        while swapped_after is not None and time.time() - t1 < 60 and not back:
            time.sleep(2)
            back = trays_in(inst)
        check("3. the tray is running again from the same folder", bool(back))
        time.sleep(5)
        log = (inst / "update.log").read_text(encoding="utf-8", errors="replace") if (inst / "update.log").exists() else ""
        check("4. the update script removed itself and its download, and logged the outcome",
              not (inst / "_interceptify_update.bat").exists() and not (inst / "Interceptify.exe.new").exists()
              and "updated" in log, f"left: {sorted(p.name for p in inst.iterdir())} log={log.strip()[-80:]!r}")
    finally:
        stop.set()
        watcher.join(timeout=2)
        for pid in trays_in(inst):
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, creationflags=NOWIN)
        # a script that got stuck is not a child of the tray any more
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "Get-CimInstance Win32_Process -Filter \"Name='cmd.exe'\" | "
                        "Where-Object { $_.CommandLine -like '*_interceptify_update.bat*' } | "
                        "ForEach-Object { taskkill /PID $_.ProcessId /T /F }"],
                       capture_output=True, creationflags=NOWIN)
    check("5. no console or Terminal window appeared at any moment", not windows, str(sorted(set(windows.values()))))

    if FAILURES:
        print(f"\n{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print(f"\nreal update: ALL PASSED ({OLD_VERSION} -> {rel.tag} in {swapped_after}s after the tray started looking).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
