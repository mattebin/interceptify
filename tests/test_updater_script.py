"""
Run the updater script for real.

write_updater_bat() produces a batch file that runs detached, after the app has
exited, with no window. Reading it proves nothing about what cmd does with it,
so this executes it: a stand-in "exe" (a script that records which build ran)
is swapped by the real script, through the real cmd, with the real certutil
hash check, in a folder whose name is not ASCII. The stand-in is a .vbs run by
wscript, so nothing here opens a window.

  1. good download   -> swapped in, new build started, logged
  2. tampered download -> refused, the OLD build is started again, logged
  3. target locked   -> swap fails, the OLD build is started again, logged

In every case the script must finish on its own (nothing waits on a hidden
console) and delete itself.

    python tests/test_updater_script.py
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import self_updater  # noqa: E402

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"   :: {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def stand_in(tag: str, marker: Path) -> bytes:
    # Records which build ran. Windows Script Host has no console, so starting
    # it shows nothing. ASCII only, so its bytes (and its hash) do not depend
    # on a codepage; the folder is found from the script's own path.
    return ("Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n"
            "Set f = fso.OpenTextFile(fso.GetParentFolderName(WScript.ScriptFullName) & \"\\"
            f"{marker.name}\", 8, True)\r\n"
            f"f.WriteLine \"{tag}\"\r\nf.Close\r\n").encode("ascii")


def scenario(name: str, *, tamper: bool = False, lock: bool = False):
    base = Path(tempfile.mkdtemp(prefix="intc-upd-")) / "Användare åäö" / "Interceptify"
    base.mkdir(parents=True)
    marker = base / "started.txt"
    target = base / "Interceptify.vbs"
    new = base / "Interceptify.vbs.new"
    target.write_bytes(stand_in("old", marker))
    good = stand_in("new", marker)
    new.write_bytes(good + (b"' tampered\r\n" if tamper else b""))
    bat = base / "_interceptify_update.bat"
    self_updater.write_updater_bat(bat, current_pid=4000000, new_exe=new, target_exe=target,
                                   expected_sha256=hashlib.sha256(good).hexdigest())
    held = None
    if lock:
        # An open handle without delete sharing is what a still-running exe looks like.
        held = open(target, "rb")
    try:
        p = subprocess.Popen(["cmd", "/c", str(bat)], cwd=str(base),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                             creationflags=0x08000000)
        try:
            p.wait(timeout=60)
            finished = True
        except subprocess.TimeoutExpired:
            p.kill()
            finished = False
        end = time.time() + 15
        while time.time() < end and not marker.exists():
            time.sleep(0.3)
    finally:
        if held:
            held.close()
    started = marker.read_text(encoding="ascii", errors="replace").strip() if marker.exists() else ""
    log = (base / "update.log").read_text(encoding="utf-8", errors="replace") if (base / "update.log").exists() else ""
    return {"finished": finished, "started": started, "log": log, "new_left": new.exists(),
            "bat_left": bat.exists(), "target_is_new": target.read_bytes() == good}


def main() -> int:
    if os.name != "nt":
        print("Windows only")
        return 0

    r = scenario("good")
    check("1a. a good download is swapped in", r["target_is_new"] and not r["new_left"], str(r))
    check("1b. ...the new build is started", r["started"] == "new", repr(r["started"]))
    check("1c. ...the script ends on its own, removes itself and logs the outcome",
          r["finished"] and not r["bat_left"] and "updated" in r["log"], str(r))

    r = scenario("tampered", tamper=True)
    check("2a. a download whose hash does not match is not installed",
          not r["target_is_new"] and not r["new_left"], str(r))
    check("2b. ...the existing build is started again", r["started"] == "old", repr(r["started"]))
    check("2c. ...nothing waits on a hidden console, and the log says why",
          r["finished"] and not r["bat_left"] and "refused" in r["log"], str(r))

    r = scenario("locked", lock=True)
    check("3a. when the exe cannot be replaced the old build stays in place", not r["target_is_new"], str(r))
    check("3b. ...and is started again", r["started"] == "old", repr(r["started"]))
    check("3c. ...the script still ends on its own and logs it",
          r["finished"] and "failed to replace" in r["log"], str(r))

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print("updater script: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
