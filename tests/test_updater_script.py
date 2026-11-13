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
import json
import os
import subprocess
import sys
import tempfile
import threading
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
            f"f.WriteLine \"{tag} \" & CreateObject(\"WScript.Shell\").Environment(\"PROCESS\")(\"PYINSTALLER_RESET_ENVIRONMENT\")\r\nf.Close\r\n").encode("ascii")


_CONSOLE_CLASSES = ("ConsoleWindowClass", "CASCADIA_HOSTING_WINDOW_CLASS", "PseudoConsoleWindow")


def visible_console_windows() -> dict:
    """Every console or Terminal window currently visible on screen."""
    import ctypes
    from ctypes import wintypes
    u = ctypes.windll.user32
    found = {}

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(h, _):
        if u.IsWindowVisible(h):
            cls = ctypes.create_unicode_buffer(128)
            u.GetClassNameW(h, cls, 128)
            if cls.value in _CONSOLE_CLASSES:
                title = ctypes.create_unicode_buffer(200)
                u.GetWindowTextW(h, title, 200)
                found[int(h or 0)] = f"{cls.value}: {title.value.strip()}"
        return True

    u.EnumWindows(cb, 0)
    return found


def scenario(name: str, *, tamper: bool = False, lock: bool = False, busy_s: float = 0):
    base = Path(tempfile.mkdtemp(prefix="intc-upd-")) / "Användare åäö" / "Interceptify"
    base.mkdir(parents=True)
    marker = base / "started.txt"
    target = base / "Interceptify.vbs"
    new = base / "Interceptify.vbs.new"
    target.write_bytes(stand_in("old", marker))
    good = stand_in("new", marker)
    new.write_bytes(good + (b"' tampered\r\n" if tamper else b""))
    bat = base / "_interceptify_update.bat"
    self_updater.write_updater_bat(bat, new_exe=new, target_exe=target,
                                   expected_sha256=hashlib.sha256(good).hexdigest(), swap_wait_s=8)
    held = None
    if lock or busy_s:
        # An open handle without delete sharing is what a still-running exe looks like.
        held = open(target, "rb")
        if busy_s:
            # ...and this is the old program's launcher letting go a few seconds later
            threading.Timer(busy_s, held.close).start()
    try:
        # Started exactly the way the tray starts it, with the screen watched
        # for the whole run: an update must never put a window in front of
        # the user.
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
        p = self_updater.launch_updater_bat(bat)
        try:
            p.wait(timeout=30)
            finished = True
        except subprocess.TimeoutExpired:
            # the whole tree, so a window it opened does not stay on screen
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True,
                           creationflags=0x08000000)
            finished = False
        end = time.time() + 15
        while time.time() < end and not marker.exists():
            time.sleep(0.3)
    finally:
        stop.set()
        watcher.join(timeout=2)
        if held:
            held.close()
    words = marker.read_text(encoding="ascii", errors="replace").split() if marker.exists() else []
    started = words[0] if words else ""
    log = (base / "update.log").read_text(encoding="utf-8", errors="replace") if (base / "update.log").exists() else ""
    return {"finished": finished, "started": started, "log": log, "new_left": new.exists(),
            "windows": sorted(set(windows.values())), "fresh": words[1:] == ["1"],
            "bat_left": bat.exists(), "target_is_new": target.read_bytes() == good}


def main() -> int:
    if os.name != "nt":
        print("Windows only")
        return 0

    # The tray has no console of its own. Run one scenario from a program
    # that has none either and collect what it saw.
    if len(sys.argv) == 3 and sys.argv[1] == "--windowless":
        Path(sys.argv[2]).write_text(json.dumps(scenario("windowless")), encoding="utf-8")
        return 0

    r = scenario("good")
    check("1a. a good download is swapped in", r["target_is_new"] and not r["new_left"], str(r))
    check("1b. ...the new build is started", r["started"] == "new", repr(r["started"]))
    check("1c. ...the script ends on its own, removes itself and logs the outcome",
          r["finished"] and not r["bat_left"] and "updated" in r["log"], str(r))

    check("1d. ...and no console or Terminal window appears at any moment", not r["windows"], str(r["windows"]))
    check("1e. ...and the new build is started as a fresh program, not as a helper of the old one", r["fresh"], str(r))

    r = scenario("busy", busy_s=4)
    check("5a. while the old exe is still in use the script waits, then swaps and starts the new build",
          r["target_is_new"] and r["started"] == "new" and r["finished"] and not r["new_left"], str(r))
    check("5b. ...with no window while it waits", not r["windows"], str(r["windows"]))

    pyw = Path(sys.executable).with_name("pythonw.exe")
    if pyw.exists():
        out = Path(tempfile.mkdtemp(prefix="interceptify-upd-")) / "windowless.json"
        subprocess.run([str(pyw), str(Path(__file__).resolve()), "--windowless", str(out)], timeout=120)
        w = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        check("4a. started from a program with no console, as the tray is: swapped, started, finished",
              bool(w) and w["target_is_new"] and w["started"] == "new" and w["finished"] and not w["bat_left"], str(w))
        check("4b. ...and still no window at any moment", bool(w) and not w["windows"], str(w.get("windows")))
    else:
        print("[SKIP] 4. no pythonw.exe next to this Python")

    r = scenario("tampered", tamper=True)
    check("2d. a refused update shows no window either", not r["windows"], str(r["windows"]))
    check("2a. a download whose hash does not match is not installed",
          not r["target_is_new"] and not r["new_left"], str(r))
    check("2b. ...the existing build is started again", r["started"] == "old", repr(r["started"]))
    check("2c. ...nothing waits on a hidden console, and the log says why",
          r["finished"] and not r["bat_left"] and "refused" in r["log"], str(r))

    r = scenario("locked", lock=True)
    check("3a. when the exe cannot be replaced the old build stays in place", not r["target_is_new"], str(r))
    check("3b. ...and is started again, as a fresh program", r["started"] == "old" and r["fresh"], repr(r["started"]))
    check("3d. ...and the unused download is removed", not r["new_left"], str(r))
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
