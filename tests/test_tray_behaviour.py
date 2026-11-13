"""
The tray has to do what its menu says, and the pieces behind it have to agree
with it. Each case here is something that was observed NOT to hold:

  1. Unpatch was undone by the next scheduled self-heal.
  2. Self-heal re-patched with its own defaults, ignoring the status-dot and
     debug-capture settings.
  3. An available update produced a toast and nothing else; nothing installed
     it, and after an install Spotify kept the old payload.
  4. The updater script paused forever on a hidden console when it failed and
     never brought the tray back; it broke on non-ASCII install paths.
  5. The tray is silent: it never shows a toast. What happened is in the log
     and on the status line at the top of the menu.
  6. Task Scheduler killed the tray after one hour.
  7. The packaged self-heal never wrote its log.

No network, no Spotify, nothing outside a temp directory.

    python tests/test_tray_behaviour.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"   :: {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="interceptify-tray-"))
    os.environ["APPDATA"] = str(tmp / "appdata")
    (tmp / "appdata").mkdir()

    import selfheal
    import spotify_patcher
    import self_updater
    import install_tasks

    # ---------------------------------------------------------------- 1 + 2
    selfheal.ROOT = tmp
    cfg = tmp / "config.json"
    calls: list[dict] = []
    real_patch = spotify_patcher.patch
    spotify_patcher.patch = lambda **kw: (calls.append(kw) or (True, "patched"))
    try:
        cfg.write_text(json.dumps({"show_badge": False, "debug_capture": True}), encoding="utf-8")
        selfheal._patch_as_user()
        check("2a. self-heal patches with the user's status-dot and debug-capture settings",
              calls[-1] == {"show_badge": False, "debug_capture": True}, str(calls[-1]))
        selfheal._patch_as_user(debug_capture=False)
        check("2b. a verification round forces debug capture off but keeps the status dot",
              calls[-1] == {"show_badge": False, "debug_capture": False}, str(calls[-1]))
        cfg.unlink()
        selfheal._patch_as_user()
        check("2c. with no config the defaults are status dot on, debug capture off",
              calls[-1] == {"show_badge": True, "debug_capture": False}, str(calls[-1]))

        # _run(): everything before the gate is stubbed, and the first thing
        # AFTER the gate raises, so "returned 0" can only mean the gate fired.
        class Reached(Exception):
            pass

        def boom(*a, **k):
            raise Reached()

        selfheal.prune_diagnostics = lambda: None
        selfheal.published_version_gap = lambda: {"status": "unknown", "detail": "test", "app": "", "published": ""}
        selfheal.fingerprint = lambda: {"spotify_version": "t", "patched": False,
                                        "payload_matches": False, "config_matches": False}
        selfheal.load_state = lambda: {}
        selfheal.drift_reason = lambda fp, st: "not patched"
        selfheal.backfill_delivery_failures = boom

        calls.clear()
        cfg.write_text(json.dumps({"user_unpatched": True}), encoding="utf-8")
        try:
            rc = selfheal._run()
        except Reached:
            rc = "ran past the gate"
        check("1a. after Unpatch in the tray, a scheduled self-heal run leaves Spotify alone",
              rc == 0 and not calls, f"rc={rc} patch calls={len(calls)}")
        try:
            selfheal._run(force=True)
            forced = False
        except Reached:
            forced = True
        check("1b. ...but --force still runs", forced)
        cfg.write_text(json.dumps({"user_unpatched": False}), encoding="utf-8")
        try:
            selfheal._run()
            went_on = False
        except Reached:
            went_on = True
        check("1c. ...and without the flag the run proceeds past the gate", went_on)
    finally:
        spotify_patcher.patch = real_patch

    # -------------------------------------------------------------------- 4
    inst = tmp / "Användare åäö" / "Interceptify"
    inst.mkdir(parents=True)
    bat = inst / "_interceptify_update.bat"
    target = inst / "Interceptify.exe"
    self_updater.write_updater_bat(bat, current_pid=4242, new_exe=inst / "Interceptify.exe.new",
                                   target_exe=target, expected_sha256="ab" * 32)
    raw = bat.read_bytes()
    text = raw.decode("utf-8")
    lines = [l.strip() for l in text.splitlines()]
    check("4a. the updater script never waits on a console nobody can see",
          not any(l.lower() == "pause" for l in lines), "contains pause")
    check("4b. it switches cmd to UTF-8 before the first path appears",
          lines[0].lower() == "@echo off" and lines[1].lower().startswith("chcp 65001"), str(lines[:2]))
    check("4c. a non-ASCII install path survives as UTF-8 bytes",
          str(target).encode("utf-8") in raw, "path not found in the script bytes")
    relaunch_old = f'start "" "{target}"'
    check("4d. both failure branches bring the existing tray back",
          lines.count(relaunch_old) == 2, f"count={lines.count(relaunch_old)}")
    check("4e. success relaunches with --updated so the new payload gets applied",
          f'start "" "{target}" --updated' in lines)
    check("4f. every outcome leaves a line in update.log",
          text.count(str(inst / "update.log")) == 3, f"count={text.count(str(inst / 'update.log'))}")

    # -------------------------------------------------------------------- 6
    tray_xml = install_tasks.task_xml(install_tasks.tray_command(), "LogonTrigger")
    heal_xml = install_tasks.task_xml(install_tasks.heal_command(), "LogonTrigger")
    check("6a. the tray task has no execution time limit",
          "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>" in tray_xml)
    check("6b. self-heal tasks keep the one-hour limit",
          "<ExecutionTimeLimit>PT1H</ExecutionTimeLimit>" in heal_xml)
    check("6c. tasks run at normal priority, in schema order after the time limit",
          "</ExecutionTimeLimit><Priority>4</Priority>" in tray_xml and "<Priority>4</Priority>" in heal_xml)
    exe, args = install_tasks._split_command(install_tasks.tray_command())
    good = {"command": exe.strip('"'), "arguments": args, "level": "", "trigger_kinds": ["LogonTrigger"],
            "priority": "4"}
    old = install_tasks.wrong_with({**good, "limit": "PT1H"}, install_tasks.tray_command(), "LogonTrigger")
    low = install_tasks.wrong_with({**good, "limit": "PT0S", "priority": ""}, install_tasks.tray_command(), "LogonTrigger")
    check("6e. a task registered without a priority (Windows default, below normal) is reported as wrong",
          any("below-normal priority" in p for p in low), str(low))
    fine = [p for p in install_tasks.wrong_with({**good, "limit": "PT0S"}, install_tasks.tray_command(), "LogonTrigger")
            if "priority" in p or "stopped by" in p]
    check("6f. ...and a task with the new settings is not", fine == [], str(fine))
    check("6d. an already-registered tray task with the old limit is reported as wrong",
          any("stopped by Task Scheduler" in p for p in old), str(old))

    # ---------------------------------------------------------------- 3 + 5
    import main as app
    app.CONFIG_PATH = tmp / "tray-config.json"

    class FakeIcon:
        def __init__(self):
            self.shown = []
            self.icon = None
            self.title = ""
            self.menu = None

        def notify(self, msg, title=""):
            self.shown.append(msg)                        # a toast: must never happen

        def update_menu(self):
            pass

    a = app.InterceptifyApp()
    a.icon = FakeIcon()
    a.notify("Spotify patched.")
    a.notify("x" * 276)
    check("5a. the tray never shows a toast",
          a.icon.shown == [], f"toasts={len(a.icon.shown)}")
    check("5b. ...the last message is on the menu's status line instead, trimmed to fit",
          a._status_line().endswith("...") and len(a._status_line()) < 110 and "x" * 20 in a._status_line(),
          a._status_line()[:60])
    src = (ROOT / "main.py").read_text(encoding="utf-8")
    check("5c. ...and no code path in the tray can raise one",
          ".icon.notify(" not in src and "icon.notify(" not in src, "main.py still calls icon.notify")

    check("3a. automatic updates are on by default", a.cfg.get("auto_update") is True, str(a.cfg))
    installs = []
    a.install_update = lambda *x: installs.append(1)

    class Rel:
        tag = "v9.9.9"

    a._last_status = None
    a._offer_or_install(Rel())
    check("3b. a newer release is installed, not just announced",
          installs == [1] and a._last_status is None, f"installs={installs} status={a._last_status}")
    a._offer_or_install(Rel())
    check("3c. the same release is not retried every poll; the status line says it is waiting",
          installs == [1] and a._last_status is not None and "v9.9.9" in a._last_status[0],
          f"installs={installs} status={a._last_status}")
    a.cfg["auto_update"] = False
    a._auto_update_tried = None
    a._last_status = None
    a._offer_or_install(Rel())
    check("3d. with automatic updates off it only says an update exists",
          installs == [1] and a._last_status is not None and "v9.9.9" in a._last_status[0],
          f"installs={installs} status={a._last_status}")
    check("3i. nothing in the update flow produced a toast", a.icon.shown == [], str(a.icon.shown))

    # autostart: three separate switches, each touching only its own tasks
    did_tasks = []
    saved_it = (install_tasks.install, install_tasks.remove, install_tasks.group_enabled)
    on = {"tray": True, "login_repair": False, "daily_repair": False}
    try:
        install_tasks.group_enabled = lambda g: on[g]
        install_tasks.install = lambda only=None: (did_tasks.append(("install", sorted(only))) or 0)
        install_tasks.remove = lambda only=None: (did_tasks.append(("remove", sorted(only))) or 0)
        a.toggle_autostart_group("daily_repair")
        a.toggle_autostart_group("tray")
        check("8a. switching the daily repair on registers only the two daily tasks",
              did_tasks[0] == ("install", sorted(install_tasks.GROUPS["daily_repair"])), str(did_tasks[:1]))
        check("8b. switching the tray off removes only the tray task",
              did_tasks[1] == ("remove", [install_tasks.TRAY_TASK]), str(did_tasks[1:2]))
        every = sorted(n for g in install_tasks.GROUPS.values() for n in g)
        check("8c. the three options cover every task the app registers, with no overlap",
              every == sorted(n for n, _, _, _ in install_tasks.tasks()), str(every))
        menu_src = src[src.index("def build_menu"):src.index("def run(self)")]
        check("8d. the tray menu has an Autostart submenu built from those options",
              'Item("Autostart", Menu(' in menu_src and "_AUTOSTART_LABELS" in menu_src)
    finally:
        install_tasks.install, install_tasks.remove, install_tasks.group_enabled = saved_it

    # ...and the real install()/remove() honour the selection (stubbed above).
    import contextlib
    import io
    deleted = []

    class R:
        returncode = 0
        stdout = stderr = ""

    saved_real = (install_tasks._schtasks, install_tasks.describe, install_tasks.wrong_with,
                  install_tasks.remove_run_key, install_tasks.INSTALL_STAMP)
    try:
        install_tasks._schtasks = lambda *args: (deleted.append(args[2]) if args[0] == "/Delete" else None) or R()
        install_tasks.describe = lambda n: {"level": ""}
        install_tasks.wrong_with = lambda got, cmd, trigger="": []
        install_tasks.remove_run_key = lambda: None
        install_tasks.INSTALL_STAMP = tmp / ".tasks-installed"
        daily = set(install_tasks.GROUPS["daily_repair"])
        with contextlib.redirect_stdout(io.StringIO()):
            install_tasks.remove(only=daily)
        check("8e. remove(only=...) deletes exactly the selected tasks",
              sorted(deleted) == sorted(daily), str(deleted))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            install_tasks.install(only={install_tasks.TRAY_TASK})
        seen = [l for l in buf.getvalue().splitlines() if "already correct" in l]
        check("8f. install(only=...) looks at exactly the selected tasks",
              len(seen) == 1 and install_tasks.TRAY_TASK in seen[0], str(seen))
    finally:
        (install_tasks._schtasks, install_tasks.describe, install_tasks.wrong_with,
         install_tasks.remove_run_key, install_tasks.INSTALL_STAMP) = saved_real

    # post-update: the new payload goes into Spotify
    state = {"patched": True, "live": "old", "ours": "new", "running": True, "unpatched": False}
    did = []
    sp = app.spotify_patcher
    saved = {k: getattr(sp, k) for k in ("is_installed", "is_patched", "inline_payload_sha_of", "our_payload_sha",
                                         "is_spotify_running", "kill_spotify", "patch", "launch_spotify",
                                         "spotify_xpui_path")}
    saved_xw, saved_sleep = app.xpui_write_problem, app.time.sleep
    try:
        sp.is_installed = lambda: True
        sp.is_patched = lambda: state["patched"]
        sp.spotify_xpui_path = lambda: tmp / "xpui.spa"
        sp.inline_payload_sha_of = lambda p: state["live"]
        sp.our_payload_sha = lambda: state["ours"]
        sp.is_spotify_running = lambda: state["running"]
        sp.kill_spotify = lambda *x, **k: did.append("kill") or True
        sp.patch = lambda **kw: (did.append("patch") or (True, "ok"))
        sp.launch_spotify = lambda **kw: did.append("launch") or True
        app.xpui_write_problem = lambda: None
        app.time.sleep = lambda s: None
        a.cfg["user_unpatched"] = False
        a._apply_update_to_spotify()
        check("3e. after an update, a Spotify running the old payload is re-patched and relaunched",
              did == ["kill", "patch", "launch"], str(did))
        did.clear(); state["running"] = False
        a._apply_update_to_spotify()
        check("3f. ...a closed Spotify is re-patched and left closed", did == ["patch"], str(did))
        did.clear(); state["live"] = "new"
        a._apply_update_to_spotify()
        check("3g. ...a Spotify already on the new payload is not touched", did == [], str(did))
        did.clear(); state["live"] = "old"; a.cfg["user_unpatched"] = True
        a._apply_update_to_spotify()
        check("3h. ...and an update never re-patches after the user chose Unpatch", did == [], str(did))
    finally:
        for k, v in saved.items():
            setattr(sp, k, v)
        app.xpui_write_problem, app.time.sleep = saved_xw, saved_sleep

    # -------------------------------------------------------------------- 7
    probe = ("import logging, logging.handlers, sys; sys.path.insert(0, r'%s'); "
             "logging.basicConfig(level=logging.INFO); import selfheal; "
             "print(any(isinstance(h, logging.handlers.RotatingFileHandler) for h in logging.getLogger().handlers))"
             % str(ROOT))
    r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                       env={**os.environ, "APPDATA": str(tmp / "appdata")})
    check("7. self-heal attaches its log file even when logging was configured first (the packaged case)",
          r.stdout.strip().endswith("True"), (r.stdout + r.stderr)[-200:])

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print("tray behaviour: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
