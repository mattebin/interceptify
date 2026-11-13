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
  6. Task Scheduler killed the tray after one hour. The tray is no longer a
     scheduled task at all: it starts from the Windows startup entry.
  7. The packaged self-heal never wrote its log.
 13. Every scheduled repair restarted Spotify twice to prove the block live,
     on every machine. That proof is now opt-in; a normal repair closes
     Spotify once, and only when its file has to change.

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

    # ------------------------------------------------------------------- 13
    # The live check (Spotify opened with a debug port, watched, opened again
    # without one) runs only where it is switched on. Everyone else gets the
    # patch put back: Spotify closes only when its file has to change, opens
    # again only if it was open, and never on the verification port.
    did: list = []
    full: list = []
    st8 = {"running": True, "problem": None,
           "fp": {"spotify_version": "t", "patched": False,
                  "payload_matches": False, "config_matches": False}}
    saved8 = {n: getattr(spotify_patcher, n) for n in
              ("patch", "is_installed", "is_spotify_running", "kill_spotify",
               "launch_spotify", "verify_patched_archive", "spotify_xpui_path")}
    saved_foreign = install_tasks.foreign_deployment_tasks

    def full_cycle(*a, **k):
        full.append(1)
        raise Reached()

    spotify_patcher.patch = lambda **kw: (did.append(("patch", kw["debug_capture"])) or (True, "patched"))
    spotify_patcher.is_installed = lambda: True
    spotify_patcher.is_spotify_running = lambda: st8["running"]
    spotify_patcher.kill_spotify = lambda *a, **k: (did.append(("kill",)) or True)
    spotify_patcher.launch_spotify = lambda port=0: (did.append(("launch", port)) or True)
    spotify_patcher.verify_patched_archive = lambda p: st8["problem"]
    spotify_patcher.spotify_xpui_path = lambda: tmp / "xpui.spa"
    install_tasks.foreign_deployment_tasks = lambda: []
    quiet = ("backfill_delivery_failures", "save_state", "note_block_change",
             "delivery_block", "report_update")
    saved_heal = {n: getattr(selfheal, n) for n in
                  quiet + ("fingerprint", "harvest", "repair_and_verify")}
    for name in quiet:
        setattr(selfheal, name, lambda *a, **k: None)
    selfheal.fingerprint = lambda: dict(st8["fp"])
    selfheal.harvest = lambda *a, **k: 0
    selfheal.repair_and_verify = full_cycle

    def run8(settings: dict, force: bool = False):
        did.clear(); full.clear()
        cfg.write_text(json.dumps(settings), encoding="utf-8")
        try:
            return selfheal._run(force=force)
        except Reached:
            return "full cycle"

    try:
        rc = run8({})
        check("13a. Spotify updated while open: one close, patch, one normal reopen, no live check",
              rc == 0 and did == [("kill",), ("patch", False), ("launch", 0)] and not full, f"rc={rc} {did}")
        st8["running"] = False
        rc = run8({})
        check("13b. Spotify updated while closed: patched, and Spotify is not opened",
              rc == 0 and did == [("patch", False)] and not full, f"rc={rc} {did}")
        st8["running"] = True
        st8["fp"] = {"spotify_version": "t", "patched": True, "payload_matches": True, "config_matches": True}
        rc = run8({})
        check("13c. patch in place but never proven live: Spotify is not touched",
              rc == 0 and not did and not full, f"rc={rc} {did}")
        st8["fp"] = {"spotify_version": "t", "patched": False, "payload_matches": False, "config_matches": False}
        st8["problem"] = "payload missing from index.html"
        rc = run8({})
        check("13d. a patch that does not check out is reported, and Spotify still comes back",
              rc == 2 and did[-1] == ("launch", 0), f"rc={rc} {did}")
        st8["problem"] = None
        rc = run8({"debug_capture": True})
        check("13e. the reopen keeps the user's debug-capture setting",
              rc == 0 and did == [("kill",), ("patch", True), ("launch", 9222)], f"rc={rc} {did}")
        rc = run8({"live_verify": True})
        check("13f. with live_verify on, the full live check runs", rc == "full cycle" and not did, f"rc={rc} {did}")
        rc = run8({}, force=True)
        check("13g. --force runs the full live check whatever the setting", rc == "full cycle" and not did, f"rc={rc} {did}")
    finally:
        for n, f in saved8.items():
            setattr(spotify_patcher, n, f)
        install_tasks.foreign_deployment_tasks = saved_foreign
        for n, f in saved_heal.items():
            setattr(selfheal, n, f)

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
    check("4d. every branch (two failures, one success) ends by starting the tray",
          lines.count(relaunch_old) == 3, f"count={lines.count(relaunch_old)}")
    check("4e. the relaunch carries no special flag: any updater, old or new, starts the tray the same way",
          "--updated" not in text)
    check("4f. every outcome leaves a line in update.log",
          text.count(str(inst / "update.log")) == 3, f"count={text.count(str(inst / 'update.log'))}")

    # -------------------------------------------------------------------- 6
    names = [n for n, _, _, _ in install_tasks.tasks()]
    check("6a. the tray is not a scheduled task: only the three self-heal checks are",
          len(names) == 3 and install_tasks.TRAY_TASK not in names
          and all(n.startswith(install_tasks.HEAL_TASK) for n in names), str(names))
    heal_xml = install_tasks.task_xml(install_tasks.heal_command(), "LogonTrigger")
    check("6b. self-heal tasks keep a one-hour limit as a backstop for a hung run",
          "<ExecutionTimeLimit>PT1H</ExecutionTimeLimit>" in heal_xml)
    check("6c. ...and run at normal priority, in schema order after the time limit",
          "</ExecutionTimeLimit><Priority>4</Priority>" in heal_xml)
    exe, args = install_tasks._split_command(install_tasks.heal_command())
    good = {"command": exe.strip('"'), "arguments": args, "level": "", "trigger_kinds": ["LogonTrigger"],
            "priority": "4", "limit": "PT1H"}
    low = install_tasks.wrong_with({**good, "priority": ""}, install_tasks.heal_command(), "LogonTrigger")
    check("6d. a task registered without a priority (Windows default, below normal) is reported as wrong",
          any("below-normal priority" in p for p in low), str(low))
    fine = [p for p in install_tasks.wrong_with(good, install_tasks.heal_command(), "LogonTrigger") if "priority" in p]
    check("6e. ...and one with the new settings is not", fine == [], str(fine))

    # The startup entry, against a fake registry and a fake task list: the real
    # ones belong to whoever runs this test.
    import contextlib
    import io
    reg: dict = {}
    legacy: dict = {}
    deleted: list = []

    class R0:
        returncode = 0
        stdout = stderr = ""

    saved_reg = (install_tasks.run_key_value, install_tasks.set_run_key, install_tasks.remove_run_key,
                 install_tasks.describe, install_tasks._schtasks, install_tasks.INSTALL_STAMP,
                 install_tasks.wrong_with)

    def fake_set():
        reg["v"] = install_tasks.tray_command()
        return True

    def fake_schtasks(*a):
        if a[0] == "/Delete":
            deleted.append(a[2])
            legacy.pop(a[2], None)
        return R0()

    try:
        install_tasks.run_key_value = lambda: reg.get("v")
        install_tasks.set_run_key = fake_set
        install_tasks.remove_run_key = lambda: (reg.pop("v", None), True)[1]
        install_tasks.describe = lambda n: legacy.get(n)
        install_tasks._schtasks = fake_schtasks
        install_tasks.INSTALL_STAMP = tmp / ".tasks-installed"
        te, ta = install_tasks._split_command(install_tasks.tray_command())
        legacy[install_tasks.TRAY_TASK] = {"command": te.strip('"'), "arguments": ta, "level": ""}
        with contextlib.redirect_stdout(io.StringIO()):
            install_tasks.install(only={install_tasks.TRAY_ENTRY})
        check("6f. switching the tray on writes the startup entry for this install",
              install_tasks.tray_autostart_on() and install_tasks.group_enabled("tray"), str(reg))
        check("6g. ...and removes the scheduled task an older version left behind, and nothing else",
              deleted == [install_tasks.TRAY_TASK], str(deleted))
        reg["v"] = r'"C:\somewhere else\Interceptify.exe"'
        check("6h. a startup entry that points at a different install does not count as on",
              not install_tasks.tray_autostart_on())
        deleted.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            install_tasks.remove(only={install_tasks.TRAY_ENTRY})
        check("6i. switching the tray off clears the startup entry and touches no self-heal task",
              "v" not in reg and deleted == [], f"{reg} {deleted}")

        # migration at tray start
        reg.clear(); deleted.clear()
        legacy[install_tasks.TRAY_TASK] = {"command": te.strip('"'), "arguments": ta, "level": ""}
        install_tasks.wrong_with = lambda got, cmd, trigger="": []
        fixed = install_tasks.refresh_outdated()
        check("6j. an old tray task for THIS install is replaced by the startup entry",
              fixed == [install_tasks.TRAY_ENTRY] and install_tasks.tray_autostart_on()
              and deleted == [install_tasks.TRAY_TASK], f"fixed={fixed} reg={reg} deleted={deleted}")
        reg.clear(); deleted.clear()
        legacy[install_tasks.TRAY_TASK] = {"command": r"C:\other\Interceptify.exe", "arguments": "", "level": ""}
        fixed = install_tasks.refresh_outdated()
        check("6k. ...another install's tray task is left alone",
              fixed == [] and not reg and deleted == [], f"fixed={fixed} reg={reg} deleted={deleted}")
        legacy.clear()
        fixed = install_tasks.refresh_outdated()
        check("6l. ...and with autostart off nothing is switched on", fixed == [] and not reg, f"{fixed} {reg}")
    finally:
        (install_tasks.run_key_value, install_tasks.set_run_key, install_tasks.remove_run_key,
         install_tasks.describe, install_tasks._schtasks, install_tasks.INSTALL_STAMP,
         install_tasks.wrong_with) = saved_reg

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

    # autostart: three separate switches, each touching only its own entry
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
        check("8b. switching the tray off removes only the tray's startup entry",
              did_tasks[1] == ("remove", [install_tasks.TRAY_ENTRY]), str(did_tasks[1:2]))
        every = sorted(n for g in install_tasks.GROUPS.values() for n in g)
        check("8c. the three options cover the startup entry and every scheduled task, with no overlap",
              every == sorted([install_tasks.TRAY_ENTRY] + [n for n, _, _, _ in install_tasks.tasks()]), str(every))
        menu_src = src[src.index("def build_menu"):src.index("def run(self)")]
        check("8d. the tray menu has an Autostart submenu built from those options",
              'Item("Autostart", Menu(' in menu_src and "_AUTOSTART_LABELS" in menu_src)
    finally:
        install_tasks.install, install_tasks.remove, install_tasks.group_enabled = saved_it

    # ...and the real install()/remove() honour the selection (stubbed above).
    deleted2 = []

    class R:
        returncode = 0
        stdout = stderr = ""

    saved_real = (install_tasks._schtasks, install_tasks.describe, install_tasks.wrong_with,
                  install_tasks.remove_run_key, install_tasks.set_run_key, install_tasks.INSTALL_STAMP)
    touched_run = []
    try:
        install_tasks._schtasks = lambda *args: (deleted2.append(args[2]) if args[0] == "/Delete" else None) or R()
        install_tasks.describe = lambda n: None if n == install_tasks.TRAY_TASK else {"level": ""}
        install_tasks.wrong_with = lambda got, cmd, trigger="": []
        install_tasks.remove_run_key = lambda: (touched_run.append("remove"), True)[1]
        install_tasks.set_run_key = lambda: (touched_run.append("set"), True)[1]
        install_tasks.INSTALL_STAMP = tmp / ".tasks-installed"
        daily = set(install_tasks.GROUPS["daily_repair"])
        with contextlib.redirect_stdout(io.StringIO()):
            install_tasks.remove(only=daily)
        check("8e. remove(only=...) deletes exactly the selected tasks and leaves the startup entry alone",
              sorted(deleted2) == sorted(daily) and touched_run == [], f"{deleted2} {touched_run}")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            install_tasks.install(only={install_tasks.HEAL_TASK})
        seen = [l for l in buf.getvalue().splitlines() if "already correct" in l]
        check("8f. install(only=...) looks at exactly the selected task and leaves the startup entry alone",
              len(seen) == 1 and install_tasks.HEAL_TASK in seen[0] and touched_run == [], f"{seen} {touched_run}")
    finally:
        (install_tasks._schtasks, install_tasks.describe, install_tasks.wrong_with,
         install_tasks.remove_run_key, install_tasks.set_run_key, install_tasks.INSTALL_STAMP) = saved_real

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

    # ------------------------------------------------- 9: diagnostics are not ads
    import re as _re
    hook_dead = {"t": 2000, "kind": "l1-hook-dead", "id": "l1", "gate": {"closed": True}}
    spec_mute = {"t": 2001, "kind": "speculative-mute", "gate": {"closed": True}}
    delivered = {"t": 2002, "kind": "delivered", "id": "ad-1", "gate": {"closed": True}}
    saved_h = (selfheal.read_incidents_from_disk, selfheal._vault_append)
    written: list[str] = []
    try:
        selfheal._vault_append = lambda lines: written.extend(lines)
        selfheal.read_incidents_from_disk = lambda: [hook_dead, spec_mute]
        st: dict = {}
        n = selfheal.harvest("1.3.9", st)
        check("9a. a dead hook and a speculative mute are not counted as ads reaching the user",
              n == 0 and st.get("incident_watermark") == 2001, f"n={n} state={st}")
        check("9b. ...they are still logged, labelled as diagnostics, and never parsed back as a delivery",
              len(written) == 2 and all("diagnostic" in w for w in written)
              and not any(selfheal._FAILURE_LINE.match(w.strip()) for w in written), str(written)[:200])
        selfheal.read_incidents_from_disk = lambda: [hook_dead, delivered]
        n = selfheal.harvest("1.3.9", {})
        check("9c. a real delivery next to a diagnostic still counts, once", n == 1, f"n={n}")
    finally:
        selfheal.read_incidents_from_disk, selfheal._vault_append = saved_h

    # ------------------------------------------------- 10: gate-key repair
    yes = ["ad_enabled", "ads_enabled", "enable-ads", "adEnabled", "enableAds", "AD_ENABLED"]
    no = ["on_demand_capped", "ready", "is_loaded", "headphones", "added_at", "leaderboard_shown", "broadcast"]
    check("10a. only keys with ad/ads as a word are gate candidates",
          all(selfheal._names_ads(k) for k in yes) and not any(selfheal._names_ads(k) for k in no),
          f"wrong yes={[k for k in yes if not selfheal._names_ads(k)]} wrong no={[k for k in no if selfheal._names_ads(k)]}")
    ext = tmp / "extensions"
    ext.mkdir(exist_ok=True)
    shipped_pats = ["^ad[_-]?enabled$", "^ads?[_-]?enabled$"]
    (ext / "adblock.config.json").write_text(json.dumps(
        {"adGateKeyPatterns": shipped_pats, "adGateFallbackKeys": ["ad_enabled"]}), encoding="utf-8")
    saved_cfg = selfheal.OUR_CONFIG
    try:
        selfheal.OUR_CONFIG = ext / "adblock.config.local.json"
        selfheal.persist_gate_pattern("adverts_on")
        local = json.loads(selfheal.OUR_CONFIG.read_text(encoding="utf-8"))
        check("10b. adopting a new gate key keeps every shipped pattern behind it",
              local["adGateKeyPatterns"][0] == "^adverts_on$" and local["adGateKeyPatterns"][1:] == shipped_pats,
              str(local["adGateKeyPatterns"]))
        check("10c. ...and the shipped fallback key stays reachable",
              local["adGateFallbackKeys"] == ["adverts_on", "ad_enabled"], str(local["adGateFallbackKeys"]))
    finally:
        selfheal.OUR_CONFIG = saved_cfg

    # ------------------------------------------------- 11: only the user ends the tray
    import patch_lock
    check("11a. nothing in the app restarts, watches or flags the tray: it is simply never ended",
          "ensure_tray_running" not in (ROOT / "selfheal.py").read_text(encoding="utf-8")
          and "user_exited" not in src and "RestartOnFailure" not in heal_xml)
    started = []
    saved_m = (patch_lock.hold_tray_mutex, app.InterceptifyApp)

    class NoApp:
        def __init__(self, *a, **k):
            started.append(1)

        def run(self):
            pass

    try:
        app.InterceptifyApp = NoApp
        patch_lock.hold_tray_mutex = lambda: False
        rc = app.main([])
        check("11b. a second start while a tray is running exits quietly instead of adding an icon",
              rc == 0 and started == [], f"rc={rc} started={started}")
        patch_lock.hold_tray_mutex = lambda: True
        app.main([])
        check("11c. ...and the first start runs", started == [1], str(started))
    finally:
        patch_lock.hold_tray_mutex, app.InterceptifyApp = saved_m

    # ------------------------------------------------- 12: works with the updater already installed
    saved_frozen = app.is_frozen_build
    try:
        app.is_frozen_build = lambda: True
        c0 = json.loads(app.CONFIG_PATH.read_text(encoding="utf-8"))
        c0["last_version"] = "2.0.6-older"
        app.CONFIG_PATH.write_text(json.dumps(c0), encoding="utf-8")
        first = app.InterceptifyApp()            # as started by ANY updater: no flag, no argument
        check("12a. a build started after an update knows it was just updated, with no flag from the updater",
              first._post_update is True)
        second = app.InterceptifyApp()
        check("12b. ...and an ordinary start of the same version does not re-apply anything",
              second._post_update is False)
    finally:
        app.is_frozen_build = saved_frozen

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print("tray behaviour: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
