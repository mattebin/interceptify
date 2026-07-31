"""
Install (or repair) Interceptify's Windows autostart, unelevated.

ONE controller, ONE payload, ONE deployment. This replaces a setup that had
four separate autostarts, and it also settles a question the rewrite had left
open: whether the scheduled tasks belong to the *source tree* or to the *packaged
.exe*.

That question is not cosmetic. The updater replaces `Interceptify.exe` and
nothing else. If the .exe self-updates while the scheduled tasks still launch
`main.py` / `selfheal.py` from a source checkout, the old source keeps running at
logon and keeps re-patching Spotify with its own, older payload. That is the
2026-07-16 incident's exact shape - a stale build winning the last write - only
now it survives every update.

So the tasks are always generated for the deployment that is installing them:

    frozen build   ->  "Interceptify.exe" --selfheal --once
    source tree    ->  "pythonw.exe" "<...>\\selfheal.py" --once

and `foreign_deployment_tasks()` reports any task belonging to the *other* model.
main.py, selfheal.py and the updater all consult it, so a split install is
surfaced as a fault instead of silently deciding which payload wins.

Nothing runs elevated. Everything Interceptify touches - xpui.spa, Spotify's
prefs, our own config - is owned by the logged-in user.

    python install_tasks.py            # install / repair
    python install_tasks.py --remove   # take it all back out
    python install_tasks.py --status   # show what is registered

If the tasks already exist at HighestAvailable (created by an older version),
Windows refuses to modify them unelevated. That one cleanup step needs an
elevated shell, and this script prints the exact command to run.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import subprocess
import sys
import tempfile
import time
import winreg
from pathlib import Path

# The INSTALL directory. In a frozen build __file__ points into PyInstaller's
# temp extraction directory, which is gone the moment the process exits.
if getattr(sys, "frozen", False):
    ROOT = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parent
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "Interceptify"

TRAY_TASK = "Interceptify Tray"
HEAL_TASK = "Interceptify SelfHeal"


# ---------------------------------------------------------------------------
# Which deployment is asking
# ---------------------------------------------------------------------------

def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def deployment() -> str:
    return "frozen" if is_frozen() else "source"


def pythonw() -> Path:
    """The windowed interpreter, so no console flashes at logon."""
    p = Path(sys.executable).with_name("pythonw.exe")
    return p if p.exists() else Path(sys.executable)


def _q(p) -> str:
    return f'"{p}"'


def tray_command() -> str:
    if is_frozen():
        return _q(sys.executable)
    return f'{_q(pythonw())} {_q(ROOT / "main.py")}'


def heal_command() -> str:
    if is_frozen():
        return f"{_q(sys.executable)} --selfheal --once"
    return f'{_q(pythonw())} {_q(ROOT / "selfheal.py")} --once'


def tasks() -> list[tuple[str, str, list[str], str]]:
    """(name, command line, schtasks schedule args, expected trigger element)."""
    tray, heal = tray_command(), heal_command()
    return [
        (TRAY_TASK, tray, ["/SC", "ONLOGON"], "LogonTrigger"),
        (HEAL_TASK, heal, ["/SC", "ONLOGON"], "LogonTrigger"),
        (f"{HEAL_TASK} (morning)", heal, ["/SC", "DAILY", "/ST", "08:00"], "CalendarTrigger"),
        (f"{HEAL_TASK} (night)", heal, ["/SC", "DAILY", "/ST", "21:00"], "CalendarTrigger"),
    ]


# ---------------------------------------------------------------------------
# Execution CONDITIONS - the part that decides whether a correct task ever runs
# ---------------------------------------------------------------------------
#
# `schtasks /Create` does not expose these, so they came from Windows' defaults,
# and the defaults are hostile to a laptop:
#
#   DisallowStartIfOnBatteries  true   -> the run is REFUSED on battery
#   StopIfGoingOnBatteries      true   -> a running repair is killed on unplug
#   StartWhenAvailable          false  -> a missed run is never made up
#
# On this machine that was not theoretical. The 08:00 task's last result was
# 0x800710E0 ("the operator or administrator has refused the request") and the
# logon task had never run at all - last run time 1999-11-30. So the self-heal
# that exists to catch a Spotify update breaking the block had been silently
# not running, while `--status` reported all tasks correct because it validated
# the command and the trigger and never looked at the conditions.
#
# A task that cannot run is indistinguishable from one that is not installed,
# except that it looks fine.
WANT_SETTINGS = {
    "DisallowStartIfOnBatteries": "false",
    "StopIfGoingOnBatteries": "false",
    "StartWhenAvailable": "true",       # make up a run missed while asleep/off
}


def _iso_local(hhmm: str) -> str:
    """A StartBoundary for today at hh:mm, local time, no timezone suffix."""
    return f"{time.strftime('%Y-%m-%d')}T{hhmm}:00"


def task_xml(cmd: str, trigger: str, at: str = "") -> str:
    """A full task definition, so every setting is stated rather than inherited.

    Registered with `schtasks /Create /XML`, which is the only way to control the
    power conditions from a plain (non-elevated, non-PowerShell) process.
    """
    exe, args = _split_command(cmd)
    exe = exe.strip('"')
    if trigger == "LogonTrigger":
        trig = f"<LogonTrigger><Enabled>true</Enabled><UserId>{_xml(_current_user())}</UserId></LogonTrigger>"
    else:
        trig = ("<CalendarTrigger>"
                f"<StartBoundary>{_iso_local(at)}</StartBoundary>"
                "<Enabled>true</Enabled>"
                "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>"
                "</CalendarTrigger>")
    # Written out in the schema's REQUIRED order, not generated from the dict.
    # Task XML validates children as a sequence, so an alphabetical or
    # dict-insertion order is rejected outright ("unexpected node") - and the
    # element is MultipleInstancesPolicy, not MultipleInstances.
    settings = (
        "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        f"<DisallowStartIfOnBatteries>{WANT_SETTINGS['DisallowStartIfOnBatteries']}"
        "</DisallowStartIfOnBatteries>"
        f"<StopIfGoingOnBatteries>{WANT_SETTINGS['StopIfGoingOnBatteries']}"
        "</StopIfGoingOnBatteries>"
        "<AllowHardTerminate>true</AllowHardTerminate>"
        f"<StartWhenAvailable>{WANT_SETTINGS['StartWhenAvailable']}</StartWhenAvailable>"
        "<Enabled>true</Enabled>"
        "<ExecutionTimeLimit>PT1H</ExecutionTimeLimit>"
    )
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        f"  <RegistrationInfo><Description>Interceptify</Description></RegistrationInfo>\n"
        f"  <Triggers>{trig}</Triggers>\n"
        '  <Principals><Principal id="Author">'
        f"<UserId>{_xml(_current_user())}</UserId>"
        "<LogonType>InteractiveToken</LogonType>"
        "<RunLevel>LeastPrivilege</RunLevel>"
        "</Principal></Principals>\n"
        f"  <Settings>{settings}</Settings>\n"
        '  <Actions Context="Author">'
        f"<Exec><Command>{_xml(exe)}</Command>"
        + (f"<Arguments>{_xml(args)}</Arguments>" if args else "")
        + "</Exec></Actions>\n"
        "</Task>\n"
    )


def _xml(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def _current_user() -> str:
    """A QUALIFIED account name. A bare username is rejected by the task schema
    with "The parameter is incorrect", which is not a hint about what is wrong."""
    user = os.environ.get("USERNAME") or getpass.getuser()
    domain = os.environ.get("USERDOMAIN") or os.environ.get("COMPUTERNAME") or ""
    return f"{domain}\\{user}" if domain else user


# ---------------------------------------------------------------------------
# Reading what is actually registered
# ---------------------------------------------------------------------------

def _schtasks(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["schtasks", *args], capture_output=True, text=True)


def _tag(xml: str, tag: str) -> str:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.S)
    return m.group(1).strip() if m else ""


def describe(name: str) -> dict | None:
    r = _schtasks("/query", "/tn", name, "/xml", "ONE")
    if r.returncode != 0:
        return None
    x = r.stdout
    triggers = _tag(x, "Triggers")
    return {
        "command": _tag(x, "Command"),
        "arguments": _tag(x, "Arguments"),
        "level": _tag(x, "RunLevel"),
        "userid": _tag(x, "UserId"),
        "triggers": triggers,
        # The trigger ELEMENTS, e.g. ["LogonTrigger"]. StartBoundary inside a
        # LogonTrigger is only when the trigger was armed, not a schedule, so the
        # element name is the thing worth comparing.
        "trigger_kinds": re.findall(r"<(\w+Trigger)>", triggers),
        "start_boundary": _tag(triggers, "StartBoundary"),
        # The execution CONDITIONS. Absent from this dict entirely until now,
        # which is why --status could report every task correct while Windows
        # was refusing to run two of them.
        "settings": {k: (_tag(x, k) or "").lower() for k in WANT_SETTINGS},
    }


def last_result(name: str) -> tuple[str, str]:
    """(last run time, last result) as Task Scheduler recorded them.

    Read because a task can be perfectly defined and still never have run. The
    logon task on this machine reported a last run of 1999-11-30 - Windows'
    never-ran sentinel - while every structural check said it was fine.
    """
    r = _schtasks("/query", "/tn", name, "/fo", "LIST", "/v")
    if r.returncode != 0:
        return "", ""
    run = res = ""
    for line in r.stdout.splitlines():
        low = line.lower()
        if low.startswith("last run time:"):
            run = line.split(":", 1)[1].strip()
        elif low.startswith("last result:"):
            res = line.split(":", 1)[1].strip()
    return run, res


NEVER_RAN = "1999-11-30"


def run_health(name: str) -> list[str]:
    """Complaints about whether the task has actually been RUNNING."""
    run, res = last_result(name)
    out = []
    if run.startswith(NEVER_RAN):
        out.append("has never run")
    try:
        code = int(res)
    except (TypeError, ValueError):
        code = 0
    if code and (code & 0xFFFFFFFF) == 0x800710E0:
        out.append("last run was REFUSED by Windows (0x800710E0) - an execution "
                   "condition blocked it, typically running on battery")
    return out


def _split_command(cmd: str) -> tuple[str, str]:
    """Split a /TR string the way Task Scheduler stores it: exe, then the rest."""
    cmd = cmd.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[: end + 1], cmd[end + 1 :].strip()
    head, _, rest = cmd.partition(" ")
    return head, rest.strip()


def _same_path(a: str, b: str) -> bool:
    return a.strip().strip('"').casefold() == b.strip().strip('"').casefold()


def _same_args(a: str, b: str) -> bool:
    """Argument strings, compared without being fooled by whitespace or case."""
    norm = lambda s: " ".join(s.strip().split()).casefold()
    return norm(a) == norm(b)


def wrong_with(got: dict | None, cmd: str, trigger: str = "") -> list[str]:
    """Everything wrong with a registered task, or [] if it is correct.

    `cmd` used to be accepted and never used, so this returned "no problems" for
    a task pointing at an entirely different script with arbitrary arguments -
    it only ever checked the run level and whether the project path appeared
    somewhere in the string. The exact executable, the exact arguments and the
    trigger kind are all part of what makes a task the one we meant to install.
    """
    if got is None:
        return ["not registered"]
    problems = []
    if "Highest" in (got.get("level") or ""):
        # Absent RunLevel means LeastPrivilege; Windows only writes the element
        # when it is not the default.
        problems.append(f"runs elevated ({got['level']})")

    want_exe, want_args = _split_command(cmd)
    if not _same_path(got.get("command", ""), want_exe):
        problems.append(f"runs {got.get('command') or '(nothing)'}, expected {want_exe}")
    if not _same_args(got.get("arguments", ""), want_args):
        problems.append(f"arguments are {got.get('arguments')!r}, expected {want_args!r}")
    if trigger and trigger not in (got.get("trigger_kinds") or []):
        problems.append(f"trigger is {got.get('trigger_kinds') or '(none)'}, expected {trigger}")
    # A task that is defined correctly and cannot RUN is not a correct task. The
    # power conditions were never inspected, so a self-heal Windows was actively
    # refusing looked identical to one that had been working all along.
    for key, want in WANT_SETTINGS.items():
        got_val = (got.get("settings") or {}).get(key, "")
        if got_val and got_val != want:
            problems.append(f"{key}={got_val}, expected {want}")
    return problems


def _looks_frozen(command: str) -> bool:
    return command.strip().strip('"').casefold().endswith(".exe") and \
        "python" not in command.casefold()


def foreign_deployment_tasks() -> list[tuple[str, str]]:
    """Registered tasks that belong to the OTHER deployment model.

    A frozen install whose autostart still launches a source checkout (or the
    reverse) has two independent patchers with two independent payloads. The
    updater only ever moves one of them forward, so the stale one keeps
    re-injecting its old JavaScript and nothing reports the disagreement.
    """
    mine_frozen = is_frozen()
    out = []
    for name, _, _, _ in tasks():
        got = describe(name)
        if not got or not got.get("command"):
            continue
        if _looks_frozen(got["command"]) != mine_frozen:
            out.append((name, f"{got['command']} {got['arguments']}".strip()))
    return out


def run_key_value() -> str | None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            return winreg.QueryValueEx(k, RUN_VALUE)[0]
    except OSError:
        return None


# ---------------------------------------------------------------------------

def status() -> int:
    print(f"  deployment: {deployment()}  ({sys.executable})")
    for name, cmd, _, trigger in tasks():
        d = describe(name)
        if d is None:
            print(f"  {name}: NOT REGISTERED")
            continue
        lvl = d["level"] or "LeastPrivilege"
        # Definition problems AND execution history. A task can be defined
        # perfectly and still have never run, or be refused every time; only
        # the second kind shows up in what Windows actually did.
        problems = wrong_with(d, cmd, trigger) + run_health(name)
        flag = ("  <-- " + "; ".join(problems)) if problems else ""
        print(f"  {name}: [{lvl}]{flag}\n      {d['command']} {d['arguments']}".rstrip())
        ran, res = last_result(name)
        if ran:
            print(f"      last run {ran}, result {res}")
    v = run_key_value()
    print(f"  HKCU Run: {v}  <-- competing autostart" if v else "  HKCU Run: absent (good)")
    foreign = foreign_deployment_tasks()
    if foreign:
        print("\n  SPLIT DEPLOYMENT — these run the other model and can re-patch with a different payload:")
        for name, target in foreign:
            print(f"    - {name}: {target}")
    return 1 if foreign else 0


def remove_run_key() -> None:
    """Drop the HKCU Run entry.

    It is a second, independent autostart for the same app. Two of them means
    two trays, both patching, and the survivor is whichever won the race.
    """
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_ALL_ACCESS) as k:
            winreg.QueryValueEx(k, RUN_VALUE)
            winreg.DeleteValue(k, RUN_VALUE)
            print("  removed the competing HKCU Run entry")
    except FileNotFoundError:
        pass
    except OSError as e:
        print(f"  could not read the Run key: {e}")


def install() -> int:
    # The competing Run key is dropped AFTER at least one task is registered.
    # Dropping it first meant a failed registration left the user with no
    # autostart at all: we removed the mechanism that was working before we knew
    # whether the replacement would.
    blocked: list[tuple[str, str]] = []
    registered_any = False
    for name, cmd, sched, trigger in tasks():
        existing = describe(name)
        # Leave a correct task alone. A task authored by an elevated process
        # keeps a security descriptor that only Administrators can modify, so
        # rewriting one that is ALREADY right fails for a reason that has
        # nothing to do with whether it is right.
        if not wrong_with(existing, cmd, trigger):
            print(f"  already correct {name}  [{existing['level'] or 'LeastPrivilege'}]")
            registered_any = True
            continue
        # Registered from a full XML definition rather than /TR + /SC flags.
        # schtasks cannot express the power conditions on the command line, so
        # with flags they came from Windows' defaults - which refuse to start on
        # battery and never make up a missed run.
        at = ""
        for i, a in enumerate(sched):
            if a == "/ST":
                at = sched[i + 1]
        xml = task_xml(cmd, trigger, at)
        tmp = Path(tempfile.gettempdir()) / f"interceptify-task-{abs(hash(name))}.xml"
        try:
            # UTF-16 with a BOM: schtasks /XML rejects anything else outright.
            tmp.write_text(xml, encoding="utf-16")
            r = _schtasks("/Create", "/TN", name, "/XML", str(tmp), "/F")
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass
        if r.returncode != 0:
            why = (r.stdout or r.stderr).strip().replace("ERROR: ", "")[:80]
            print(f"  FAILED   {name}  ({why})")
            blocked.append((name, why))
            continue

        # Read the task back rather than trusting the exit code. schtasks
        # returning 0 means it accepted the command line, not that the task in
        # the store is the one intended - and the whole point of this script is
        # that a task was quietly running elevated against the wrong target.
        # Verifying the write with the same tool that made it is weak, but the
        # store is the authority here and there is nothing closer to the truth.
        got = describe(name)
        problems = wrong_with(got, cmd, trigger)
        if problems:
            print(f"  FAILED   {name}  ({'; '.join(problems)})")
            blocked.append((name, "; ".join(problems)))
        else:
            print(f"  installed {name}  [verified: {got['level'] or 'LeastPrivilege'}]")
            registered_any = True

    if registered_any:
        remove_run_key()
    elif run_key_value():
        print("  kept the HKCU Run entry: no scheduled task was registered, so removing it\n"
              "  would leave you with no autostart at all.")

    if blocked:
        print("\n  Could not put these right:")
        for name, why in blocked:
            print(f"    - {name}: {why}")
        # Only an access problem is fixable by elevating. Saying "run this
        # elevated" for every failure sends you chasing a permission wall that
        # may not be the actual problem.
        denied = [n for n, w in blocked if "denied" in w.lower()]
        if denied:
            print("\n  Access denied means the task was authored by an elevated process, so\n"
                  "  only an administrator can replace it. Run this ONCE in an elevated\n"
                  "  terminal, then re-run this script:")
            print("    " + "; ".join(f'schtasks /Delete /TN "{n}" /F' for n in denied))
        return 1
    print(f"\n  All autostart entries run as you, from the {deployment()} deployment.")
    return 0


def remove() -> int:
    remove_run_key()
    rc = 0
    for name, _, _, _ in tasks():
        r = _schtasks("/Delete", "/TN", name, "/F")
        if r.returncode == 0:
            print(f"  removed {name}")
        elif describe(name) is not None:
            print(f"  FAILED to remove {name}: {(r.stdout or r.stderr).strip()[:80]}")
            rc = 1
    return rc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--remove", action="store_true", help="uninstall every autostart entry")
    ap.add_argument("--status", action="store_true", help="show what is currently registered")
    a = ap.parse_args(argv)
    if a.status:
        return status()
    if a.remove:
        return remove()
    return install()


if __name__ == "__main__":
    sys.exit(main())
