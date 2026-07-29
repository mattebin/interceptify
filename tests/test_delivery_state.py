"""
A structural self-test passing must never clear a RECORDED ad delivery.

This is the defect that mattered most in the third audit. The tripwire logged
"an ad was delivered while the gate was closed", the program marked verification
failed, and then the very next structural self-test wrote `verified_pass: True`
over it. The incident watermark had already advanced, so no later run would look
at those incidents again - and the user was shown a green status for a block that
had, by the program's own record, failed at the one thing it promises.

The reason it is not a scoring bug but a category error: the structural test
CANNOT schedule an ad. Ads are server-scheduled. So it can prove that Spotify's
ad switch moves under our writes, that the core echoes it, that the block
re-closes it unaided and that every layer is attached - and none of that is
evidence about whether an ad got through. A recorded delivery is direct evidence;
a structural pass is indirect at best. Direct evidence does not get overwritten
by indirect evidence.

What is asserted here:
  1. a delivery is recorded durably, not as a transient flag
  2. a structural PASS does NOT clear it
  3. it does NOT clear while the block is unchanged, however long you wait
  4. it does NOT clear the instant the block changes either
  5. it DOES clear once the block changed AND enough real time has passed
  6. the user can always acknowledge it deliberately
  7. with nothing pending, a structural PASS is still a PASS

Run:  python tests/test_delivery_state.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"   :: {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def main() -> int:
    # selfheal derives its paths from APPDATA and its own directory; point
    # APPDATA at a temp tree so importing it cannot touch a real Spotify.
    os.environ["APPDATA"] = tempfile.mkdtemp(prefix="interceptify-delivery-")
    import selfheal

    fp_before = {"live_payload_sha": "aaa", "spotify_version": "1.2.94", "xpui_sha": "x"}
    fp_after_repair = {"live_payload_sha": "bbb", "spotify_version": "1.2.94", "xpui_sha": "x"}

    state: dict = {}
    selfheal.note_delivery_failure(state, 4, fp_before)

    d = selfheal.delivery_block(state)
    check("1. a delivery is recorded in the state file", bool(d) and d["count"] == 4,
          f"got {d!r}")
    check("1b. ...with what the block looked like when it failed",
          d.get("payload_sha") == "aaa" and "config_sha" in d)

    # 2 + 3. The headline: a structural PASS does not clear it.
    verdict, code = selfheal.resolve_verdict("PASS", state, fp_before)
    check("2. a structural PASS is reported as UNRESOLVED, not PASS", verdict == "UNRESOLVED",
          f"verdict={verdict}")
    check("2b. ...and exits non-zero so a scheduled run records the day it mattered", code == 3,
          f"exit={code}")

    # Age it a week. Time alone must not be enough: nothing about the block
    # changed, so "it works now" has nothing behind it.
    state["unresolved_delivery"]["last_t"] = int(time.time()) - 7 * 24 * 3600
    check("3. a week of waiting does NOT clear it while the block is unchanged",
          selfheal.clearable_reason(state, fp_before) is None,
          str(selfheal.clearable_reason(state, fp_before)))
    check("3b. ...and the verdict is still UNRESOLVED",
          selfheal.resolve_verdict("PASS", state, fp_before)[0] == "UNRESOLVED")

    # 4. A repair that changed the payload starts the clock; it does not stop it.
    state["unresolved_delivery"]["last_t"] = int(time.time())
    check("4. changing the block does NOT clear it immediately",
          selfheal.clearable_reason(state, fp_after_repair) is None)
    check("4b. ...verdict still UNRESOLVED right after a repair",
          selfheal.resolve_verdict("PASS", state, fp_after_repair)[0] == "UNRESOLVED")

    # 5. Changed AND enough real use since.
    state["unresolved_delivery"]["last_t"] = int(time.time()) - (selfheal.DELIVERY_CLEAR_AFTER_S + 60)
    why = selfheal.clearable_reason(state, fp_after_repair)
    check("5. clears once the block changed AND the time has passed", why is not None, str(why))
    check("5b. ...and the verdict may be PASS again",
          selfheal.resolve_verdict("PASS", state, fp_after_repair)[0] == "PASS")

    # 6. Deliberate acknowledgement always works.
    state["unresolved_delivery"]["last_t"] = int(time.time())
    state2 = dict(state)
    state2.pop("unresolved_delivery")
    check("6. acknowledging removes the block",
          selfheal.resolve_verdict("PASS", state2, fp_before)[0] == "PASS")

    # 7. Nothing pending: the structural verdict passes straight through, so
    #    this rule cannot make every run fail forever.
    checks = {"PASS": ("PASS", 0), "UNKNOWN": ("UNKNOWN", 4), "FAIL": ("FAIL", 2)}
    ok = all(selfheal.resolve_verdict(v, {}, fp_before) == expect for v, expect in checks.items())
    check("7. with nothing pending, the structural verdict passes through unchanged", ok,
          str({v: selfheal.resolve_verdict(v, {}, fp_before) for v in checks}))

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print("delivery-state rules: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
