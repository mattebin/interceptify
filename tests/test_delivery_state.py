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

    # Both hashes, deliberately. These fixtures used to carry only a payload sha,
    # which meant every case below was satisfied by the "unknown is not changed"
    # guard rather than by the rule it was written to test - they passed without
    # exercising anything.
    fp_before = {"live_payload_sha": "aaa", "live_config_sha": "cfg-a",
                 "spotify_version": "1.2.94", "xpui_sha": "x"}
    fp_after_repair = {"live_payload_sha": "bbb", "live_config_sha": "cfg-b",
                       "spotify_version": "1.2.94", "xpui_sha": "x"}

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
    #
    # This case used to pass by pushing `last_t` - the DELIVERY time - past the
    # window, which is exactly the bug: the 24 hours could elapse while the
    # broken code was still installed, so a fix landing on day ten cleared the
    # incident on arrival. The window now runs from when the NEW code went in
    # and requires playback observed on it, so satisfying it takes both.
    selfheal.note_block_change(state, fp_after_repair)
    d = state["unresolved_delivery"]
    d["changed_at"] = int(time.time()) - (selfheal.DELIVERY_CLEAR_AFTER_S + 60)
    d["observed_s"] = selfheal.DELIVERY_MIN_OBSERVED_S + 60
    why = selfheal.clearable_reason(state, fp_after_repair)
    check("5. clears once the NEW block has been running long enough, with real use",
          why is not None, str(why))
    check("5b. ...and the verdict may be PASS again",
          selfheal.resolve_verdict("PASS", state, fp_after_repair)[0] == "PASS")

    # 6. Deliberate acknowledgement always works.
    #
    # Built fresh rather than reused: case 5b's PASS now REMOVES the record it
    # retired, so this used to read a key that no longer existed. That is the
    # point of the change - deciding a record is clearable and leaving it in
    # place was how run() saved PASS while --verify still read FAIL.
    state6: dict = {}
    selfheal.note_delivery_failure(state6, 2, fp_before)
    check("6.pre a fresh record is pending", selfheal.delivery_block(state6) is not None)
    state6.pop("unresolved_delivery")             # what --acknowledge-delivery does
    check("6. acknowledging removes the block",
          selfheal.resolve_verdict("PASS", state6, fp_before)[0] == "PASS")

    # 7. Nothing pending: the structural verdict passes straight through, so
    #    this rule cannot make every run fail forever.
    checks = {"PASS": ("PASS", 0), "UNKNOWN": ("UNKNOWN", 4), "FAIL": ("FAIL", 2)}
    ok = all(selfheal.resolve_verdict(v, {}, fp_before) == expect for v, expect in checks.items())
    check("7. with nothing pending, the structural verdict passes through unchanged", ok,
          str({v: selfheal.resolve_verdict(v, {}, fp_before) for v in checks}))

    # ---------------------------------------------------------------------
    # 8. THE CLOCK RUNS FROM THE NEW CODE, NOT FROM THE AD.
    #
    # "24h with no further delivery" was measured from the delivery timestamp,
    # so the window could elapse entirely while the BROKEN code was still
    # installed. A fix patched in on day ten cleared the incident the instant it
    # landed, with zero seconds of listening on the thing that was supposed to
    # have fixed it. That is the strongest false-green left in the design: it
    # retires the only durable evidence the block ever failed.
    # ---------------------------------------------------------------------
    old = int(time.time()) - (selfheal.DELIVERY_CLEAR_AFTER_S + 10 * 24 * 3600)
    fp_old = dict(fp_before, live_payload_sha="old" * 21, live_config_sha="oldc" * 16)
    state8 = {"unresolved_delivery": {
        "count": 3, "first_t": old, "last_t": old,
        "payload_sha": fp_old["live_payload_sha"], "config_sha": fp_old["live_config_sha"]}}
    fp_new = dict(fp_before, live_payload_sha="new" * 21, live_config_sha="newc" * 16)

    check("8. an old incident does not clear merely because the code just changed",
          selfheal.clearable_reason(state8, fp_new) is None,
          str(selfheal.clearable_reason(state8, fp_new)))

    selfheal.note_block_change(state8, fp_new)
    d = state8["unresolved_delivery"]
    check("8b. the change is stamped with WHEN it happened", bool(d.get("changed_at")))
    check("8c. ...and the window is still open right after the patch",
          selfheal.clearable_reason(state8, fp_new) is None)

    # 24h of wall-clock, but the user never played anything.
    d["changed_at"] = int(time.time()) - (selfheal.DELIVERY_CLEAR_AFTER_S + 60)
    check("8d. wall-clock alone does not clear it - a sleeping machine plays no ads",
          selfheal.clearable_reason(state8, fp_new) is None,
          f"observed_s={d.get('observed_s')}")

    d["observed_s"] = selfheal.DELIVERY_MIN_OBSERVED_S + 60
    check("8e. 24h on the new code PLUS real playback clears it",
          selfheal.clearable_reason(state8, fp_new) is not None,
          str(selfheal.clearable_reason(state8, fp_new)))

    # 8f ISOLATES the clock. Everything the old rule looked at is satisfied - the
    # delivery is ten days old and there is plenty of playback - but the code
    # that is supposed to have fixed it went in a moment ago. Under the old rule
    # this cleared instantly. 8d cannot catch that regression on its own: the
    # playback gate stops it for a different reason, so both guards must be
    # tested where only one of them applies.
    d["changed_at"] = int(time.time())
    check("8f: a fix that landed one second ago does not inherit ten days of waiting",
          selfheal.clearable_reason(state8, fp_new) is None,
          f"last_t is {(int(time.time()) - d['last_t']) // 86400}d old, "
          f"observed={d['observed_s']}s, but the patch is new")

    # 9. UNKNOWN is not CHANGED. An unpatched archive has no live hashes, and
    #    those compared unequal to the recorded ones - so "the block is not
    #    running at all" was the state most likely to retire a failure.
    fp_unpatched = dict(fp_before, patched=False, live_payload_sha=None, live_config_sha=None)
    check("9. a missing live hash never counts as 'the block changed'",
          selfheal.clearable_reason(state8, fp_unpatched) is None,
          str(selfheal.clearable_reason(state8, fp_unpatched)))

    # 9b ISOLATES it, at the place where it actually decides something. In
    # clearable_reason() the null guard is shadowed by the changed_to check; the
    # damage a null hash can do is upstream, where it would STAMP an epoch that
    # nothing ever ran under - "the block changed" recorded for an archive that
    # is not patched at all.
    state9: dict = {}
    selfheal.note_delivery_failure(state9, 1, fp_before)
    selfheal.note_block_change(state9, fp_unpatched)
    check("9b: an unpatched archive does not get stamped as 'the block changed'",
          not state9["unresolved_delivery"].get("changed_at"),
          str(state9["unresolved_delivery"].get("changed_at")))
    selfheal.note_block_change(state9, fp_after_repair)
    check("9c: ...but a real patch does",
          bool(state9["unresolved_delivery"].get("changed_at")))

    # 10. Changed AGAIN after the stamp: the clock restarts, it does not
    #     inherit the previous patch's elapsed time.
    fp_newer = dict(fp_before, live_payload_sha="third" * 12 + "abcd", live_config_sha="thirdc" * 10 + "abcd")
    check("10. a further change restarts the window rather than inheriting it",
          selfheal.clearable_reason(state8, fp_newer) is None,
          str(selfheal.clearable_reason(state8, fp_newer)))

    # 11. Deciding a record is clearable must ALSO clear it. Leaving it in place
    #     let run() save PASS while the record survived, and the next --verify
    #     read that surviving record as FAIL - two components disagreeing about
    #     the same machine.
    # Own state: 8f deliberately left state8 un-clearable, and a test that
    # depends on the residue of the one before it is testing the order it runs
    # in as much as the rule.
    state11 = {"unresolved_delivery": {
        "count": 1, "first_t": old, "last_t": old,
        "payload_sha": fp_old["live_payload_sha"], "config_sha": fp_old["live_config_sha"],
        "changed_at": int(time.time()) - (selfheal.DELIVERY_CLEAR_AFTER_S + 60),
        "changed_to_payload": fp_new["live_payload_sha"],
        "changed_to_config": fp_new["live_config_sha"],
        "observed_s": selfheal.DELIVERY_MIN_OBSERVED_S + 60}}
    check("11.pre the record IS clearable", selfheal.clearable_reason(state11, fp_new) is not None)
    verdict, _ = selfheal.resolve_verdict("PASS", state11, fp_new)
    check("11. resolve_verdict PASS removes the record it just retired",
          verdict == "PASS" and selfheal.delivery_block(state11) is None,
          f"verdict={verdict} still_pending={selfheal.delivery_block(state11)}")

    # 12. Only playback the USER was doing counts. A window where the test had
    #     to start the music proves the plumbing, not the outcome.
    state12 = {"unresolved_delivery": {"count": 1, "first_t": old, "last_t": old,
                                       "payload_sha": "a", "config_sha": "b",
                                       "changed_at": int(time.time()), "observed_s": 0,
                                       "changed_to_payload": "c", "changed_to_config": "d"}}
    selfheal.note_observed_playback(state12, {"final": {"streamedDelta": 900, "startedByTest": True}})
    check("12. playback the self-test started does not count as observation",
          state12["unresolved_delivery"]["observed_s"] == 0,
          str(state12["unresolved_delivery"]["observed_s"]))
    selfheal.note_observed_playback(state12, {"final": {"streamedDelta": 900, "startedByTest": False}})
    check("12b. ...real listening does",
          state12["unresolved_delivery"]["observed_s"] == 900,
          str(state12["unresolved_delivery"]["observed_s"]))

    # ---------------------------------------------------------------------
    # 13. AN UNRESOLVED DELIVERY MUST NOT BLOCK INSTALLING THE FIX.
    #
    # The stop sat in front of the repair unconditionally, so the machine that
    # had heard an ad was the one machine that could never receive newer code.
    # The scheduled path would exit 3 forever while Spotify kept running the
    # payload that failed.
    # ---------------------------------------------------------------------
    pending13 = {"count": 1, "first_t": old, "last_t": old}
    live = {"patched": True, "payload_matches": True, "config_matches": True}
    stale_payload = {"patched": True, "payload_matches": False, "config_matches": True}
    stale_config = {"patched": True, "payload_matches": True, "config_matches": False}
    unpatched = {"patched": False, "payload_matches": False, "config_matches": False}

    check("13. with nothing new to install, an unresolved delivery stops the run",
          selfheal.blocked_by_pending(live, pending13, False) is True)
    check("13b (THE BUG): a stale PAYLOAD is installed despite the unresolved delivery",
          selfheal.blocked_by_pending(stale_payload, pending13, False) is False)
    check("13c: ...and so is a stale CONFIG",
          selfheal.blocked_by_pending(stale_config, pending13, False) is False)
    check("13d: ...and an unpatched Spotify is re-patched, not left broken",
          selfheal.blocked_by_pending(unpatched, pending13, False) is False)
    check("13e: nothing pending never blocks",
          selfheal.blocked_by_pending(live, None, False) is False)
    check("13f: --force is never blocked",
          selfheal.blocked_by_pending(live, pending13, True) is False)

    # ---------------------------------------------------------------------
    # 14. TWO PATCHES IN A ROW MUST NOT BRICK THE RECORD.
    #
    # run() stamps the epoch BEFORE the repair and again AFTER it. The second
    # call was ignored because a stamp already existed, so the stored target
    # stayed the PRE-repair payload while Spotify ran the post-repair one.
    # Clearance requires the live hashes to equal the stored target, so the
    # incident became permanently unclearable however well the new code worked.
    #
    # This is not hypothetical: the live install reached exactly this state
    # (target e538..., running 1280..., observed 0s) and had to be repaired by
    # hand. Codex asked for a test that calls note_block_change twice; this is
    # that test.
    # ---------------------------------------------------------------------
    state14: dict = {}
    selfheal.note_delivery_failure(state14, 1, fp_before)
    mid = dict(fp_before, live_payload_sha="mid" * 21, live_config_sha="midc" * 16)
    final = dict(fp_before, live_payload_sha="fin" * 21, live_config_sha="finc" * 16)

    selfheal.note_block_change(state14, mid)          # pre-repair stamp
    d14 = state14["unresolved_delivery"]
    first_stamp = d14["changed_at"]
    check("14. the first patch is stamped as the target",
          d14["changed_to_payload"] == mid["live_payload_sha"])

    selfheal.note_block_change(state14, final)        # post-repair stamp
    check("14b (THE BRICK): a second patch RE-stamps rather than being ignored",
          d14["changed_to_payload"] == final["live_payload_sha"],
          f"target={d14['changed_to_payload'][:12]} live={final['live_payload_sha'][:12]}")
    check("14c: ...and the observation counter restarts with the new block",
          d14["observed_s"] == 0)
    check("14d: ...so the record can still become clearable",
          d14["changed_to_payload"] == final["live_payload_sha"]
          and d14["changed_to_config"] == final["live_config_sha"])

    d14["changed_at"] = int(time.time()) - (selfheal.DELIVERY_CLEAR_AFTER_S + 60)
    d14["observed_s"] = selfheal.DELIVERY_MIN_OBSERVED_S + 60
    check("14e: and it does, once the window and the listening are satisfied",
          selfheal.clearable_reason(state14, final) is not None,
          str(selfheal.clearable_reason(state14, final)))

    # Re-stamping only on a REAL change: calling it again with the same
    # fingerprint must not reset the clock the run is waiting on.
    state14["unresolved_delivery"] = dict(d14)
    selfheal.note_block_change(state14, final)
    check("14f: an unchanged fingerprint does not restart the clock",
          state14["unresolved_delivery"]["changed_at"] == d14["changed_at"]
          and state14["unresolved_delivery"]["observed_s"] == d14["observed_s"],
          "re-stamping on every run would mean the window never completes")
    assert first_stamp is not None

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print("delivery-state rules: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
