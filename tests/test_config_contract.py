"""
The config file and the payload must agree about what the knobs are called.

This exists because they silently stopped agreeing. adblock.js was changed to
read `CFG.webpackChunkGlobals` (plural, a list) while adblock.config.json still
published `webpackChunkGlobal` (singular). Nothing failed: the payload fell back
to its built-in default and the documented knob simply stopped working. A
tunable that does nothing is worse than a missing one, because it reads as
tried-and-didn't-help when the truth is never-applied.

Three directions, all of which have actually broken:
  * a config key nothing reads       -> a knob that silently does nothing
  * a CFG.* read with no default     -> undefined at runtime if config is absent
  * a build-volatile default that is
    NOT published                    -> the next Spotify rebuild needs a code
                                        change and a release, when the whole
                                        point of the file is that it needs
                                        neither

COMMENTS ARE NOT READS. The scan used to run over the raw source, so a knob
mentioned only in a comment counted as used - which is how `seek15BurstSpacingMs`
and `weakOnlySelectors` stayed published for months after the code that read
them was removed. Comments are stripped before anything is matched.

Run:  python tests/test_config_contract.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "extensions" / "adblock.config.json"
PAYLOAD = ROOT / "extensions" / "adblock.js"

# Keys the payload reads dynamically rather than as a literal CFG.<name>, so a
# source scan cannot see them. Each one needs a reason to be here.
DYNAMIC_READS: dict[str, str] = {
    # discovery patterns are read via a helper that takes the key name
    "adGateKeyPatterns": "read through the ad-gate discovery helper",
    "adGateFallbackKeys": "read through the ad-gate discovery helper",
}

# Defaults that a Spotify rebuild can invalidate. Every one of these MUST be in
# the shipped config, because the alternative when Spotify moves is editing JS
# and cutting a release - and the file exists precisely so that a re-patch is
# enough. Codex found the contract had no check in this direction at all.
BUILD_VOLATILE = [
    "strongAdSelectors", "fuzzyAdTestIdRegex", "visualHideSelectors",
    "skipForwardTestId", "seekForward15TestId", "muteButtonTestId",
    "playPauseTestId", "progressInputSelector", "nowPlayingTitleSelectors",
    "instreamSourceSignatures", "instreamModuleFallbackId",
    "playerStateSignatures", "playerStateFallbackId",
    "webpackChunkGlobals", "manifestRegex", "sourceSegmentRegex",
    "sponsoredPlaylistRegex", "adBodyMarkerRegex", "adUrlSignals",
    "adTextMarkers", "adGateKeyPatterns", "adGateFallbackKeys",
    "adSlots", "primaryAdSlot", "adSlotIdRegex", "primarySlotRegex",
    "connectorSkipMethods",
]

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"(?m)^\s*//.*$")
_TRAILING_COMMENT = re.compile(r"(?m)(?<![:\"'\\])//(?![\"']).*$")


def strip_comments(js: str) -> str:
    """Source with comments blanked out, so a mention is not mistaken for a use.

    Deliberately crude: it can only ever remove too much (a `//` inside a string
    literal), and removing too much makes this test stricter, never laxer. A
    knob it wrongly reports as unread is a five-second look at the code; a knob
    it wrongly reports as read is what this test exists to catch.
    """
    js = _BLOCK_COMMENT.sub(" ", js)
    js = _LINE_COMMENT.sub("", js)
    return _TRAILING_COMMENT.sub("", js)


def main() -> int:
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    raw = PAYLOAD.read_text(encoding="utf-8")
    js = strip_comments(raw)
    failures: list[str] = []

    # ---- 1. every published key must be read somewhere -------------------
    for key in cfg:
        # Leading underscore = a note for whoever edits the file. The patcher
        # strips these before injecting, so they never reach the page.
        if key.startswith("_") or key in DYNAMIC_READS:
            continue
        if not re.search(r"CFG\.%s\b" % re.escape(key), js):
            failures.append(f"config key {key!r} is published but never read as CFG.{key} "
                            f"(mentions in comments do not count)")

    # ---- 2. every key the payload reads must have a built-in default -----
    # The config is merged OVER the defaults, so a read with no default is
    # undefined whenever the file is missing a key - which is the normal state
    # for an older config after an upgrade.
    if "const DEFAULTS" not in js:
        failures.append("adblock.js has no `const DEFAULTS` block to check reads against")
    defaults_block = js.split("const DEFAULTS", 1)[-1]
    for key in sorted(set(re.findall(r"CFG\.([A-Za-z_][A-Za-z0-9_]*)", js))):
        if not re.search(r"^\s*%s:" % re.escape(key), defaults_block, re.M):
            failures.append(f"CFG.{key} is read but has no built-in default in adblock.js")

    # ---- 3. build-volatile defaults must be externally published ---------
    for key in BUILD_VOLATILE:
        if key not in cfg:
            failures.append(f"{key!r} is build-volatile but is not published in "
                            f"{CONFIG.name}; a Spotify rebuild would need a code change")

    for f in failures:
        print(f"[FAIL] {f}")
    if failures:
        print(f"\n{len(failures)} config-contract violation(s).")
        return 1
    published = len([k for k in cfg if not k.startswith("_")])
    print(f"[PASS] {published} config keys: all read by adblock.js outside comments, all with "
          f"defaults, and all {len(BUILD_VOLATILE)} build-volatile knobs published.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
