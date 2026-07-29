"""
A release must be able to correct a build-volatile default.

That is the entire reason the config is external. Selectors, webpack module ids,
gate-key patterns and URL regexes are the values a Spotify rebuild invalidates,
so when we ship a fix for one it has to reach installs that already have the
file. Two attempts at this have now failed in opposite directions:

  * v2.0.4: "merge only keys the user does not have yet". An existing install
    kept its old value forever, so a corrected instreamModuleFallbackId could
    never take effect.
  * the first split: "treat every difference from the bundled file as a user
    override and preserve it in the local file". Identical outcome by a longer
    route - the release's own correction was recorded as a local override OF
    ITSELF and lost.

Both guessed, because the content of a config file cannot tell "the user edited
this" from "this is simply the previous release's copy". So we stamp the sha of
the shipped file whenever we write it, and let the stamp answer the question.

Asserted here:
  1. no config at all              -> seeded from the bundle
  2. untouched since we wrote it   -> new shipped defaults take effect
  3. user override in the LOCAL file -> survives, and still wins
  4. modified shipped file, unknown provenance -> new defaults take effect AND
     the old file is kept, not silently discarded
  5. unparseable config            -> quarantined and replaced, never tolerated
  6. patching refuses while the effective config cannot be built

Run:  python tests/test_config_upgrade.py
"""

from __future__ import annotations

import json
import os
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


OLD = {"instreamModuleFallbackId": 46849, "tickMs": 500}
NEW = {"instreamModuleFallbackId": 99999, "tickMs": 500, "brandNewKnob": 7}


def main() -> int:
    os.environ["APPDATA"] = tempfile.mkdtemp(prefix="interceptify-cfgupgrade-")
    import main as app
    import spotify_patcher

    tmp = Path(tempfile.mkdtemp(prefix="interceptify-cfg-"))
    install, bundle = tmp / "install", tmp / "bundle"
    (install / "extensions").mkdir(parents=True)
    (bundle / "extensions").mkdir(parents=True)
    (bundle / "extensions" / "adblock.js").write_text("// payload", encoding="utf-8")
    (bundle / "extensions" / "adblock.config.json").write_text(
        json.dumps(NEW, indent=2), encoding="utf-8")

    app.ROOT = install
    app.bundled_root = lambda: bundle
    spotify_patcher._root = lambda: install

    ext = install / "extensions"
    shipped = ext / "adblock.config.json"
    local = ext / "adblock.config.local.json"

    # 1. Nothing there yet.
    app.sync_bundled_extensions()
    check("1. a fresh install is seeded from the bundle",
          json.loads(shipped.read_text(encoding="utf-8")) == NEW)

    # 2. We wrote it and nobody touched it; ship a newer default.
    (bundle / "extensions" / "adblock.config.json").write_text(
        json.dumps({**NEW, "instreamModuleFallbackId": 11111}, indent=2), encoding="utf-8")
    app.sync_bundled_extensions()
    check("2. an untouched shipped config takes the NEW default",
          json.loads(shipped.read_text(encoding="utf-8"))["instreamModuleFallbackId"] == 11111,
          shipped.read_text(encoding="utf-8"))
    check("2b. ...without inventing a local override",
          not local.exists(), "a local override file was created out of nothing")
    # The provenance stamp is what makes this branch distinguishable from a
    # hand-edited file. Without it every routine update would take the
    # unknown-provenance path and leave a superseded-* copy behind, so the
    # install directory fills with near-identical files and the one that ever
    # matters is impossible to spot.
    check("2c. ...and without setting aside a copy of a file nobody edited",
          not list(ext.glob("adblock.config.superseded-*.json")),
          f"stray: {[p.name for p in ext.glob('adblock.config.superseded-*.json')]}")

    # 3. A real user override lives in the local file and must win.
    local.write_text(json.dumps({"instreamModuleFallbackId": 424242}), encoding="utf-8")
    (bundle / "extensions" / "adblock.config.json").write_text(
        json.dumps({**NEW, "instreamModuleFallbackId": 22222, "tickMs": 750}, indent=2),
        encoding="utf-8")
    app.sync_bundled_extensions()
    merged = spotify_patcher.load_adblock_config()
    check("3. an explicit local override survives the update and wins",
          merged["instreamModuleFallbackId"] == 424242, str(merged.get("instreamModuleFallbackId")))
    check("3b. ...while a shipped value the user never overrode still updates",
          merged["tickMs"] == 750, str(merged.get("tickMs")))

    # 4. Hand-edited shipped file (or a pre-stamp install): unknown provenance.
    local.unlink()
    shipped.write_text(json.dumps({**NEW, "instreamModuleFallbackId": 777, "tickMs": 111}, indent=2),
                       encoding="utf-8")
    (bundle / "extensions" / "adblock.config.json").write_text(
        json.dumps({**NEW, "instreamModuleFallbackId": 33333, "tickMs": 750}, indent=2),
        encoding="utf-8")
    app.sync_bundled_extensions()
    check("4. a modified shipped config does NOT block the release's correction",
          json.loads(shipped.read_text(encoding="utf-8"))["instreamModuleFallbackId"] == 33333,
          shipped.read_text(encoding="utf-8"))
    kept = list(ext.glob("adblock.config.superseded-*.json"))
    check("4b. ...and the user's previous file is kept, not discarded", len(kept) == 1,
          f"found {[p.name for p in kept]}")
    check("4c. ...with its actual contents intact",
          bool(kept) and json.loads(kept[0].read_text(encoding="utf-8"))["tickMs"] == 111)

    # 5. Corrupt file: quarantined and replaced, not tolerated.
    for p in kept:
        p.unlink()
    shipped.write_text("{ this is not json", encoding="utf-8")
    app.sync_bundled_extensions()
    check("5. an unparseable shipped config is replaced with the shipped defaults",
          json.loads(shipped.read_text(encoding="utf-8"))["instreamModuleFallbackId"] == 33333)
    corrupt = list(ext.glob("adblock.config.corrupt-*.json"))
    check("5b. ...and quarantined rather than deleted", len(corrupt) == 1,
          f"found {[p.name for p in corrupt]}")

    # 6. While the effective config cannot be built, patching must refuse. It
    #    used to warn and inject an effectively empty config, so a payload with
    #    none of the Spotify-specific selectors, ids or gate keys went in while
    #    everything reported success.
    local.write_text("{ broken", encoding="utf-8")
    problem = spotify_patcher.config_problem()
    check("6. a malformed local override is detected", problem is not None, str(problem))
    ok, msg = spotify_patcher.patch(show_badge=True, debug_capture=False)
    check("6b. ...and patch() refuses rather than injecting an empty config",
          not ok and "Refusing to patch" in msg, msg)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print("config upgrade path: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
