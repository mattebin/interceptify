"""
The recon record is only useful if a Spotify update's moves come out of it in
words. This feeds it the two builds we have real data for (1.3.0 and 1.3.9,
reduced to the fields that changed) and checks the report names each move, and
that an unchanged build reports nothing.

    python tests/test_recon.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import recon_ids  # noqa: E402

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"   :: {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def build(version, chunk, conn_id, exports, methods, used, provider, slots, dom):
    return {
        "client": {"userAgent": f"Spotify/{version}"},
        "runtime": {"chunkArrays": chunk, "defineExportsArity": 3, "registryGlobal": "object"},
        "connector": {"moduleId": conn_id, "exportNames": exports, "methods": methods, "used": used},
        "gate": {"gateKeysDiscovered": ["ad_enabled"], "envelopeKeys": ["state"], "stateKeys": ["ad_enabled", "is_playing"]},
        "provider": {"moduleId": provider},
        "slots": {"primary": "stream", "constants": slots},
        "esperanto": {"spotify.ads.esperanto.proto.Slots": ["1"]},
        "dom": dom,
    }


def main() -> int:
    used = {"putState": True, "getAdState": True, "skipToNextWithOverride": True}
    old = build("1.3.0.277", ["rspackChunk"], "84032", ["adsCoreConnector", "l", "q"],
                ["putState", "getAdState", "skipToNextWithOverride"], used, "98213",
                {"STREAM_SLOT_ID": "stream", "SPONSORED_PLAYLIST_SLOT_ID": "sponsored-playlist"},
                {"testid:ad-controls": {"inBundleModules": 1}, "testid:canvas-ad-player": {"inBundleModules": 1}})
    new = build("1.3.9.2055", ["rspackChunk"], "15", ["zz", "l", "q"],
                ["putState", "getAdState", "skipToNext"], {**used, "skipToNextWithOverride": False}, "57106",
                {"STREAM_SLOT_ID": "stream", "PODCAST_SPONSOR_SLOT_ID": "podcast-creator-sponsorship-1"},
                {"testid:ad-controls": {"inBundleModules": 1}, "testid:canvas-ad-player": {"inBundleModules": 0}})

    moved = recon_ids.changes_between(old, new)
    text = "\n".join(moved)
    check("1. the connector module's new id is reported", "connector module: 84032 -> 15" in text, text)
    check("2. a renamed connector export is reported", "connector export names" in text and "zz" in text, text)
    check("3. the provider's new id is reported", "in-stream provider module: 98213 -> 57106" in text, text)
    check("4. a method the block uses going missing is called out as such",
          "connector methods the block USES are gone: skipToNextWithOverride" in text, text)
    check("5. added and removed methods and slots are listed",
          "connector method added: skipToNext" in text and "ad slot removed: sponsored-playlist" in text
          and "ad slot added: podcast-creator-sponsorship-1" in text, text)
    check("6. a screen-element name that left the bundle is listed",
          "screen-element names no longer in the bundle: testid:canvas-ad-player" in text, text)
    check("7. things that did not move are not mentioned",
          "chunk array" not in text and "gate key" not in text and "primary ad slot" not in text, text)
    check("8. an identical build reports nothing", recon_ids.changes_between(new, json.loads(json.dumps(new))) == [])

    out = Path(tempfile.mkdtemp(prefix="interceptify-recon-"))
    p1, m1 = recon_ids.save(json.loads(json.dumps(old)), out)
    p2, m2 = recon_ids.save(json.loads(json.dumps(new)), out)
    p3, m3 = recon_ids.save(json.loads(json.dumps(new)), out)
    check("9. the first record of all has nothing to compare against", m1 == [] and p1.name == "spotify-1.3.0.277.json")
    check("10. the next build is compared against the one before it",
          p2.name == "spotify-1.3.9.2055.json" and any("84032 -> 15" in m for m in m2), str(m2))
    check("11. re-recording the same build compares against the OTHER build, not against itself",
          any("84032 -> 15" in m for m in m3), str(m3))

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print("recon: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
