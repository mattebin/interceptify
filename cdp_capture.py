"""
Live diagnostic capture for Interceptify v2.

Attaches to Spotify's Chrome DevTools Protocol endpoint (only open while the
tray's "Debug capture mode" is ON, which launches Spotify with
--remote-debugging-port=9222), calls window.__interceptify.snapshot() in the
renderer, and dumps every identifier — MediaSources, <audio>/<video> elements,
AudioContexts + master gains, the in-stream ad object, classified ad sources,
recent network/ad-intel — to a timestamped capture_*.json.

Run this WHILE a bug is happening live (e.g. an ad + a song playing at once).

Usage:  python cdp_capture.py [port]   (default port 9222)
"""

import json
import sys
import time

import redact
import urllib.request

import websocket  # websocket-client

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9222
ORIGIN = "http://127.0.0.1:%d" % PORT  # matches the patcher's --remote-allow-origins

SNAP_EXPR = (
    "JSON.stringify((window.__interceptify && window.__interceptify.snapshot) "
    "? window.__interceptify.snapshot() : {err:'no-interceptify'})"
)



def redact_snapshot(node):
    """Walk the snapshot and redact EVERY string in it, not just the URL-shaped
    ones.

    This used to skip any string without "://" in it, which meant response
    bodies - the metaLog carries up to 4000 characters of them - were written to
    disk verbatim by a function named redact_snapshot. An embedded JSON
    access_token survived the whole "redaction" path untouched.
    """
    return redact.redact_any(node)

def list_targets():
    with urllib.request.urlopen("http://127.0.0.1:%d/json" % PORT, timeout=5) as r:
        return json.loads(r.read())


def eval_expr(ws_url, expr):
    ws = websocket.create_connection(ws_url, origin=ORIGIN, timeout=8)
    try:
        ws.send(json.dumps({
            "id": 1, "method": "Runtime.evaluate",
            "params": {"expression": expr, "returnByValue": True, "awaitPromise": False},
        }))
        deadline = time.time() + 8
        while time.time() < deadline:
            msg = json.loads(ws.recv())
            if msg.get("id") == 1:
                r = msg.get("result", {})
                if r.get("exceptionDetails"):
                    return None, str(r["exceptionDetails"])
                return r.get("result", {}).get("value"), None
    finally:
        try:
            ws.close()
        except Exception:
            pass
    return None, "timeout"


def warn_if_piling_up(pattern: str = "capture_*.json", limit: int = 10) -> None:
    """Say when diagnostics are accumulating. They are redacted, not harmless:
    a capture still describes what was playing and when. Nothing here deletes
    anything - `python selfheal.py --scrub` lists them and only removes them
    when told to."""
    import pathlib
    files = sorted(pathlib.Path(__file__).resolve().parent.glob(pattern))
    if len(files) >= limit:
        print(f"NOTE: {len(files)} {pattern} files in the project directory. "
              f"Review and clear them with: python selfheal.py --scrub")


def main():
    warn_if_piling_up()
    try:
        targets = list_targets()
    except Exception as e:
        print("Cannot reach CDP on port %d (%s)." % (PORT, e))
        print("Enable 'Debug capture mode' in the Interceptify tray first (it relaunches Spotify with the debug port).")
        sys.exit(1)

    pages = [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
    snap = None
    for t in pages:
        try:
            val, err = eval_expr(t["webSocketDebuggerUrl"], SNAP_EXPR)
            if val and '"err":"no-interceptify"' not in val:
                snap = val
                break
        except Exception as e:
            # Even the error paths print through the redactor. A CDP target URL
            # is a Spotify renderer URL, and these two lines were the one place
            # a raw one still reached the terminal.
            print("  (target %s: %s)" % (redact.redact_url(t.get("url", ""))[:60], e))

    if not snap:
        print("No __interceptify.snapshot found on any page target.")
        print("Targets seen:", [redact.redact_url(t.get("url", ""))[:60] for t in pages])
        print("Make sure Spotify is patched AND running with Debug capture mode ON.")
        sys.exit(2)

    # The snapshot is a live dump of Spotify's authenticated renderer: request
    # URLs and response bodies in it carry access tokens and account
    # identifiers. Redact ONCE, up front, and print from the redacted copy.
    # Splitting it - redacted to the file, raw to the terminal - meant the
    # credentials were still on screen, in the scrollback, and in whatever the
    # user pasted into a bug report.
    data = redact_snapshot(json.loads(snap))
    out = "capture_%s.json" % time.strftime("%Y%m%d-%H%M%S")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # Headline identifiers, focused on the concurrent ad+song bug.
    print("=" * 70)
    print("SAVED full snapshot -> %s" % out)
    print("=" * 70)
    print("adState=%s  adActive=%s  weMuted=%s  strongPresent=%s  weak=%s"
          % (data.get("adState"), data.get("adActive"), data.get("weMuted"),
             data.get("strongPresent"), data.get("weak")))
    print("docTitle=%r  nowPlaying=%s" % (data.get("docTitle"), data.get("nowPlaying")))
    print("instreamModuleIds=%s  knownAdSources=%s  instreamWindowActiveMs=%s"
          % (data.get("instreamModuleIds"), data.get("knownAdSources"), data.get("instreamWindowActiveMs")))
    print("-" * 70)
    me = data.get("mediaElements", [])
    print("MEDIA ELEMENTS (%d) — concurrent streams show up here:" % len(me))
    for m in me:
        print("  %s src=%s dur=%.1f t=%.1f paused=%s muted=%s vol=%s rs=%s"
              % (m.get("tag"), str(m.get("src"))[-60:], m.get("duration") or 0,
                 m.get("currentTime") or 0, m.get("paused"), m.get("muted"),
                 m.get("volume"), m.get("readyState")))
    ms = data.get("mediaSources", [])
    print("MEDIA SOURCES (%d):" % len(ms))
    for s in ms:
        print("  readyState=%s url=%s" % (s.get("readyState"), s.get("url")))
    ac = data.get("audioContexts", [])
    print("AUDIO CONTEXTS (%d):" % len(ac))
    for c in ac:
        print("  state=%s masterGain=%s" % (c.get("state"), c.get("masterGain")))
    print("-" * 70)
    print("recent diagLog:", json.dumps(data.get("diagLog", [])[-12:]))
    print("recent manifests (metaLog):")
    for m in (data.get("metaLog", []) or [])[-6:]:
        print("  url=%s status=%s maxEnd=%s adActive=%s" % (str(m.get("url"))[-70:], m.get("status"), m.get("maxEnd"), m.get("adActive")))
    print("(full network sniffer + adIntel in the saved JSON)")


if __name__ == "__main__":
    main()
