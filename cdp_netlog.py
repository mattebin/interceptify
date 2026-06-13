"""
Continuous CDP network recorder for Interceptify v2 diagnosis.

Attaches to Spotify's renderer (CDP port, open while Debug capture mode is ON),
enables the Network domain, and logs EVERY request the renderer makes to a
netlog_*.jsonl (full URLs + type + status), printing streaming/ad-ish ones live.
This catches the manifest + segment URLs of a track/ad the moment they're
fetched, regardless of the in-page sniffer's ring-buffer window.

Run in the background; read the netlog_*.jsonl whenever a track change or ad
happens to see the actual stream sources. Ctrl-C / kill to stop.

Usage:  python cdp_netlog.py [port]
"""

import json
import re
import sys
import time
import urllib.request

import websocket  # websocket-client

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9222
ORIGIN = "http://127.0.0.1:%d" % PORT
OUT = "netlog_%s.jsonl" % time.strftime("%Y%m%d-%H%M%S")

# streaming / ad / telemetry shapes worth flagging live
FLAG = re.compile(
    r"/manifests/|/segments/|/sources/|spotifycdn|audio4-|/storage-resolve|"
    r"/track-playback|/ads/|/ad-logic/|gabo-receiver|doubleclick|adeventtracker|"
    r"/melody/|sponsoredplaylist|/ad/|/context-feed",
    re.I,
)


def page_target():
    tg = json.loads(urllib.request.urlopen("http://127.0.0.1:%d/json" % PORT, timeout=5).read())
    pages = [t for t in tg if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
    if not pages:
        raise RuntimeError("no page target (is Debug capture mode on?)")
    return pages[0]


def main():
    t = page_target()
    ws = websocket.create_connection(t["webSocketDebuggerUrl"], origin=ORIGIN, timeout=10)
    ws.settimeout(None)  # blocking recv for a long-running logger
    ws.send(json.dumps({"id": 1, "method": "Network.enable"}))
    f = open(OUT, "w", encoding="utf-8")
    print("RECORDING -> %s  (title=%r)" % (OUT, t.get("title", "")[:40]), flush=True)
    n = 0
    try:
        while True:
            msg = json.loads(ws.recv())
            m = msg.get("method")
            if m == "Network.requestWillBeSent":
                p = msg["params"]
                url = p.get("request", {}).get("url", "")
                rec = {"t": round(time.time(), 2), "ev": "req", "type": p.get("type"), "url": url}
                f.write(json.dumps(rec) + "\n"); f.flush()
                n += 1
                if FLAG.search(url):
                    print("  REQ [%s] %s" % (p.get("type"), url[:170]), flush=True)
            elif m == "Network.responseReceived":
                p = msg["params"]
                resp = p.get("response", {})
                url = resp.get("url", "")
                if FLAG.search(url):
                    rec = {"t": round(time.time(), 2), "ev": "resp", "status": resp.get("status"),
                           "mime": resp.get("mimeType"), "type": p.get("type"), "url": url}
                    f.write(json.dumps(rec) + "\n"); f.flush()
                    print("  RESP %s %s %s" % (resp.get("status"), resp.get("mimeType"), url[:150]), flush=True)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print("logger stopped:", type(e).__name__, e, flush=True)
    finally:
        print("total requests logged: %d" % n, flush=True)
        try: f.close()
        except Exception: pass
        try: ws.close()
        except Exception: pass


if __name__ == "__main__":
    main()
