"""
Record every Spotify-side name the block depends on, for the build that is
installed right now.

Nothing here changes Spotify or the patch. It restarts the client once with a
debug port, asks the running page what the payload resolved and what the bundle
actually contains, writes one JSON file, and restarts the client normally.

    python recon_ids.py                 # restart, dump, restart clean
    python recon_ids.py --port 9222     # attach to an already-open debug port
    python recon_ids.py --out DIR       # where the JSON goes (default: ./recon)

Run it after a Spotify update and diff the file against the previous build's:
that diff is the list of things the update moved.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import spotify_patcher  # noqa: E402

JS = r"""
(async () => {
  const out = {};
  const safe = (fn, d) => { try { return fn(); } catch (e) { return d === undefined ? "ERR " + String(e).slice(0, 120) : d; } };
  const M = window.__webpack_modules__ || {};
  const src = (id) => { let f = M[id]; if (f && f.__intc_orig) f = f.__intc_orig; try { return String(f); } catch { return ""; } };
  const ids = Object.keys(M);
  const req = window.__interceptify_webpack_require;
  const I = window.__interceptify;
  const h = I ? safe(() => I.health(), {}) : {};

  out.client = {
    userAgent: (navigator.userAgent.match(/Spotify\/[\d.]+/) || [""])[0],
    payload: I ? I.version : null,
    protectionReady: h.protectionReady, notReady: h.notReady, layers: h.layers,
  };

  // ---- how code is reached ------------------------------------------------
  out.runtime = {
    chunkArrays: Object.keys(window).filter((k) => /chunk/i.test(k) && Array.isArray(window[k]) && !/^__interceptify/.test(k)),
    chunkGlobalsHooked: h.chunkGlobals,
    moduleCount: ids.length,
    registryGlobal: typeof window.__webpack_modules__,
    liveRequire: h.liveRequire,
    requireKeys: req ? Object.keys(req) : null,
    defineExportsSource: req && req.d ? String(req.d).slice(0, 220) : null,
    defineExportsArity: req && req.d ? req.d.length : null,
  };

  // ---- the ads connector --------------------------------------------------
  const ac = window.__interceptify_ads_connector;
  const methods = [];
  if (ac) { let p = ac; let d = 0; while (p && p !== Object.prototype && d < 4) { for (const n of Object.getOwnPropertyNames(p)) if (n !== "constructor" && typeof safe(() => ac[n], null) === "function" && methods.indexOf(n) < 0) methods.push(n); p = Object.getPrototypeOf(p); d++; } }
  const cid = window.__interceptify_ads_module;
  const csrc = cid != null ? src(cid) : "";
  out.connector = {
    moduleId: cid, candidates: window.__interceptify_ads_module_candidates,
    sourceLength: csrc.length,
    exportNames: cid != null && req ? safe(() => Object.keys(req(cid))) : null,
    sourceNamesAdsCoreConnector: csrc.includes("adsCoreConnector"),
    methods: methods.sort(),
    used: Object.fromEntries(["putState", "getAdState", "clearSlot", "subscribeToInStreamAds", "skipToNext", "skipToNextWithOverride", "updateAdStateEndpoint", "updateAdServerEndpoint", "fetchSlot", "subscribeToSlot"].map((n) => [n, !!ac && typeof ac[n] === "function"])),
  };

  // ---- the ad gate ----------------------------------------------------------
  let st = null; try { st = ac ? await ac.getAdState() : null; } catch (e) { st = { error: String(e).slice(0, 120) }; }
  const inner = (st && st.state) || {};
  out.gate = {
    envelopeKeys: st ? Object.keys(st) : null,
    stateKeys: Object.keys(inner).sort(),
    valueShape: safe(() => { const k = Object.keys(inner)[0]; return k ? Object.fromEntries(Object.keys(inner[k]).map((x) => [x, typeof inner[k][x]])) : null; }),
    gateKeysDiscovered: h.gateKeys, gateVerified: h.gateVerified,
    ad_enabled: safe(() => inner.ad_enabled && inner.ad_enabled.value, null),
  };

  // ---- slots ----------------------------------------------------------------
  const slotConsts = {};
  for (const id of ids) { const s = src(id); if (s.indexOf("_SLOT_ID") < 0) continue; for (const m of s.matchAll(/([A-Z_]*SLOT[A-Z_]*)\s*[:=]\s*["']([^"']+)["']/g)) slotConsts[m[1]] = m[2]; }
  out.slots = { constants: slotConsts, payloadSlots: h.adSlots, primary: h.primarySlot, discovered: h.discoveredSlots };

  // ---- the in-stream provider (L1) -------------------------------------------
  const pid = window.__interceptify_instream_id;
  const psrc = pid != null ? src(pid) : "";
  const both = ids.filter((id) => { const s = src(id); return s.includes("getInStreamAd") && s.includes("inStreamApi"); });
  const ctx = (psrc.match(/([\w$]+)=[\w$]+\((\d+)\)[;,]?let [\w$]+=\(\)=>\(0,\1\.([\w$]+)\)\(\)\.inStreamApi/) || psrc.match(/=\(\)=>\(0,([\w$]+)\.([\w$]+)\)\(\)\.inStreamApi/) || []);
  const ctxVar = ctx.length === 4 ? ctx[1] : ctx[1];
  const ctxExport = ctx.length === 4 ? ctx[3] : ctx[2];
  const ctxId = ctx.length === 4 ? ctx[2] : ((psrc.match(new RegExp("[,; ]" + (ctxVar || "~") + "=[\\w$]+\\((\\d+)\\)")) || [])[1] || null);
  out.provider = {
    moduleId: pid, sourceLength: psrc.length, source: psrc.slice(0, 600),
    exportNames: (psrc.match(/\{([^{}]*?\b[\w$]+:[^{}]*)\}\)\}?$/) ? null : null),
    exportNamesFromSource: [...psrc.matchAll(/[{,]([\w$]+):(?=[\w$(])/g)].map((m) => m[1]).filter((v, i, a) => a.indexOf(v) === i).slice(-6),
    matchesBothNeedles: both.map((id) => ({ id, len: src(id).length })),
    exportsIntercepted: window.__interceptify_instream_exports_intercepted || 0,
    exportsFrozen: !!window.__interceptify_instream_exports_frozen,
    apiCaptured: !!window.__interceptify_instream_api,
    adsApiContext: { moduleId: ctxId, exportUsed: ctxExport, sourceHasAdsAPIProvider: ctxId ? src(ctxId).includes("AdsAPIProvider") : null },
    adsApiProviderModules: ids.filter((id) => src(id).includes("AdsAPIProvider")),
  };

  // ---- a second handle on the ads core (not used yet) ----------------------
  const svc = {};
  for (const id of ids) { const s = src(id); if (s.indexOf("spotify.ads.esperanto") < 0) continue; for (const m of s.matchAll(/spotify\.ads\.esperanto[\w.]*/g)) (svc[m[0]] = svc[m[0]] || []).push(id); }
  out.esperanto = Object.fromEntries(Object.entries(svc).map(([k, v]) => [k, [...new Set(v)].slice(0, 4)]));

  // ---- DOM names the reactive layer and the CSS use -------------------------
  const cfg = window.__INTERCEPTIFY_CONFIG || {};
  const needles = new Set();
  const take = (v) => { if (typeof v === "string") { for (const m of v.matchAll(/data-testid(?:\*|\^)?="([^"]+)"/g)) needles.add("testid:" + m[1]); for (const m of v.matchAll(/\.([A-Za-z0-9_-]{12,})/g)) needles.add("class:" + m[1]); } else if (Array.isArray(v)) v.forEach(take); };
  ["strongAdSelectors", "visualHideSelectors", "nowPlayingTitleSelectors", "progressInputSelector"].forEach((k) => take(cfg[k]));
  ["skipForwardTestId", "seekForward15TestId", "muteButtonTestId", "playPauseTestId"].forEach((k) => { if (cfg[k]) needles.add("testid:" + cfg[k]); });
  const all = ids.map(src);
  const dom = {};
  for (const n of needles) { const lit = n.split(":")[1]; let c = 0; for (const s of all) if (s.indexOf(lit) >= 0) c++; dom[n] = { inBundleModules: c, inDomNow: n.startsWith("testid:") ? document.querySelectorAll('[data-testid="' + lit + '"]').length : document.getElementsByClassName(lit).length }; }
  out.dom = dom;
  out.configInjected = { keys: Object.keys(cfg).length, instreamModuleFallbackId: cfg.instreamModuleFallbackId, playerStateFallbackId: cfg.playerStateFallbackId, webpackChunkGlobals: cfg.webpackChunkGlobals, connectorSkipMethods: cfg.connectorSkipMethods, adGateKeyPatterns: cfg.adGateKeyPatterns };
  return JSON.stringify(out, (k, v) => (typeof v === "bigint" ? String(v) : v));
})()
"""


def cdp_eval(port: int, expr: str, timeout: float = 60):
    import websocket
    tg = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=3))
    page = next(t for t in tg if t.get("type") == "page")
    ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=timeout,
                                     origin=f"http://127.0.0.1:{port}")
    try:
        ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate",
                            "params": {"expression": expr, "returnByValue": True, "awaitPromise": True}}))
        while True:
            m = json.loads(ws.recv())
            if m.get("id") == 1:
                r = m.get("result", {})
                if "exceptionDetails" in r:
                    raise RuntimeError(json.dumps(r["exceptionDetails"])[:400])
                return r.get("result", {}).get("value")
    finally:
        ws.close()


def wait_port(port: int, seconds: int = 45) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1).read()
            return True
        except Exception:
            time.sleep(1)
    return False


def _listdiff(label: str, old, new) -> list[str]:
    old, new = set(old or []), set(new or [])
    out = []
    if new - old:
        out.append(f"{label} added: {', '.join(sorted(map(str, new - old)))}")
    if old - new:
        out.append(f"{label} removed: {', '.join(sorted(map(str, old - new)))}")
    return out


def changes_between(old: dict, new: dict) -> list[str]:
    """What a Spotify update moved, in words. Only things the block depends on."""
    g = lambda d, *path: __import__("functools").reduce(
        lambda a, k: (a or {}).get(k) if isinstance(a, dict) else None, path, d)
    out: list[str] = []
    for label, path in (("chunk array", ("runtime", "chunkArrays")),
                        ("export definer arity", ("runtime", "defineExportsArity")),
                        ("module registry global", ("runtime", "registryGlobal")),
                        ("connector module", ("connector", "moduleId")),
                        ("connector export names", ("connector", "exportNames")),
                        ("in-stream provider module", ("provider", "moduleId")),
                        ("gate key", ("gate", "gateKeysDiscovered")),
                        ("ad-state envelope", ("gate", "envelopeKeys")),
                        ("primary ad slot", ("slots", "primary"))):
        a, b = g(old, *path), g(new, *path)
        if a != b:
            out.append(f"{label}: {a} -> {b}")
    out += _listdiff("connector method", g(old, "connector", "methods"), g(new, "connector", "methods"))
    lost = [k for k, v in (g(new, "connector", "used") or {}).items()
            if not v and (g(old, "connector", "used") or {}).get(k)]
    if lost:
        out.append("connector methods the block USES are gone: " + ", ".join(sorted(lost)))
    out += _listdiff("ad-state key", g(old, "gate", "stateKeys"), g(new, "gate", "stateKeys"))
    out += _listdiff("ad slot", (g(old, "slots", "constants") or {}).values(), (g(new, "slots", "constants") or {}).values())
    out += _listdiff("ads service", (old.get("esperanto") or {}).keys(), (new.get("esperanto") or {}).keys())
    od, nd = old.get("dom") or {}, new.get("dom") or {}
    dead = sorted(k for k, v in nd.items() if not v.get("inBundleModules") and (od.get(k) or {}).get("inBundleModules"))
    if dead:
        out.append("screen-element names no longer in the bundle: " + ", ".join(dead))
    return out


def save(data: dict, out_dir: Path) -> tuple[Path, list[str]]:
    """Write this build's record and return (path, what moved since the most
    recent record of a DIFFERENT build)."""
    version = (data.get("client", {}).get("userAgent") or "Spotify/unknown").split("/")[-1]
    data["recorded"] = time.strftime("%Y-%m-%d %H:%M")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"spotify-{version}.json"
    previous = None
    others = sorted((p for p in out_dir.glob("spotify-*.json") if p != path), key=lambda p: p.stat().st_mtime)
    if others:
        try:
            previous = json.loads(others[-1].read_text(encoding="utf-8"))
        except Exception:
            previous = None
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path, (changes_between(previous, data) if previous else [])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0, help="attach to this debug port instead of restarting Spotify")
    ap.add_argument("--out", default=str(ROOT / "recon"))
    ap.add_argument("--settle", type=float, default=15.0, help="seconds to let the client boot before asking")
    a = ap.parse_args()

    restarted = False
    port = a.port
    if not port:
        port = 9222
        for _ in range(8):
            if not spotify_patcher.is_spotify_running():
                break
            spotify_patcher.kill_spotify(); time.sleep(1.2)
        spotify_patcher.launch_spotify(port)
        restarted = True
        if not wait_port(port):
            print("no debug port; is Spotify installed?")
            return 2
        time.sleep(a.settle)
    try:
        data = json.loads(cdp_eval(port, JS))
    finally:
        if restarted:
            for _ in range(8):
                if not spotify_patcher.is_spotify_running():
                    break
                spotify_patcher.kill_spotify(); time.sleep(1.2)
            spotify_patcher.launch_spotify(0)
    path, moved = save(data, Path(a.out))
    print(path)
    for m in moved:
        print("  moved:", m)
    return 0


if __name__ == "__main__":
    sys.exit(main())
