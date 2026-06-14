/*
 * Interceptify ad-block — injected into Spotify's xpui.spa.
 *
 * Strategy, in order of preference:
 *   1. Hook window.fetch / XHR: stub out requests to known ad endpoints
 *      before they leave the app. (Belt + braces with Interceptify's proxy.)
 *   2. Watch Spotify's track state via the DOM; when the current track is
 *      flagged as an advertisement, seek to the end / press skip.
 *   3. Fallback: mute the <audio> element whenever an ad is detected so
 *      even un-skippable ones become silent.
 *
 * Why this file is small and simple: every update to Spotify's internal JS
 * can rename private symbols, so we stick to stable surfaces (DOM test-ids,
 * fetch URLs, <audio> elements). Easier to keep alive than reaching into
 * their redux store.
 */
(function () {
  const TAG = "[interceptify]";
  const log = (...a) => console.log(TAG, ...a);

  // ===================================================================
  // CONFIG — every build-volatile knob lives here so a Spotify update is
  // a JSON ship (adblock.config.json -> window.__INTERCEPTIFY_CONFIG),
  // not a JS edit. Defaults below MIRROR adblock.config.json so the file
  // still works if the injected global is absent or partial.
  // Regexes are stored as STRINGS and compiled with new RegExp() at use.
  // The old window flags are folded in for back-compat (they seed the
  // defaults, then config/defaults can override).
  // ===================================================================
  const CFG = Object.assign({
    // ---- timing ----
    tickMs: 500,
    cooldownMs: 1500,            // post-ad/post-skip advancing lockout
    suspectClearTicks: 2,
    confirmTicks: 2,             // a strong ad marker must persist >= this many ticks before CONFIRM+mute (kills 1-tick flickers)
    suspectMaxMs: 8000,          // force un-mute if weak-only never escalates
    skipRetryMs: 900,
    maxSkipRetries: 3,
    minAdvanceIntervalMs: 700,   // global anti-spin
    forceRestoreMs: 4000,        // watchdog: force gain/mute restore if ad_active but no strong
    maxAdMs: 90000,              // hard ceiling: force-release if an "ad" persists longer than any real ad
    instreamWindowMs: 3000,
    seek15Burst: 4,
    seek15BurstSpacingMs: 150,
    // ---- DOM detection: ADVANCING gate (audio/video-ad subset ONLY) ----
    // ADVANCING gate: only audio/video-ad controls that UNMOUNT with the ad
    // audio. context-item-info-ad-* are deliberately NOT here — they are
    // now-playing UI TEXT that lingers ~1 tick past the audio transition and
    // were a confirmed over-skip vector; they live in weakOnly (mute) instead.
    strongAdSelectors: [
      '[data-testid="ad-controls"]', '[data-testid="ad-countdown-timer"]',
      '[data-testid="ads-video-player-npv"]', '[data-testid="standalone-video-ad-player"]',
      '[data-testid="canvas-ad-player"]', '[data-testid="canvas-ad-container"]',
      '[data-testid="video-takeover-link"]',
    ],
    // Anchored (^...$) so a prefix can't bleed into a non-ad id; no context-item-info-ad here.
    fuzzyAdTestIdRegex: "^(ad-controls|ad-countdown[\\w-]*|ads?-video[\\w-]*|standalone-video-ad[\\w-]*|canvas-ad-(player|container)|video-takeover[\\w-]*)$",
    // arm mute/CSS but NEVER advance (lingering nodes — the v1 over-skip leftovers)
    weakOnlySelectors: [
      '[data-testid="ad-companion-card"]', '[data-testid="leavebehind-advertiser"]',
      '[data-testid="context-item-info-ad-title"]', '[data-testid="context-item-info-ad-subtitle"]',
    ],
    visualHideSelectors: [
      '[data-testid="context-item-info-ad-title"]',
      '[data-testid="context-item-info-ad-subtitle"]',
      '[data-testid="context-item-info"][aria-label*="Advertisement" i]',
      '[data-testid="ad-controls"]',
      '[data-testid="ad-countdown-timer"]',
      '[data-testid="embedded-ad"]',
      '[data-testid="embedded-ad-carousel"]',
      '[data-testid="home-ad-card"]',
      '[data-testid="home-ads-container"]',
      '[data-testid="sponsored-recommendation-modal-trigger"]',
      '[data-testid="ad-companion-card"]',
      '[data-testid="ad-companion-card-tagline"]',
      '[data-testid="leavebehind-advertiser"]',
      // Build-specific empty ad-banner at the bottom of the main view. It has NO
      // stable testid/aria — only a minified class — so re-identify it after a
      // Spotify update with diagnosticOverlay + Alt+click. The :has() rule also
      // collapses its class-less wrapper so the reserved space disappears.
      '.ScclvBC0NsMgQLQC',
      'div:has(> .ScclvBC0NsMgQLQC)',
    ],
    // ---- skip targets ----
    skipForwardTestId: "control-button-skip-forward",
    seekForward15TestId: "control-button-seek-forward-15",
    muteButtonTestId: "volume-bar-toggle-mute-button",
    progressInputSelector: '[data-testid="playback-progressbar"] input[type="range"]',
    nowPlayingTitleSelectors: [
      '[data-testid="context-item-link"]',
      '[data-testid="context-item-info-title"]',
      '[data-testid="now-playing-widget"] a',
    ],
    // ---- L1 webpack discovery (NO hard-coded ids) ----
    // STRICT: only the provider module has BOTH getInStreamAd AND inStreamApi.
    // The looser sets/regex (onAdMessageCallbacks, bare inStreamAd, etc.)
    // over-matched unrelated modules and broke Spotify's boot, since wrapping
    // touches exports named d/m that countless minified modules also have.
    instreamSourceSignatures: [["getInStreamAd", "inStreamApi"]],
    instreamSourceRegex: "",            // disabled — the AND-pair uniquely IDs the provider
    playerStateSignatures: [["AdsAPIProvider"]],  // the ads-API module's stable error-string (was 5563)
    playerStateRegex: "",
    playerStateFallbackId: 5563,        // used only if scan fails
    instreamModuleFallbackId: 46849,    // used only if scan fails (fast-path hint)
    enableInstreamHook: true,           // master kill-switch for L1; set false if a build breaks on it
    webpackChunkGlobal: "webpackChunkclient_web",
    // ---- network classifier ----
    manifestRegex: "/manifests/v\\d+/json/sources/([a-f0-9]+)/options",
    manifestAdMaxMs: 60000,
    manifestAdMinMs: 1000,
    manifestRequireCorroboration: true,
    manifestDurationBlock: false,       // OFF by default: duration is the ONLY /options manifest ad-signal
                                        // and it false-positives on short (<60s) REAL tracks. L1+L3 catch ads.
    adBodyMarkerRegex: "audio_ad|creative_id|lineitem_id|advertisement|\"file_type\"\\s*:\\s*\"AD",
    knownAdSourcesMax: 256,
    sourceSegmentRegex: "/sources/([a-f0-9]+)/",
    sponsoredPlaylistRegex: "/sponsoredplaylist/v\\d+/sponsored",
    manifestDurationFields: ["end_time_millis", "duration_millis", "duration_ms"],
    adUrlSignals: ["/ads/", "/ad-logic/", "/gabo-receiver-service/", "/pagead", "doubleclick.net", "adeventtracker"],
    // ---- feature flags (window flags seed the defaults for back-compat) ----
    blockInstreamSignal: window.__INTERCEPTIFY_BLOCK_INSTREAM_SIGNAL !== false,
    enableDomSprayLastResort: false,    // the deleted blind-seek family stays OFF
    enableMediaSourceEndOfStream: false,
    diagnosticOverlay: false,           // show load state + uncaught errors in-page (Spotify gates DevTools)
    debugCapture: window.__INTERCEPTIFY_DEBUG_CAPTURE === true,
    showBadge: window.__INTERCEPTIFY_SHOW_BADGE !== false,
  }, (window.__INTERCEPTIFY_CONFIG && typeof window.__INTERCEPTIFY_CONFIG === "object") ? window.__INTERCEPTIFY_CONFIG : {});

  // Compiled-regex cache: CFG stores regex SOURCES as strings; compile once.
  const _reCache = {};
  function rx(src, flags) {
    if (src == null) return null;
    const key = (flags || "") + "::" + src;
    let re = _reCache[key];
    if (!re) {
      try { re = new RegExp(src, flags); } catch { re = null; }
      _reCache[key] = re;
    }
    return re;
  }

  // Back-compat aliases for the surviving code below.
  const DEBUG_CAPTURE = CFG.debugCapture === true;
  const blockInStreamSignal = () => CFG.blockInstreamSignal !== false;

  // ---- Diagnostic: capture uncaught errors + (optionally) show them in-page ----
  // Spotify gates DevTools, so when the patched client renders blank/broken this
  // surfaces the actual boot error + what we hooked, visibly, for a screenshot.
  window.__interceptify_errors = window.__interceptify_errors || [];
  // Rolling FSM event log — records every state transition + its trigger signal
  // and every mute/gain action, so an over-mute can be traced to the exact
  // signal that fired. Always on (cheap); the overlay reads it.
  window.__interceptify_diag_log = window.__interceptify_diag_log || [];
  window.__interceptify_diag_counts = window.__interceptify_diag_counts || {};
  const _diagT0 = Date.now();
  function _diagLog(type, info) {
    try {
      const e = { t: +((Date.now() - _diagT0) / 1000).toFixed(1), type };
      if (info) for (const k in info) e[k] = info[k];
      window.__interceptify_diag_log.push(e);
      const ck = type + (info && (info.reason || info.sel) ? ":" + (info.reason || info.sel) : "");
      window.__interceptify_diag_counts[ck] = (window.__interceptify_diag_counts[ck] || 0) + 1;
      if (window.__interceptify_diag_log.length > 250) window.__interceptify_diag_log = window.__interceptify_diag_log.slice(-150);
    } catch {}
  }
  try {
    const _onErr = (msg, src, line, col, err) => {
      try {
        window.__interceptify_errors.push({
          msg: String(msg), src: String(src || "").slice(-70), line,
          stack: ((err && err.stack) || "").slice(0, 500),
        });
      } catch {}
    };
    window.addEventListener("error", (e) => _onErr(e.message, e.filename, e.lineno, e.colno, e.error), true);
    window.addEventListener("unhandledrejection", (e) => _onErr("unhandledrejection: " + ((e.reason && e.reason.message) || e.reason), "", 0, 0, e.reason), true);
  } catch {}
  if (CFG.diagnosticOverlay) {
    // Alt+click any element to print its identity + ancestor chain in the
    // overlay — lets us pinpoint a blank/reserved banner container precisely.
    window.__interceptify_inspect = null;
    try {
      window.addEventListener("click", (ev) => {
        if (!ev.altKey) return;
        try { ev.preventDefault(); ev.stopPropagation(); } catch {}
        const chain = [];
        let el = ev.target;
        for (let i = 0; el && i < 8; i++, el = el.parentElement) {
          const tid = (el.getAttribute && el.getAttribute("data-testid")) || "";
          const al = (el.getAttribute && el.getAttribute("aria-label")) || "";
          const cls = (((el.className && el.className.baseVal !== undefined) ? el.className.baseVal : el.className) || "") + "";
          const r = el.getBoundingClientRect();
          chain.push((el.tagName || "?").toLowerCase() +
            (tid ? " testid=" + tid : "") + (al ? " aria=" + al.slice(0, 28) : "") +
            (cls ? " cls=" + cls.slice(0, 48) : "") + " [" + Math.round(r.width) + "x" + Math.round(r.height) + "]");
        }
        window.__interceptify_inspect = chain;
      }, true);
    } catch {}
    const _renderDiag = () => {
      try {
        if (!document.body) return;
        let d = document.getElementById("interceptify-diag");
        if (!d) {
          d = document.createElement("div");
          d.id = "interceptify-diag";
          d.style.cssText = "position:fixed;top:44px;left:8px;right:8px;max-height:62%;overflow:auto;z-index:2147483647;background:rgba(25,0,0,0.94);color:#fff;font:11px/1.45 monospace;padding:10px;border:2px solid #ff3b30;white-space:pre-wrap;";
          (document.body || document.documentElement).appendChild(d);
        }
        let state = "?"; try { state = adState; } catch {}
        let weMuted = "?"; try { weMuted = _weMuted; } catch {}
        const ids = window.__interceptify_instream_module_ids || [];
        const errs = window.__interceptify_errors || [];
        const logArr = window.__interceptify_diag_log || [];
        const counts = window.__interceptify_diag_counts || {};
        const countStr = Object.keys(counts).sort((a, b) => counts[b] - counts[a]).slice(0, 10)
          .map((k) => k + "=" + counts[k]).join("  ");
        const recent = logArr.slice(-18).map((e) => {
          const extra = Object.keys(e).filter((k) => k !== "t" && k !== "type").map((k) => k + "=" + e[k]).join(" ");
          return e.t + "s " + e.type + (extra ? " " + extra : "");
        }).join("\n");
        let lines =
          "INTERCEPTIFY DIAGNOSTIC (diagnosticOverlay:false to hide)\n" +
          "state=" + state + "  weMuted=" + weMuted + "  ad_active=" + (!!window.__interceptify_ad_active) +
          "  L1hook=" + (CFG.enableInstreamHook !== false) + "  ids=" + JSON.stringify(ids) + "  errors=" + errs.length + "\n" +
          "signal/transition counts: " + (countStr || "(none)") + "\n" +
          "--- recent FSM events (newest last) — watch this when music mutes ---\n" +
          (recent || "(no ad signals seen yet — good)");
        const insp = window.__interceptify_inspect;
        lines += "\n\n>>> ALT+CLICK the empty banner to identify it (TARGET first, parents below) <<<\n" +
          (insp ? insp.map((s, i) => (i ? "   ^ " : "TARGET: ") + s).join("\n") : "(alt+click the red-circled empty area, then screenshot)");
        // Banner finder: ANY wide box low in the viewport (incl. class-less ones).
        try {
          const b = [];
          const vh = window.innerHeight || 1080;
          document.querySelectorAll("div, aside, section, footer").forEach((el) => {
            const r = el.getBoundingClientRect();
            if (r.width < 280 || r.height < 12 || r.height > 220 || r.top < vh * 0.55) return;
            const tid = el.getAttribute("data-testid") || "";
            const al = (el.getAttribute("aria-label") || "").slice(0, 20);
            const cls = (((el.className && el.className.baseVal !== undefined) ? el.className.baseVal : el.className) || "") + "";
            b.push("@top:" + Math.round(r.top) + " " + Math.round(r.width) + "x" + Math.round(r.height) +
              (tid ? " testid=" + tid : "") + (al ? " aria=" + al : "") + (cls ? " cls=" + cls.slice(0, 26) : "") +
              (el.childElementCount === 0 ? " EMPTY" : ""));
          });
          b.sort((x, y) => parseInt(y.split(":")[1], 10) - parseInt(x.split(":")[1], 10));
          d.textContent = lines + "\n--- lower-viewport boxes (bottom-most first; the banner is one of these) ---\n" + (b.slice(0, 14).join("\n") || "(none)");
        } catch { d.textContent = lines; }
      } catch {}
    };
    if (document.body) _renderDiag(); else document.addEventListener("DOMContentLoaded", _renderDiag);
    setInterval(_renderDiag, 1000);
  }

  // ===================================================================
  // EARLY HOOKS — must install before Spotify's deferred xpui-snapshot.js
  // runs, so we catch the dealer WebSocket and the very first fetches.
  // ===================================================================

  // Shared state
  window.__interceptify_ad_active = false;
  window.__interceptify_sniffer = window.__interceptify_sniffer || [];
  window.__interceptify_meta_log = window.__interceptify_meta_log || [];
  window.__interceptify_mediasources = window.__interceptify_mediasources || new Set();
  window.__interceptify_known_ad_sources = window.__interceptify_known_ad_sources || new Set();
  window.__interceptify_ad_intel = window.__interceptify_ad_intel || {
    manifests: [],
    blockedSources: [],
    blockedSegments: [],
    instreamAds: [],
    instreamApiCalls: [],
    adPlays: [],
  };

  function snifferLog(kind, info) {
    if (!DEBUG_CAPTURE) return;
    try {
      window.__interceptify_sniffer.push({
        ts: Date.now(),
        adActive: !!window.__interceptify_ad_active,
        kind, ...info,
      });
      if (window.__interceptify_sniffer.length > 8000)
        window.__interceptify_sniffer = window.__interceptify_sniffer.slice(-4000);
    } catch {}
  }

  function nowPlayingSnapshot() {
    try {
      const title =
        document.querySelector('[data-testid="context-item-link"]') ||
        document.querySelector('[data-testid="context-item-info-title"]') ||
        document.querySelector('[data-testid="now-playing-widget"] a');
      const subtitle =
        document.querySelector('[data-testid="context-item-info-subtitle"]') ||
        document.querySelector('[data-testid="context-item-info-ad-subtitle"]');
      return {
        documentTitle: document.title,
        title: (title && title.textContent || "").trim().slice(0, 160),
        subtitle: (subtitle && subtitle.textContent || "").trim().slice(0, 160),
      };
    } catch {
      return {};
    }
  }

  function rememberIntel(bucket, info) {
    if (!DEBUG_CAPTURE) return;
    try {
      const intel = window.__interceptify_ad_intel;
      const arr = intel[bucket] || (intel[bucket] = []);
      arr.push({
        ts: Date.now(),
        adActive: !!window.__interceptify_ad_active,
        nowPlaying: nowPlayingSnapshot(),
        ...info,
      });
      if (arr.length > 200) intel[bucket] = arr.slice(-120);
    } catch {}
  }

  function installSuppressionCss() {
    try {
      if (document.getElementById("interceptify-suppress-css")) return;
      const style = document.createElement("style");
      style.id = "interceptify-suppress-css";
      style.textContent = [
        'html[data-interceptify-ad-suppressed="true"] [data-testid*="ad" i] { display:none !important; visibility:hidden !important; opacity:0 !important; pointer-events:none !important; }',
        'html[data-interceptify-ad-suppressed="true"] [data-testid*="sponsor" i] { display:none !important; visibility:hidden !important; opacity:0 !important; pointer-events:none !important; }',
        'html[data-interceptify-ad-suppressed="true"] [data-testid*="premium" i] { display:none !important; visibility:hidden !important; opacity:0 !important; pointer-events:none !important; }',
        'html[data-interceptify-ad-suppressed="true"] [data-testid="context-item-info"] { visibility:hidden !important; opacity:0 !important; }',
        'html[data-interceptify-ad-suppressed="true"] [data-testid="now-playing-widget"] { visibility:hidden !important; opacity:0 !important; }',
        'html[data-interceptify-ad-suppressed="true"] [data-testid="now-playing-bar"] a[href*="/premium"] { display:none !important; }',
        'html[data-interceptify-ad-suppressed="true"] iframe[src*="ad"], html[data-interceptify-ad-suppressed="true"] iframe[id*="ad"] { display:none !important; visibility:hidden !important; }',
      ].join("\n");
      (document.head || document.documentElement).appendChild(style);
    } catch {}
  }

  function suppressAdUi(reason, ms) {
    try {
      installSuppressionCss();
      const until = Date.now() + (ms || 2500);
      window.__interceptify_suppress_ad_ui_until = Math.max(window.__interceptify_suppress_ad_ui_until || 0, until);
      document.documentElement.setAttribute("data-interceptify-ad-suppressed", "true");
      snifferLog("ad-ui-suppress", { reason, until });
      setTimeout(() => {
        try {
          if (Date.now() >= (window.__interceptify_suppress_ad_ui_until || 0)) {
            document.documentElement.removeAttribute("data-interceptify-ad-suppressed");
          }
        } catch {}
      }, (ms || 2500) + 50);
    } catch {}
  }

  function clearExpiredSuppressionCss() {
    try {
      if (Date.now() >= (window.__interceptify_suppress_ad_ui_until || 0)) {
        document.documentElement.removeAttribute("data-interceptify-ad-suppressed");
      }
    } catch {}
  }
  installSuppressionCss();

  function extractManifestMaxEnd(text) {
    let maxEnd = 0;
    const fields = (CFG.manifestDurationFields && CFG.manifestDurationFields.length)
      ? CFG.manifestDurationFields : ["end_time_millis", "duration_millis", "duration_ms"];
    try {
      const visit = (v) => {
        if (!v || typeof v !== "object") return;
        for (const f of fields) {
          if (typeof v[f] === "number") maxEnd = Math.max(maxEnd, v[f]);
        }
        if (Array.isArray(v)) {
          v.forEach(visit);
        } else {
          Object.keys(v).forEach((k) => visit(v[k]));
        }
      };
      visit(JSON.parse(text));
    } catch {}
    try {
      // String scan fallback (in case the JSON.parse path missed nested forms).
      const fieldAlt = fields.map((f) => f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
      const re = rx('"(?:' + fieldAlt + ')"\\s*:\\s*(\\d+)', "g");
      if (re) {
        let m;
        while ((m = re.exec(text)) !== null) {
          const n = parseInt(m[1], 10);
          if (Number.isFinite(n)) maxEnd = Math.max(maxEnd, n);
        }
      }
    } catch {}
    return maxEnd;
  }

  function emptyManifestResponse() {
    return new Response(
      JSON.stringify({ contents: [] }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  }

  function compactValue(value, depth = 0) {
    if (value == null) return value;
    if (typeof value === "string") return value.slice(0, 600);
    if (typeof value === "number" || typeof value === "boolean") return value;
    if (typeof value === "function") return "[Function]";
    if (depth > 3) return "[DepthLimit]";
    if (Array.isArray(value)) return value.slice(0, 20).map((v) => compactValue(v, depth + 1));
    if (typeof value === "object") {
      const out = {};
      Object.keys(value).slice(0, 80).forEach((k) => {
        try { out[k] = compactValue(value[k], depth + 1); } catch {}
      });
      return out;
    }
    return String(value).slice(0, 200);
  }

  function summarizeAdObject(ad) {
    if (!ad || typeof ad !== "object") return null;
    const metadata = ad.metadata || {};
    const summary = {
      id: ad.id,
      adId: ad.adId,
      requestId: ad.requestId,
      uri: ad.uri,
      slot: ad.slot,
      mediaType: ad.mediaType,
      isPodcastAd: ad.isPodcastAd,
      isDsaEligible: ad.isDsaEligible,
      clickthroughUrl: ad.clickthroughUrl,
      advertiser: ad.advertiser || metadata.advertiser,
      creativeId: metadata.creative_id,
      lineitemId: metadata.lineitem_id,
      buttonMessage: metadata.buttonMessage,
      tagline: metadata.tagline,
      logoImage: metadata.logoImage || ad.logoImage,
      images: compactValue(ad.images),
      metadata: compactValue(metadata),
    };
    if (!summary.id && !summary.adId && !summary.uri && !summary.clickthroughUrl && !summary.advertiser) {
      return null;
    }
    return summary;
  }

  function rememberInStreamAd(ad, reason) {
    try {
      const summary = summarizeAdObject(ad);
      if (!summary) return;
      suppressAdUi(reason || "instream-ad", 3000);
      const key = [
        summary.adId || summary.id || "",
        summary.requestId || "",
        summary.uri || "",
        summary.clickthroughUrl || "",
      ].join("|");
      window.__interceptify_seen_instream_ads = window.__interceptify_seen_instream_ads || new Set();
      if (key && window.__interceptify_seen_instream_ads.has(key)) return;
      if (key) window.__interceptify_seen_instream_ads.add(key);
      rememberIntel("instreamAds", { reason, ad: summary });
      snifferLog("instream-ad", {
        reason,
        id: summary.adId || summary.id,
        advertiser: summary.advertiser,
        uri: summary.uri,
        clickthroughUrl: (summary.clickthroughUrl || "").slice(0, 220),
      });
      window.__interceptify_instream_ad_until = Date.now() + 3000;
      try {
        setBadgeState("blocked");
        scheduleTransientAdCleanup(3500, "instream-ad");
      } catch {}
    } catch {}
  }

  function inStreamAdKey(ad) {
    try {
      const summary = summarizeAdObject(ad);
      if (!summary) return "";
      return [
        summary.adId || summary.id || "",
        summary.requestId || "",
        summary.uri || "",
        summary.clickthroughUrl || "",
      ].join("|");
    } catch {}
    return "";
  }

  function rememberInStreamApiCall(method, info) {
    if (!DEBUG_CAPTURE) return;
    try {
      rememberIntel("instreamApiCalls", {
        method,
        ...compactValue(info || {}, 0),
      });
      snifferLog("instream-api-call", {
        method,
        hasAd: !!(info && info.ad),
        argCount: info && info.argCount,
      });
    } catch {}
  }

  function inStreamAdFromMessage(value) {
    if (!value || typeof value !== "object") return null;
    return value.ad || value.inStreamAd || value.instreamAd || null;
  }

  function looksLikeInStreamAdMessage(value) {
    try {
      const ad = inStreamAdFromMessage(value);
      if (summarizeAdObject(ad)) return true;
      const selfSummary = summarizeAdObject(value);
      if (selfSummary && (selfSummary.creativeId || selfSummary.lineitemId || selfSummary.advertiser)) return true;
      const preview = JSON.stringify(compactValue(value, 0));
      return /Spotify Ad Server|audio_ad|creative_id|lineitem_id/.test(preview) &&
        /advertiser|requestId|adId|inStream/i.test(preview);
    } catch {}
    return false;
  }

  function maybeRememberInStreamMessage(method, value) {
    try {
      const msg = value && typeof value === "object" ? value : null;
      const ad = inStreamAdFromMessage(msg);
      if (ad) {
        rememberInStreamAd(ad, method);
        rememberInStreamApiCall(method, { ad: summarizeAdObject(ad), message: compactValue(msg, 0) });
        return true;
      }
      if (summarizeAdObject(msg)) {
        rememberInStreamAd(msg, method);
        rememberInStreamApiCall(method, { ad: summarizeAdObject(msg), message: compactValue(msg, 0) });
        return true;
      }
      if (msg && /ad/i.test(JSON.stringify(compactValue(msg, 0)))) {
        rememberInStreamApiCall(method, { message: compactValue(msg, 0) });
      }
    } catch {}
    return false;
  }

  // Over-skip guard for the L1 in-stream skipToNext() path. advance() (the FSM
  // choke point) is fully gated; the webpack-driven neutralize path was NOT, so
  // a re-read / lingering / prefetched in-stream ad object could fire
  // skipToNext() onto a REAL song (audited bypass). This mirrors advance()'s two
  // over-skip protections WITHOUT requiring CONFIRMED — gating on state would
  // neuter early/preventive blocking (the in-stream skip is the only lever over
  // core-process ad audio on current builds). It blocks the two realistic
  // over-skip cases only:
  //   (1) the post-skip transition window — we JUST advanced, so a second skip
  //       now lands on the freshly-started real song (the user's #1 fear); and
  //   (2) now-playing has moved off the confirmed ad to a different, non-ad
  //       track (mirror of advance()'s keystone gate (b2)).
  function inStreamSkipSafe() {
    if (Date.now() < cooldownUntil) return false;        // (1) — always enforced
    try {                                                  // (2) — fail-open: a guard
      if (currentAdFp) {                                   //     error must not disable
        const fpNow = nowPlayingSnapshot();               //     the only working lever
        if (!fpEqual(fpNow, currentAdFp) && !fpLooksLikeAd(fpNow)) return false;
      }
    } catch {}
    return true;
  }

  function neutralizeInStreamAd(api, ad, reason) {
    const summary = summarizeAdObject(ad);
    if (!summary) return false;
    suppressAdUi(reason || "neutralize", 3000);
    rememberInStreamAd(ad, reason);
    rememberInStreamApiCall(`${reason}.neutralize`, { ad: summary });
    if (!blockInStreamSignal()) return false;
    try {
      const key = inStreamAdKey(ad) || `${Date.now()}`;
      window.__interceptify_neutralized_ads = window.__interceptify_neutralized_ads || new Set();
      if (!window.__interceptify_neutralized_ads.has(key)) {
        window.__interceptify_neutralized_ads.add(key);
        if (api && typeof api.skipToNext === "function") {
          if (!inStreamSkipSafe()) {
            // Over-skip guard tripped: suppress the skip. The ad object is still
            // nulled below (UI suppressed), and advance() will skip it once
            // CONFIRMED + fully gated, so a real ad is never leaked here.
            rememberInStreamApiCall("skipToNext.suppressed", { ad: summary });
          } else {
            try {
              rememberInStreamApiCall("skipToNext.forAd", { ad: summary });
              api.skipToNext();
              // Arm the SAME transition lock advance() uses, so a re-read ad
              // object (or a real song that just started) cannot trigger a
              // second skip inside the audio->song crossover window.
              cooldownUntil = Math.max(cooldownUntil, Date.now() + (CFG.cooldownMs || 1500));
            } catch (e) {
              rememberInStreamApiCall("skipToNext.error", { error: String(e && e.message || e) });
            }
          }
        }
      }
      if (api && api.__interceptify_set_instream_ad) {
        api.__interceptify_set_instream_ad(null);
      } else if (api && Object.prototype.hasOwnProperty.call(api, "inStreamAd")) {
        api.inStreamAd = null;
      }
    } catch {}
    return true;
  }

  function wrapInStreamCallback(callback, reason) {
    if (typeof callback !== "function") return callback;
    if (callback.__interceptify_wrapped) return callback;
    window.__interceptify_callback_wrappers = window.__interceptify_callback_wrappers || new WeakMap();
    const existing = window.__interceptify_callback_wrappers.get(callback);
    if (existing) return existing;
    const wrapped = function () {
      const args = Array.from(arguments);
      const hasAdPayload = args.some((value) => maybeRememberInStreamMessage(`${reason}.callback`, value));
      rememberInStreamApiCall(`${reason}.callback`, {
        argCount: args.length,
        args: compactValue(args, 0),
      });
      if (hasAdPayload && blockInStreamSignal()) {
        rememberInStreamApiCall(`${reason}.callback.blocked`, {
          argCount: args.length,
          args: compactValue(args, 0),
        });
        return undefined;
      }
      return callback.apply(this, arguments);
    };
    wrapped.__interceptify_wrapped = true;
    wrapped.__interceptify_original = callback;
    window.__interceptify_callback_wrappers.set(callback, wrapped);
    return wrapped;
  }

  function wrapCallbackCollection(collection, reason) {
    if (!collection || collection.__interceptify_callbacks_wrapped) return collection;
    try {
      if (collection instanceof Set) {
        const values = Array.from(collection);
        collection.clear();
        values.forEach((value) => collection.add(wrapInStreamCallback(value, reason)));
        const originalAdd = collection.add;
        collection.add = function (value) {
          rememberInStreamApiCall(`${reason}.add`, { valueType: typeof value });
          return originalAdd.call(this, wrapInStreamCallback(value, reason));
        };
        collection.__interceptify_callbacks_wrapped = true;
        rememberInStreamApiCall(`${reason}.wrapped-set`, { size: collection.size });
        return collection;
      }
      if (Array.isArray(collection)) {
        for (let i = 0; i < collection.length; i++) {
          collection[i] = wrapInStreamCallback(collection[i], reason);
        }
        ["push", "unshift"].forEach((method) => {
          const original = collection[method];
          collection[method] = function () {
            const values = Array.from(arguments).map((value) => wrapInStreamCallback(value, reason));
            rememberInStreamApiCall(`${reason}.${method}`, { count: values.length });
            return original.apply(this, values);
          };
        });
        const originalSplice = collection.splice;
        collection.splice = function (start, deleteCount) {
          const rest = Array.prototype.slice.call(arguments, 2).map((value) => wrapInStreamCallback(value, reason));
          rememberInStreamApiCall(`${reason}.splice`, { count: rest.length });
          return originalSplice.apply(this, [start, deleteCount, ...rest]);
        };
        collection.__interceptify_callbacks_wrapped = true;
        rememberInStreamApiCall(`${reason}.wrapped-array`, { length: collection.length });
        return collection;
      }
      if (typeof collection === "function") {
        return wrapInStreamCallback(collection, reason);
      }
      rememberInStreamApiCall(`${reason}.unknown-collection`, {
        type: typeof collection,
        keys: Object.keys(collection || {}).slice(0, 30),
      });
    } catch (e) {
      rememberInStreamApiCall(`${reason}.wrap-error`, { error: String(e && e.message || e) });
    }
    return collection;
  }

  function wrapAdMessageCallbackSlot(api, reason) {
    if (!api || api.__interceptify_callback_slot_wrapped) return;
    try {
      const existing = api.onAdMessageCallbacks;
      let currentCallbacks = wrapCallbackCollection(existing, `${reason}.onAdMessageCallbacks`);
      Object.defineProperty(api, "onAdMessageCallbacks", {
        configurable: true,
        enumerable: true,
        get() {
          return currentCallbacks;
        },
        set(value) {
          currentCallbacks = wrapCallbackCollection(value, `${reason}.onAdMessageCallbacks`);
        },
      });
      api.__interceptify_callback_slot_wrapped = true;
    } catch (e) {
      rememberInStreamApiCall("onAdMessageCallbacks.wrap-error", { reason, error: String(e && e.message || e) });
    }
  }

  function wrapInStreamApi(api, reason) {
    if (!api || typeof api !== "object" || api.__interceptify_api_wrapped) return api;
    try {
      window.__interceptify_instream_api = api;
      wrapAdMessageCallbackSlot(api, reason);
      try {
        const existing = api.inStreamAd;
        let currentInStreamAd = existing && summarizeAdObject(existing) && blockInStreamSignal() ? null : existing;
        api.__interceptify_set_instream_ad = (value) => { currentInStreamAd = value; };
        Object.defineProperty(api, "inStreamAd", {
          configurable: true,
          enumerable: true,
          get() {
            const hasAd = summarizeAdObject(currentInStreamAd);
            if (hasAd && blockInStreamSignal()) {
              neutralizeInStreamAd(api, currentInStreamAd, "inStreamAd.get");
              return null;
            }
            return currentInStreamAd;
          },
          set(value) {
            if (summarizeAdObject(value)) {
              rememberInStreamApiCall("inStreamAd.set", { ad: summarizeAdObject(value) });
              if (blockInStreamSignal()) {
                neutralizeInStreamAd(api, value, "inStreamAd.set");
                currentInStreamAd = null;
                return;
              }
            }
            currentInStreamAd = value;
          },
        });
        if (summarizeAdObject(existing)) neutralizeInStreamAd(api, existing, "inStreamAd.initial");
      } catch (e) {
        rememberInStreamApiCall("inStreamAd.wrap-error", { error: String(e && e.message || e) });
      }
      const names = new Set();
      let cur = api;
      while (cur && cur !== Object.prototype) {
        Object.getOwnPropertyNames(cur).forEach((name) => names.add(name));
        cur = Object.getPrototypeOf(cur);
      }
      rememberInStreamApiCall("api-discovered", {
        reason,
        methods: Array.from(names).filter((name) => typeof api[name] === "function").sort(),
        keys: Object.keys(api || {}).sort(),
      });
      names.forEach((name) => {
        if (name === "constructor" || typeof api[name] !== "function") return;
        if (api[name].__interceptify_wrapped) return;
        const original = api[name];
        api[name] = function () {
          const args = Array.from(arguments);
          const wrappedArgs = args.map((arg, index) => {
            if (typeof arg !== "function") return arg;
            rememberInStreamApiCall(`${name}.callback-wrapped`, { index });
            return wrapInStreamCallback(arg, name);
          });
          rememberInStreamApiCall(name, {
            argCount: args.length,
            args: compactValue(args, 0),
          });
          const hasAdPayload = args.some((value) => {
            const remembered = maybeRememberInStreamMessage(`${name}.arg`, value);
            return remembered || looksLikeInStreamAdMessage(value);
          });
          if (hasAdPayload && blockInStreamSignal() && /processMessage|set|notify|emit|publish/i.test(name)) {
            rememberInStreamApiCall(`${name}.blocked`, {
              argCount: args.length,
              args: compactValue(args, 0),
            });
            return undefined;
          }
          const result = original.apply(this, wrappedArgs);
          maybeRememberInStreamMessage(`${name}.return`, result);
          if (result && typeof result.then === "function") {
            result.then((value) => maybeRememberInStreamMessage(`${name}.promise`, value)).catch(() => {});
          }
          if (name === "getInStreamAd" && summarizeAdObject(result) && blockInStreamSignal()) {
            neutralizeInStreamAd(api, result, "getInStreamAd.return");
            return null;
          }
          return result;
        };
        api[name].__interceptify_wrapped = true;
        api[name].__interceptify_original = original;
      });
      api.__interceptify_api_wrapped = true;
    } catch (e) {
      rememberInStreamApiCall("api-wrap-error", { reason, error: String(e && e.message || e) });
    }
    return api;
  }

  function wrapInStreamExports(exportsObj) {
    if (!exportsObj || exportsObj.__interceptify_instream_hooked) return;
    // PROVIDER-SHAPE GUARD: only the in-stream provider exports BOTH d (the api
    // accessor) and m (the ad-object accessor) as functions. Refusing anything
    // else prevents collateral wrapping of unrelated modules that merely export
    // a minified function named d or m — which would mangle Spotify's bundle and
    // leave the whole UI blank (the v2.0.0 regression this guards against).
    try {
      if (typeof exportsObj.d !== "function" || typeof exportsObj.m !== "function") return;
    } catch { return; }
    try {
      if (typeof exportsObj.m === "function" && !exportsObj.m.__interceptify_wrapped) {
        const orig = exportsObj.m;
        const wrapped = function () {
          const ad = orig.apply(this, arguments);
          rememberInStreamAd(ad, "webpack-instream.m");
          return ad;
        };
        wrapped.__interceptify_wrapped = true;
        exportsObj.m = wrapped;
      }
      if (typeof exportsObj.d === "function" && !exportsObj.d.__interceptify_wrapped) {
        const orig = exportsObj.d;
        const wrapped = function () {
          const api = wrapInStreamApi(orig.apply(this, arguments), "webpack-instream.d");
          try {
            if (api && typeof api.getInStreamAd === "function" && !api.getInStreamAd.__interceptify_wrapped) {
              const origGet = api.getInStreamAd;
              api.getInStreamAd = function () {
                const ad = origGet.apply(this, arguments);
                rememberInStreamAd(ad, "webpack-instream.d.getInStreamAd");
                return ad;
              };
              api.getInStreamAd.__interceptify_wrapped = true;
            }
          } catch {}
          return api;
        };
        wrapped.__interceptify_wrapped = true;
        exportsObj.d = wrapped;
      }
      exportsObj.__interceptify_instream_hooked = true;
    } catch {}
  }

  // ID-agnostic webpack module discovery. v1 hard-coded module 46849 (the
  // in-stream ad provider) and 5563 (player-state); both are build-volatile,
  // so a renumber silently kills L1. Instead we enumerate ALL module keys and
  // match String(factory) against CFG.instreamSourceSignatures (OR-of-AND-sets)
  // or CFG.instreamSourceRegex. Stringification is cached per modules object
  // via a WeakSet so chunk pushes don't re-stringify everything.
  window.__interceptify_instream_module_ids = window.__interceptify_instream_module_ids || [];
  const _stringifiedFactories = new WeakSet();
  function _factoryMatchesInstream(fn) {
    let src;
    try { src = String(fn); } catch { return false; }
    try {
      const sigs = CFG.instreamSourceSignatures || [];
      for (const andSet of sigs) {
        if (Array.isArray(andSet) && andSet.length && andSet.every((needle) => src.includes(needle))) return true;
      }
    } catch {}
    try {
      if (CFG.instreamSourceRegex) {   // empty string disables the regex (avoid RegExp("") matching everything)
        const re = rx(CFG.instreamSourceRegex);
        if (re && re.test(src)) return true;
      }
    } catch {}
    return false;
  }
  function _factoryMatchesPlayerState(fn) {
    let src;
    try { src = String(fn); } catch { return false; }
    try {
      const sigs = CFG.playerStateSignatures || [];
      for (const andSet of sigs) {
        if (Array.isArray(andSet) && andSet.length && andSet.every((needle) => src.includes(needle))) return true;
      }
    } catch {}
    try {
      if (CFG.playerStateRegex) {
        const re = rx(CFG.playerStateRegex);
        if (re && re.test(src)) return true;
      }
    } catch {}
    return false;
  }
  // Discover the player-state module id within a require's module table so the
  // replaced factory can pull (0, playerState.G)().inStreamApi without a literal.
  function discoverPlayerStateId(require) {
    try {
      if (require && require.m) {
        for (const id of Object.keys(require.m)) {
          const fn = require.m[id];
          if (typeof fn === "function" && _factoryMatchesPlayerState(fn)) return id;
        }
      }
    } catch {}
    return CFG.playerStateFallbackId;
  }
  // Enumerate ALL keys of a modules object; return ids whose factory source
  // matches the in-stream signatures. Caches stringification via the WeakSet.
  function discoverInStreamModuleIds(modules) {
    const found = [];
    if (!modules || typeof modules !== "object") return found;
    try {
      for (const id of Object.keys(modules)) {
        const fn = modules[id];
        if (typeof fn !== "function") continue;
        if (fn.__interceptify_wrapped) continue;
        if (_stringifiedFactories.has(fn)) continue;
        _stringifiedFactories.add(fn);
        if (_factoryMatchesInstream(fn)) found.push(id);
      }
    } catch {}
    return found;
  }

  function installWebpackAdProviderHook() {
    if (window.__interceptify_webpack_ad_hooked) return;
    if (CFG.enableInstreamHook === false) { window.__interceptify_webpack_ad_hooked = true; log("L1 in-stream hook disabled via config"); return; }
    window.__interceptify_webpack_ad_hooked = true;
    try {
      const chunkGlobal = CFG.webpackChunkGlobal || "webpackChunkclient_web";
      const chunk = window[chunkGlobal] = window[chunkGlobal] || [];
      const makeWrappedFactory = (originalFactory) => {
        const wrappedFactory = function (module, exports, require) {
          try {
            const source = String(originalFactory);
            // Fast-path replacement: this factory builds the in-stream ad
            // provider via the player-state module. Discover the player-state
            // id by source scan (was hard-coded 5563).
            if (source.includes("getInStreamAd") && source.includes("inStreamApi") && require.d) {
              const psId = discoverPlayerStateId(require);
              const playerState = require(psId);
              const getApi = () => (0, playerState.G)().inStreamApi;
              const wrappedD = () => {
                const api = wrapInStreamApi(getApi(), "webpack-instream.replaced.d");
                try {
                  if (api && typeof api.getInStreamAd === "function" && !api.getInStreamAd.__interceptify_wrapped) {
                    const origGet = api.getInStreamAd;
                    api.getInStreamAd = function () {
                      const ad = origGet.apply(this, arguments);
                      rememberInStreamAd(ad, "webpack-instream.replaced.getInStreamAd");
                      return ad;
                    };
                    api.getInStreamAd.__interceptify_wrapped = true;
                  }
                } catch {}
                return api;
              };
              const wrappedM = () => {
                const ad = wrappedD().getInStreamAd();
                rememberInStreamAd(ad, "webpack-instream.replaced.m");
                return ad;
              };
              require.d(exports, { d: () => wrappedD, m: () => wrappedM });
              snifferLog("webpack-module-replaced", { module: "instream" });
              return undefined;
            }
          } catch {}
          const result = originalFactory.apply(this, arguments);
          try { wrapInStreamExports(module && module.exports || exports); } catch {}
          return result;
        };
        wrappedFactory.__interceptify_wrapped = true;
        return wrappedFactory;
      };
      // Wrap EVERY discovered in-stream module in a modules object (replaces
      // the literal modules[46849] lookup). Falls back to the literal hint id
      // only when the scan finds nothing.
      // Record what we ACTUALLY wrap (the diagnostic overlay reads this).
      const _recordWrapped = (key) => {
        try {
          if (window.__interceptify_instream_module_ids.indexOf(String(key)) === -1)
            window.__interceptify_instream_module_ids.push(String(key));
        } catch {}
      };
      // The known-good provider id present in `map`, else null. getInStreamAd+
      // inStreamApi can match MORE than the provider (this build also carries a
      // decoy 80755), and wrapping a non-provider destructively blanks the UI —
      // so per-chunk we wrap ONLY the fallback provider id. The source scan is a
      // whole-graph fallback used at bootstrap when that id is genuinely gone.
      const fbKeyIn = (map) => {
        const fb = CFG.instreamModuleFallbackId;
        if (fb == null || !map) return null;
        if (map[fb]) return fb;
        if (map[String(fb)]) return String(fb);
        return null;
      };
      const patchModules = (modules) => {
        if (!modules) return;
        try {
          const key = fbKeyIn(modules);
          if (key != null && !modules[key].__interceptify_wrapped) {
            modules[key] = makeWrappedFactory(modules[key]);
            _recordWrapped(key);
            snifferLog("webpack-module-hooked", { module: String(key) });
          }
        } catch {}
      };
      const patchRequire = (require) => {
        if (!require || !require.m) return;
        try {
          const key = fbKeyIn(require.m);
          if (key != null && !require.m[key].__interceptify_wrapped) {
            require.m[key] = makeWrappedFactory(require.m[key]);
            if (require.c && require.c[key]) delete require.c[key];
            _recordWrapped(key);
            snifferLog("webpack-runtime-module-hooked", { module: String(key) });
          }
        } catch {}
      };
      chunk.forEach((payload) => patchModules(payload && payload[1]));
      const originalPush = chunk.push.bind(chunk);
      chunk.push = function () {
        for (let i = 0; i < arguments.length; i++) {
          patchModules(arguments[i] && arguments[i][1]);
        }
        return originalPush.apply(this, arguments);
      };
      originalPush([[`interceptify-${Date.now()}`], {}, function (require) {
        try {
          window.__interceptify_webpack_require = require;
          patchRequire(require);
          // Whole-graph view of require.m: prefer the known provider id; only if
          // it is genuinely absent (renamed build) wrap the SINGLE best source
          // match — never multiple (that is what blanked the UI).
          let id = fbKeyIn(require.m || {});
          if (id == null) {
            const matched = discoverInStreamModuleIds(require.m || {});
            id = matched.length ? matched[0] : null;
          }
          let wrappedAny = false;
          if (id != null) {
            try {
              if (require.m[id] && !require.m[id].__interceptify_wrapped) {
                require.m[id] = makeWrappedFactory(require.m[id]);
                if (require.c && require.c[id]) delete require.c[id];
              }
              wrapInStreamExports(require(id));
              _recordWrapped(id);
              wrappedAny = true;
            } catch {}
          }
          if (!wrappedAny) log("L1 in-stream module not found — relying on DOM/manifest layers");
        } catch {}
      }]);
    } catch {}
  }

  installWebpackAdProviderHook();

  // Shared ad-URL signal test (CFG.adUrlSignals). Used by the fetch BLOCK 0
  // (folded in from v1's second fetch wrapper) and the XHR block below.
  function looksLikeAdUrl(url) {
    if (typeof url !== "string") {
      try { url = String(url); } catch { return false; }
    }
    const sigs = CFG.adUrlSignals || [];
    return sigs.some((s) => url.includes(s));
  }

  // ---- fetch hook (sniffer + ad-CDN blocker + metadata capture) ----
  // EXACTLY ONE window.fetch wrapper (v1's duplicate second reassignment is
  // gone; its looksLikeAdUrl 403 layer is folded in below as BLOCK 0).
  if (window.fetch && !window.fetch.__interceptify_hooked) {
    const _f = window.fetch;
    window.fetch = function (input, init) {
      let url = "";
      try {
        url = typeof input === "string" ? input : (input && input.url) || "";
      } catch {}
      try {
        snifferLog("fetch", {
          url: url.slice(0, 220),
          method: (init && init.method) || (input && input.method) || "GET",
        });
      } catch {}

      // PRE-PLAYER BLOCK 0: hard 403 on known ad-endpoint URLs (folded in
      // from v1's second fetch wrapper). CFG.adUrlSignals are substring hits.
      try {
        if (url && looksLikeAdUrl(url)) {
          log("blocked fetch:", url);
          try { setBadgeState("blocked"); setTimeout(() => setBadgeState(adState === "CONFIRMED" ? "ad" : "idle"), 800); } catch {}
          try { stats.fetchBlocked++; } catch {}
          return Promise.resolve(
            new Response("{}", { status: 403, headers: { "Content-Type": "application/json" } })
          );
        }
      } catch {}

      // PRE-PLAYER BLOCK 1: starve Spotify of sponsored playlists.
      try {
        if (rx(CFG.sponsoredPlaylistRegex) && rx(CFG.sponsoredPlaylistRegex).test(url)) {
          return Promise.resolve(new Response(
            JSON.stringify({ sponsorships: [] }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          ));
        }
      } catch {}

      // PRE-PLAYER BLOCK 2: source-ID based segment block.
      // Every segment URL has a /sources/<srcId>/ component. Once a
      // manifest tells us a srcId is an ad (duration < 60s), 404 every
      // subsequent segment fetch with that srcId. Spotify's player can't
      // play what it can't fetch.
      try {
        const segRe = rx(CFG.sourceSegmentRegex);
        const segMatch = segRe && url.match(segRe);
        if (segMatch && window.__interceptify_known_ad_sources &&
            window.__interceptify_known_ad_sources.has(segMatch[1])) {
          rememberIntel("blockedSegments", {
            srcId: segMatch[1],
            url: url.slice(0, 220),
            reason: "known-ad-source",
          });
          snifferLog("segment-blocked", { srcId: segMatch[1], url: url.slice(0, 220) });
          return Promise.resolve(new Response(new ArrayBuffer(0), {
            status: 404, statusText: "Blocked by Interceptify (known ad source)",
          }));
        }
      } catch {}

      // PRE-PLAYER BLOCK 3: manifest interception (THE source of truth).
      // Spotify fetches /manifests/v9/json/sources/<srcId>/options/... to
      // learn how to play a piece of media. The response includes
      // end_time_millis -- ad clips are < 60 sec, music/podcasts are
      // hundreds of seconds. If we see a short manifest, replace it with
      // an empty contents array AND remember the srcId so future segment
      // fetches for it get 404'd above.
      try {
        const mfRe = rx(CFG.manifestRegex);
        const mfMatch = mfRe && url.match(mfRe);
        if (mfMatch) {
          const srcId = mfMatch[1];
          // If we've already classified this srcId as ad, return empty immediately
          if (window.__interceptify_known_ad_sources.has(srcId)) {
            rememberIntel("blockedSources", {
              srcId,
              url: url.slice(0, 220),
              reason: "cached-known-ad-source",
            });
            return Promise.resolve(emptyManifestResponse());
          }
          // Otherwise fetch normally, then inspect & maybe rewrite
          return _f.apply(this, arguments).then(async (resp) => {
            try {
              const text = await resp.clone().text();
              const maxEnd = extractManifestMaxEnd(text);
              if (DEBUG_CAPTURE) {
                rememberIntel("manifests", {
                  srcId,
                  url: url.slice(0, 220),
                  status: resp.status,
                  maxEnd,
                  classifiedAs: maxEnd > 0 && maxEnd < CFG.manifestAdMaxMs ? "ad" : "content",
                  bodyLen: text.length,
                  body: text.slice(0, 3000),
                });
                window.__interceptify_meta_log.push({
                  ts: Date.now(),
                  adActive: !!window.__interceptify_ad_active,
                  url: url.slice(0, 220),
                  status: resp.status,
                  bodyLen: text.length,
                  body: text.slice(0, 4000),
                  srcId,
                  maxEnd,
                });
                if (window.__interceptify_meta_log.length > 80)
                  window.__interceptify_meta_log = window.__interceptify_meta_log.slice(-50);
              }
              // Duration is the ONLY ad-signal a /options manifest carries —
              // its body has NO ad markers (verified against live captures, for
              // music AND ads) — and it false-positives on short (<60s) REAL
              // tracks (interludes, skits, punk). So the destructive segment-404
              // block is OPT-IN (CFG.manifestDurationBlock, default OFF); L1
              // (in-stream) + L3 (mute/skip) handle ads without silencing music.
              const adMin = CFG.manifestAdMinMs || 0;
              const inAdWindow = maxEnd > adMin && maxEnd < CFG.manifestAdMaxMs;
              let corroborated = !CFG.manifestRequireCorroboration;
              if (inAdWindow && CFG.manifestRequireCorroboration) {
                let bodyMarker = false;
                try { const mre = rx(CFG.adBodyMarkerRegex, "i"); bodyMarker = !!(mre && mre.test(text)); } catch {}
                // Only a FRESH signal tied to THIS playback (a painted ad marker
                // right now) corroborates — NOT lingering ad_active / instream
                // window, which bleed into the next real track's prefetch.
                let strongNow = false;
                try { strongNow = !!STRONG_PRESENT(); } catch {}
                corroborated = bodyMarker || strongNow;
              }
              if (CFG.manifestDurationBlock && inAdWindow && corroborated) {
                // LRU-cap the set so a one-off classification can't grow unbounded.
                const set = window.__interceptify_known_ad_sources;
                set.add(srcId);
                const cap = CFG.knownAdSourcesMax | 0;
                if (cap > 0 && set.size > cap) {
                  const first = set.values().next();
                  if (!first.done) set.delete(first.value);
                }
                rememberIntel("blockedSources", {
                  srcId, url: url.slice(0, 220), maxEnd, reason: "manifest-short+corroborated",
                });
                snifferLog("manifest-blocked", { srcId, maxEnd, url: url.slice(0, 220) });
                console.log("[interceptify] ad manifest blocked: srcId=" + srcId.slice(0, 8) + "... duration=" + (maxEnd / 1000).toFixed(1) + "s");
                return emptyManifestResponse();
              } else if (inAdWindow) {
                snifferLog("manifest-short-not-blocked", { srcId, maxEnd, durationBlock: !!CFG.manifestDurationBlock, url: url.slice(0, 220) });
              }
            } catch {}
            return resp;
          });
        }
      } catch {}

      // Observe ad-active CDN segments, but do not block by adActive alone.
      // The same hosts/URL shape carry real music and podcasts; only a
      // classified srcId is safe enough to block.
      try {
        if (window.__interceptify_ad_active &&
            /\/segments\/v\d+\/origins\/[a-f0-9]+\/sources\/[a-f0-9]+\//.test(url) &&
            /spotifycdn\.com/.test(url)) {
          const m = url.match(/\/sources\/([a-f0-9]+)\//);
          snifferLog("segment-ad-active-observed", {
            srcId: m && m[1],
            url: url.slice(0, 220),
          });
        }
      } catch {}

      // Capture interesting JSON bodies (metadata, pathfinder, manifests)
      const interesting =
        /\/metadata\/\d+\/track\//.test(url) ||
        /\/pathfinder\/v\d+\/query/.test(url) ||
        /\/sponsoredplaylist\/v\d+\/sponsored/.test(url) ||
        /\/manifests\/v\d+\/json\/sources\//.test(url);

      const promise = _f.apply(this, arguments);
      if (DEBUG_CAPTURE && interesting) {
        promise.then(async (resp) => {
          try {
            const text = await resp.clone().text();
            window.__interceptify_meta_log.push({
              ts: Date.now(),
              adActive: !!window.__interceptify_ad_active,
              url: url.slice(0, 220),
              status: resp.status,
              bodyLen: text.length,
              body: text.slice(0, 4000),
            });
            if (window.__interceptify_meta_log.length > 60)
              window.__interceptify_meta_log = window.__interceptify_meta_log.slice(-30);
          } catch {}
        }).catch(() => {});
      }
      return promise;
    };
    window.fetch.__interceptify_hooked = true;
  }

  // ---- XMLHttpRequest sniffer ----
  if (DEBUG_CAPTURE && XMLHttpRequest && !XMLHttpRequest.prototype.__interceptify_hooked) {
    const _o = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      try { snifferLog("xhr-open", { method, url: (url || "").slice(0, 220) }); } catch {}
      return _o.apply(this, arguments);
    };
    XMLHttpRequest.prototype.__interceptify_hooked = true;
  }

  // ---- WebSocket constructor wrap (catch the dealer) ----
  if (DEBUG_CAPTURE && window.WebSocket && !window.WebSocket.__interceptify_hooked) {
    const _WS = window.WebSocket;
    const Wrapped = function (url, protocols) {
      try { snifferLog("ws-open", { url: (url || "").slice(0, 220) }); } catch {}
      const ws = new _WS(url, protocols);
      const _send = ws.send.bind(ws);
      ws.send = function (data) {
        try {
          const len = typeof data === "string" ? data.length : (data.byteLength || data.size || 0);
          const preview = typeof data === "string" ? data.slice(0, 200) : "<bin>";
          snifferLog("ws-send", { url: ws.url, len, preview });
        } catch {}
        return _send(data);
      };
      ws.addEventListener("message", (ev) => {
        try {
          const d = ev.data;
          const len = typeof d === "string" ? d.length : (d.byteLength || d.size || 0);
          const preview = typeof d === "string" ? d.slice(0, 200) : "<bin>";
          snifferLog("ws-recv", { url: ws.url, len, preview });
        } catch {}
      });
      return ws;
    };
    Wrapped.prototype = _WS.prototype;
    Wrapped.OPEN = _WS.OPEN; Wrapped.CLOSED = _WS.CLOSED;
    Wrapped.CONNECTING = _WS.CONNECTING; Wrapped.CLOSING = _WS.CLOSING;
    Wrapped.__interceptify_hooked = true;
    window.WebSocket = Wrapped;
  }

  // ---- navigator.sendBeacon (telemetry) ----
  if (DEBUG_CAPTURE && navigator.sendBeacon && !navigator.sendBeacon.__interceptify_hooked) {
    const _sb = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      try { snifferLog("beacon", { url: (url || "").slice(0, 220) }); } catch {}
      return _sb(url, data);
    };
    navigator.sendBeacon.__interceptify_hooked = true;
  }

  // ---- EventSource (Server-Sent Events) ----
  if (DEBUG_CAPTURE && window.EventSource && !window.EventSource.__interceptify_hooked) {
    const _ES = window.EventSource;
    const WrappedES = function (url, opts) {
      try { snifferLog("eventsource-open", { url: (url || "").slice(0, 220) }); } catch {}
      const es = new _ES(url, opts);
      es.addEventListener("message", (ev) => {
        try {
          const d = ev.data;
          snifferLog("eventsource-msg", { url, preview: (typeof d === "string" ? d : "").slice(0, 200) });
        } catch {}
      });
      return es;
    };
    WrappedES.prototype = _ES.prototype;
    WrappedES.__interceptify_hooked = true;
    window.EventSource = WrappedES;
  }

  // ---- BroadcastChannel (cross-renderer messaging) ----
  if (DEBUG_CAPTURE && window.BroadcastChannel && !window.BroadcastChannel.__interceptify_hooked) {
    const _BC = window.BroadcastChannel;
    const WrappedBC = function (name) {
      const bc = new _BC(name);
      try { snifferLog("bc-open", { name }); } catch {}
      const _post = bc.postMessage.bind(bc);
      bc.postMessage = function (msg) {
        try { snifferLog("bc-post", { name, preview: JSON.stringify(msg).slice(0, 200) }); } catch {}
        return _post(msg);
      };
      bc.addEventListener("message", (ev) => {
        try { snifferLog("bc-recv", { name, preview: JSON.stringify(ev.data).slice(0, 200) }); } catch {}
      });
      return bc;
    };
    WrappedBC.prototype = _BC.prototype;
    WrappedBC.__interceptify_hooked = true;
    window.BroadcastChannel = WrappedBC;
  }

  // ---- MediaSource tracking + sourcebuffer instrumentation ----
  if (DEBUG_CAPTURE && window.MediaSource && !MediaSource.prototype.__interceptify_hooked) {
    const _add = MediaSource.prototype.addSourceBuffer;
    MediaSource.prototype.__interceptify_hooked = true;
    MediaSource.prototype.addSourceBuffer = function (mime) {
      window.__interceptify_mediasources.add(this);
      try { snifferLog("ms-addSourceBuffer", { mime, msUrl: this.__intercept_url }); } catch {}
      const sb = _add.apply(this, arguments);
      const _ap = sb.appendBuffer.bind(sb);
      sb.appendBuffer = function (data) {
        // Instrument only. Dropping MediaSource buffers can poison the next
        // real track when Spotify leaves ad UI mounted after ad audio ends.
        if (window.__interceptify_ad_active) {
          try { snifferLog("ms-appendBuffer-ad-active", { size: data.byteLength || 0, mime }); } catch {}
        }
        try { snifferLog("ms-appendBuffer", { size: data.byteLength || data.size || 0, mime }); } catch {}
        return _ap(data);
      };
      return sb;
    };
  }

  // URL.createObjectURL: tag MediaSource with its blob URL so we can correlate
  if (DEBUG_CAPTURE && URL.createObjectURL && !URL.createObjectURL.__interceptify_hooked) {
    const _c = URL.createObjectURL.bind(URL);
    URL.createObjectURL = function (obj) {
      const u = _c(obj);
      try {
        if (obj instanceof MediaSource) obj.__intercept_url = u;
        snifferLog("createObjectURL", { url: u.slice(0, 80), kind: obj && obj.constructor && obj.constructor.name });
      } catch {}
      return u;
    };
    URL.createObjectURL.__interceptify_hooked = true;
  }

  // ---- Safe-skip guard (belt + braces only) ----
  // Block our own clicks on skip-forward / skip-back / playpause when no
  // STRONG ad marker is currently in the DOM, or while we are in COOLDOWN.
  // Stops a stray click from ruining music on the ad->song transition tick.
  // It is NO LONGER load-bearing: the blind seek/keyboard/blanket-video
  // mechanisms it used to miss are deleted. adInDom() now uses
  // CFG.strongAdSelectors ONLY (companion/leavebehind removed — those linger
  // into a song and would let a click through).
  if (!window.__interceptify_safe_skip) {
    window.__interceptify_safe_skip = true;
    const adInDom = () => {
      try {
        const sel = (CFG.strongAdSelectors || []).join(", ");
        if (sel && document.querySelector(sel)) return true;
      } catch {}
      return false;
    };
    const inCooldown = () => {
      try { return adState === "COOLDOWN" || Date.now() < cooldownUntil; } catch { return false; }
    };
    const fromOurScript = () => {
      const s = (new Error()).stack || "";
      return /interceptify-adblock|\badvance\b|\bcheck\b/.test(s);
    };
    const _click = HTMLElement.prototype.click;
    HTMLElement.prototype.click = function () {
      try {
        const tid = this.getAttribute && this.getAttribute("data-testid");
        if (tid === "control-button-skip-forward" ||
            tid === "control-button-skip-back" ||
            tid === "control-button-seek-forward-15" ||
            tid === "control-button-playpause") {
          // Block our own click if no strong ad marker, OR during cooldown.
          if (fromOurScript() && (!adInDom() || inCooldown())) return;
        }
      } catch {}
      return _click.apply(this, arguments);
    };
  }

  // killCurrentMediaSources: nuke any open MediaSource by signalling
  // end-of-stream. Spotify's player thinks the audio finished -> advances.
  // OFF by default (CFG.enableMediaSourceEndOfStream): endOfStream() can
  // poison the next real track if Spotify reuses the same MediaSource across
  // the ad->song transition. Last resort only; not wired into the tick.
  function killCurrentMediaSources() {
    if (!CFG.enableMediaSourceEndOfStream) return 0;
    let killed = 0;
    try {
      window.__interceptify_mediasources.forEach((ms) => {
        try {
          if (ms.readyState === "open") {
            ms.endOfStream();
            killed++;
          }
        } catch {}
      });
    } catch {}
    if (killed) log("killed", killed, "MediaSource(s) via endOfStream");
    return killed;
  }
  window.__interceptify_killMediaSources = killCurrentMediaSources;

  // ---- Sniffer buffer expanded for 1-hour data collection ----
  // Bigger ring buffer + periodic snapshot to sessionStorage so we don't
  // lose data on tab refresh.
  if (DEBUG_CAPTURE) setInterval(() => {
    try {
      const events = window.__interceptify_sniffer || [];
      if (events.length > 30000) {
        window.__interceptify_sniffer = events.slice(-15000);
      }
      // Snapshot small summary to sessionStorage so it survives reloads
      sessionStorage.setItem("__interceptify_summary", JSON.stringify({
        ts: Date.now(),
        snifferCount: events.length,
        adActiveCount: events.filter(e => e.adActive).length,
        metaLogCount: (window.__interceptify_meta_log || []).length,
        detections: window.__interceptify ? window.__interceptify.stats() : null,
        knownAdSources: window.__interceptify_known_ad_sources ? window.__interceptify_known_ad_sources.size : 0,
        adIntel: {
          manifests: (window.__interceptify_ad_intel && window.__interceptify_ad_intel.manifests || []).length,
          blockedSources: (window.__interceptify_ad_intel && window.__interceptify_ad_intel.blockedSources || []).length,
          blockedSegments: (window.__interceptify_ad_intel && window.__interceptify_ad_intel.blockedSegments || []).length,
          adPlays: (window.__interceptify_ad_intel && window.__interceptify_ad_intel.adPlays || []).length,
        },
      }));
    } catch {}
  }, 30000);

  // ---- PerformanceObserver: catches EVERY network resource ----
  // Belt-and-braces in case some fetch path bypasses our hooks.
  try {
    if (DEBUG_CAPTURE && typeof PerformanceObserver !== "undefined" && !window.__interceptify_perfobs) {
      window.__interceptify_perfobs = true;
      const po = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          try {
            snifferLog("perf-resource", {
              name: (entry.name || "").slice(0, 220),
              initiatorType: entry.initiatorType,
              size: entry.transferSize || entry.encodedBodySize || 0,
              duration: Math.round(entry.duration),
            });
          } catch {}
        }
      });
      po.observe({ type: "resource", buffered: true });
    }
  } catch {}

  // ---- Service Worker registration tracker ----
  try {
    if (DEBUG_CAPTURE && navigator.serviceWorker && !navigator.serviceWorker.__interceptify_hooked) {
      const _reg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
      navigator.serviceWorker.register = function (url, opts) {
        try { snifferLog("sw-register", { url: (url || "").slice(0, 220), opts: JSON.stringify(opts || {}) }); } catch {}
        return _reg(url, opts);
      };
      navigator.serviceWorker.__interceptify_hooked = true;
    }
  } catch {}

  // ---- Worker constructor hook ----
  try {
    if (DEBUG_CAPTURE && window.Worker && !window.Worker.__interceptify_hooked) {
      const _W = window.Worker;
      const Wrapped = function (url, opts) {
        try { snifferLog("worker-create", { url: (typeof url === "string" ? url : "<blob>").slice(0, 220) }); } catch {}
        return new _W(url, opts);
      };
      Wrapped.prototype = _W.prototype;
      Wrapped.__interceptify_hooked = true;
      window.Worker = Wrapped;
    }
  } catch {}

  // ---- localStorage / sessionStorage tracking for ad-related keys ----
  try {
    if (DEBUG_CAPTURE) {
      const trackStorage = (storage, label) => {
        const _set = storage.setItem.bind(storage);
        storage.setItem = function (k, v) {
          try {
            if (/ad|ads|sponsor|promot/i.test(k) && k !== "__interceptify_summary") {
              snifferLog(label + "-setItem", { key: k, valLen: (v || "").length, val: (v || "").slice(0, 200) });
            }
          } catch {}
          return _set(k, v);
        };
      };
      if (!localStorage.__interceptify_hooked) {
        trackStorage(localStorage, "localStorage");
        Object.defineProperty(localStorage, "__interceptify_hooked", { value: true });
      }
      if (!sessionStorage.__interceptify_hooked) {
        trackStorage(sessionStorage, "sessionStorage");
        Object.defineProperty(sessionStorage, "__interceptify_hooked", { value: true });
      }
    }
  } catch {}

  // ---- Expand metadata-response capture to MORE endpoints ----
  // Add /track-playback/, /play-state/, /audio-url/, /content-feed/ etc.
  // (handled in the fetch hook above via the `interesting` regex; nothing
  // to do here unless we want to add more — current set is good baseline)

  // ---- MutationObserver on <body> to record EXACT ad UI mount time ----
  try {
    if (DEBUG_CAPTURE && !window.__interceptify_mo_installed) {
      window.__interceptify_mo_installed = true;
      const startup = () => {
        if (!document.body) return setTimeout(startup, 100);
        const mo = new MutationObserver((muts) => {
          for (const m of muts) {
            for (const node of m.addedNodes) {
              if (node.nodeType !== 1) continue;
              try {
                const id = node.getAttribute && node.getAttribute("data-testid");
                if (id && /^(ad|ads|leavebehind|video-takeover|sponsor|context-item-info-ad)/.test(id)) {
                  snifferLog("dom-ad-mount", { testid: id });
                }
              } catch {}
            }
          }
        });
        mo.observe(document.body, { childList: true, subtree: true, attributes: false });
      };
      startup();
    }
  } catch {}

  // ===================================================================
  // END EARLY HOOKS
  // ===================================================================

  // Visible signal the script loaded — adds a small green dot to the top-right
  // corner of the Spotify window. No DevTools needed to confirm.
  // CFG.showBadge (seeded from window.__INTERCEPTIFY_SHOW_BADGE) controls it.
  const SHOW_BADGE = CFG.showBadge !== false;
  function mountBadge() {
    if (!SHOW_BADGE) return;
    if (document.getElementById("interceptify-badge")) return;
    const b = document.createElement("div");
    b.id = "interceptify-badge";
    b.title = "Interceptify ad-block active";
    b.style.cssText = [
      // Sit inside the top nav bar, just left of the "Upgrade to Premium"
      // button. Anchoring to the top-right and offsetting right:~270px keeps
      // it in the same visible spot as the Spotify window resizes.
      "position:fixed",
      "top:18px",
      "right:270px",
      "width:12px",
      "height:12px",
      "border-radius:50%",
      "background:#1ed760",
      "box-shadow:0 0 6px #1ed760",
      "z-index:2147483647",
      "cursor:help",
      "opacity:0.85",
    ].join(";");
    (document.body || document.documentElement).appendChild(b);
  }
  if (document.body) mountBadge();
  else document.addEventListener("DOMContentLoaded", mountBadge);
  // Spotify re-renders the root; re-mount if our badge vanishes.
  setInterval(mountBadge, 2000);

  // ------------------------------------------------------------------
  // 1. Network shim — neutralise ad endpoints client-side
  // ------------------------------------------------------------------
  // NOTE: the fetch ad-URL 403 layer lives in the SINGLE fetch hook above
  // (PRE-PLAYER BLOCK 0). There is no second window.fetch reassignment here
  // any more. looksLikeAdUrl() / CFG.adUrlSignals are shared. The always-on
  // XHR open/send block below carries an idempotency guard so a re-injection
  // can't double-wrap it.
  if (!XMLHttpRequest.prototype.__interceptify_url_block_hooked) {
    XMLHttpRequest.prototype.__interceptify_url_block_hooked = true;
    const _xhrOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      this.__interceptify_url = url;
      return _xhrOpen.apply(this, arguments);
    };
    const _xhrSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function (body) {
      if (looksLikeAdUrl(this.__interceptify_url)) {
        log("blocked xhr:", this.__interceptify_url);
        try { stats.xhrBlocked++; } catch {}
        // Simulate a dead request — fire error after a microtask
        setTimeout(() => this.dispatchEvent(new Event("error")), 0);
        return;
      }
      return _xhrSend.apply(this, arguments);
    };
  }

  // ------------------------------------------------------------------
  // 2 + 3. Detect ad playback and skip / mute
  // ------------------------------------------------------------------

  // STRONG = the audio/video-ad subset that may drive the ADVANCING gate.
  // Sourced from CFG.strongAdSelectors (companion/leavebehind NOT here — they
  // linger past audio end and are the v1 over-skip leftovers; they live in
  // CFG.weakOnlySelectors + CFG.visualHideSelectors instead).
  const STRONG_AD_SELECTORS = (CFG.strongAdSelectors || []).slice();
  // Visual-only ad surfaces — hidden via CSS, never used to skip/mute.
  const VISUAL_AD_SELECTORS = (CFG.visualHideSelectors || []).slice();

  // Hide visual-only ads with CSS so they never render.
  function injectAdHidingCSS() {
    if (document.getElementById("interceptify-hide-css")) return;
    if (!VISUAL_AD_SELECTORS.length) return;
    const style = document.createElement("style");
    style.id = "interceptify-hide-css";
    style.textContent = VISUAL_AD_SELECTORS.map(s => s + " { display:none !important; }").join("\n");
    (document.head || document.documentElement).appendChild(style);
  }
  injectAdHidingCSS();
  setInterval(injectAdHidingCSS, 5000);

  // ------------------------------------------------------------------
  // (Pre-player video-block removed -- it was too broad, killed podcast
  // and Canvas video. To be replaced by manifest-classifier once we have
  // sample data of ad-manifest vs music/podcast-manifest bodies.)
  // ------------------------------------------------------------------
  // Low-level crippling — hooks that prevent ad audio/video from ever
  // reaching the speakers / screen, no matter what Spotify's player does.
  // Activated by window.__interceptify_ad_active which the detection
  // loop below toggles in lockstep with the badge state.
  // ------------------------------------------------------------------
  window.__interceptify_ad_active = false;

  // (a) Master-gain interception. Every AudioNode that wires up to a
  //     speaker (AudioDestinationNode) is rerouted through a per-context
  //     GainNode we own. Setting that gain to 0 mutes everything Spotify
  //     emits, regardless of source type (BufferSource, MediaElementSource,
  //     OscillatorNode, etc.).
  try {
    if (!AudioNode.prototype.__interceptify_connect_hooked) {
      const origConnect = AudioNode.prototype.connect;
      AudioNode.prototype.__interceptify_connect_hooked = true;
      AudioNode.prototype.connect = function (target, ...rest) {
        try {
          if (target && target instanceof AudioDestinationNode) {
            const ctx = target.context;
            if (!ctx.__interceptify_master) {
              const g = ctx.createGain();
              g.gain.value = window.__interceptify_ad_active ? 0 : 1;
              origConnect.call(g, target);
              ctx.__interceptify_master = g;
              // Track EVERY context that gets a master gain (not only those made
              // via our AudioContext wrap) so applyAdActiveGains + the watchdog
              // can always restore it -> no untracked context stuck silent.
              (window.__interceptify_audioContexts = window.__interceptify_audioContexts || new Set()).add(ctx);
            }
            return origConnect.call(this, ctx.__interceptify_master, ...rest);
          }
        } catch {}
        return origConnect.call(this, target, ...rest);
      };
    }
  } catch {}

  // (b) Track every AudioContext so we can flip its master-gain on demand.
  try {
    const _AC = window.AudioContext || window.webkitAudioContext;
    if (_AC && !_AC.__interceptify_wrapped) {
      const Wrapped = function (...a) {
        const c = new _AC(...a);
        (window.__interceptify_audioContexts = window.__interceptify_audioContexts || new Set()).add(c);
        return c;
      };
      Wrapped.prototype = _AC.prototype;
      Wrapped.__interceptify_wrapped = true;
      window.AudioContext = Wrapped;
      if (window.webkitAudioContext) window.webkitAudioContext = Wrapped;
    }
  } catch {}

  // (c) Block <video>.play() during ads — resolve immediately and synthesize
  //     'ended' so Spotify's listener advances the queue.
  try {
    if (!HTMLMediaElement.prototype.__interceptify_play_hooked) {
      const origPlay = HTMLMediaElement.prototype.play;
      HTMLMediaElement.prototype.__interceptify_play_hooked = true;
      HTMLMediaElement.prototype.play = function () {
        // Only intercept the AD video: ad_active AND a blob: source AND a strong
        // ad marker present right now. Otherwise (e.g. the NEXT track's Canvas
        // visualizer video while ad_active is still held through cooldown) play
        // normally — never synthesize 'ended' on real content.
        let _src = "";
        try { _src = this.currentSrc || this.src || ""; } catch {}
        const isAdVideo = window.__interceptify_ad_active && this.tagName === "VIDEO" &&
          typeof _src === "string" && _src.startsWith("blob:") &&
          (typeof STRONG_PRESENT === "function" && STRONG_PRESENT());
        if (isAdVideo) {
          try { this.muted = true; this.volume = 0; } catch {}
          const v = this;
          setTimeout(() => {
            try { if (STRONG_PRESENT()) v.dispatchEvent(new Event("ended", { bubbles: true })); } catch {}
          }, 10);
          return Promise.resolve();
        }
        return origPlay.apply(this, arguments);
      };
    }
  } catch {}

  // (d) Refuse blob: src on <video> while ad-active. Spotify's ad video
  //     comes via a MediaSource blob URL; dropping the assignment means
  //     the video element never gets a source to play from.
  try {
    const proto = HTMLMediaElement.prototype;
    const srcDesc = Object.getOwnPropertyDescriptor(proto, "src");
    if (srcDesc && srcDesc.set && !proto.__interceptify_src_hooked) {
      proto.__interceptify_src_hooked = true;
      Object.defineProperty(proto, "src", {
        configurable: true,
        get: srcDesc.get,
        set(v) {
          if (window.__interceptify_ad_active && this.tagName === "VIDEO" &&
              typeof v === "string" && v.startsWith("blob:")) {
            return;
          }
          return srcDesc.set.call(this, v);
        },
      });
    }
  } catch {}

  // (e) Apply ad-active to every known master gain in real time.
  function applyAdActiveGains(active) {
    if (!window.__interceptify_audioContexts) return;
    for (const ctx of window.__interceptify_audioContexts) {
      try {
        if (ctx.__interceptify_master) {
          ctx.__interceptify_master.gain.setValueAtTime(active ? 0 : 1, ctx.currentTime);
        }
      } catch {}
    }
  }
  // ------------------------------------------------------------------

  // Hook Spotify's internal event-emitter pattern. The xpui code does things
  // like  n.on("adplaying", cb)  and  n.emit("adbreakstart").
  // Spotify's full ad lifecycle (verified via static analysis 2026-04-29):
  //   adrequest -> adresponse -> adbreakstart -> adplay -> adplaying ->
  //   adfirstquartile -> admidpoint -> adended -> adbreakend
  //   Plus: adpause, aderror, adclicked
  // We treat any of the "starting" events as ad-on, "ending" events as ad-off.
  let eventBasedAd = false;
  const AD_START_EVENTS = /^(adrequest|adresponse|adbreakstart|adplay|adplaying|adfirstquartile|admidpoint)$/i;
  const AD_END_EVENTS = /^(adended|adbreakend|aderror)$/i;
  function markAdEvent(eventName) {
    try {
      if (!eventName || typeof eventName !== "string") return;
      if (AD_START_EVENTS.test(eventName)) {
        eventBasedAd = true;
        log("event-emitter ad signal:", eventName);
      } else if (AD_END_EVENTS.test(eventName)) {
        eventBasedAd = false;
      }
    } catch {}
  }
  function tryHookEmitter(proto, methodName) {
    if (!proto || typeof proto[methodName] !== "function" || proto["__interceptify_" + methodName]) return;
    const orig = proto[methodName];
    proto["__interceptify_" + methodName] = true;
    proto[methodName] = function (eventName, handler, ...rest) {
      try {
        const name = typeof eventName === "string" ? eventName : (eventName && eventName.type);
        if ((methodName === "on" || methodName === "addEventListener") &&
            typeof eventName === "string" && typeof handler === "function" &&
            (AD_START_EVENTS.test(eventName) || AD_END_EVENTS.test(eventName))) {
          const wrapped = function (...args) {
            markAdEvent(eventName);
            return handler.apply(this, args);
          };
          return orig.call(this, eventName, wrapped, ...rest);
        }
        markAdEvent(name);
      } catch {}
      return orig.call(this, eventName, handler, ...rest);
    };
  }
  // We don't know the exact emitter class, so probe a few likely candidates
  // late (after Spotify has booted its module graph).
  setInterval(() => {
    try {
      tryHookEmitter(EventTarget && EventTarget.prototype, "dispatchEvent");
      tryHookEmitter(EventTarget && EventTarget.prototype, "addEventListener");
      // Walk a small set of globals looking for emitter-like objects
      for (const k of Object.keys(window)) {
        const v = window[k];
        if (v && typeof v === "object") {
          const proto = Object.getPrototypeOf(v);
          if (proto && typeof proto.emit === "function") tryHookEmitter(proto, "emit");
          if (proto && typeof proto.on === "function") tryHookEmitter(proto, "on");
        }
      }
    } catch {}
  }, 1500);

  // ===================================================================
  // SIGNAL CLASSIFICATION (step 2)
  // Two signal classes, recomputed FRESH every tick with NO memory:
  //   STRONG_PRESENT() — a real audio/video ad is mounted RIGHT NOW. The
  //     ONLY thing allowed to drive the advancing gate. Exact querySelector
  //     over CFG.strongAdSelectors PLUS a per-tick fuzzy test-id Set scoped
  //     STRICTLY to the audio/video-ad prefixes (so a renamed test-id still
  //     matches but companion/banner ids never widen the gate).
  //   WEAK() — ad intent that may LINGER or match the inter-track gap. Arms
  //     mute / moves IDLE->SUSPECTED but can NEVER confirm or advance.
  // ===================================================================

  // Returns the matched strong selector/marker (truthy) or "" if none.
  function STRONG_PRESENT() {
    // (a) exact strong selectors
    for (const s of STRONG_AD_SELECTORS) {
      try { if (document.querySelector(s)) return s; } catch {}
    }
    // (b) fuzzy test-id fallback, scoped to the audio/video-ad prefix set.
    //     Worst case here is an over-MUTE (safe), never an over-skip.
    try {
      const fuzzy = rx(CFG.fuzzyAdTestIdRegex, "i");
      if (fuzzy) {
        const nodes = document.querySelectorAll("[data-testid]");
        for (let i = 0; i < nodes.length; i++) {
          const id = nodes[i].getAttribute("data-testid");
          if (id && fuzzy.test(id)) return "fuzzy:" + id;
        }
      }
    } catch {}
    return "";
  }

  // Returns the matched weak reason (truthy) or "" if none.
  function WEAK() {
    // PRE-PAINT ad signals ONLY — things that genuinely PRECEDE an ad and do
    // NOT persist during normal playback. (A painted ad is caught by
    // STRONG_PRESENT, which CONFIRMS + mutes.) Everything DOM/title-presence
    // based was removed: Spotify keeps a leavebehind/companion node mounted
    // during normal music (we only CSS-hide it), and `class*=Advertisement` /
    // the bare-title heuristic also match on real tracks — those made v2
    // periodically MUTE real music (the "weak-node" over-mute the log caught).
    if (eventBasedAd) return "event:adplaying";
    if (window.__interceptify_instream_ad_until &&
        Date.now() < window.__interceptify_instream_ad_until) {
      return "instream-ad-object";
    }
    return "";
  }

  // Back-compat single-truthy helper retained for debug surface only.
  function isAdPlaying() {
    return STRONG_PRESENT() || WEAK() || null;
  }

  function captureAdPlay(reason) {
    if (!DEBUG_CAPTURE) return;
    try {
      const testIds = [];
      document.querySelectorAll("[data-testid]").forEach((e) => {
        const id = e.getAttribute("data-testid");
        if (id && /ad|promo|sponsor|advert/i.test(id)) testIds.push(id);
      });
      const recentNetwork = (window.__interceptify_sniffer || [])
        .filter((e) => Date.now() - e.ts < 30000)
        .filter((e) => /fetch|xhr-open|perf-resource|segment|manifest/.test(e.kind || ""))
        .slice(-80);
      rememberIntel("adPlays", {
        reason,
        testIds: Array.from(new Set(testIds)).slice(0, 80),
        knownAdSources: Array.from(window.__interceptify_known_ad_sources || []),
        recentNetwork,
      });
    } catch {}
  }

  // --- SURVIVING advancing primitives -------------------------------------
  // ALL of these are reached ONLY through advance() (the single choke point).
  // Each is also SELF-GATING against songs by Spotify's own UI contract, so
  // even a stale strong read can't move a real track.

  // 1. Native skip-forward click. Spotify DISABLES skip-forward on a real
  //    Free track, so the click is a no-op by their own contract. Routes
  //    through safeSkip belt+braces.
  function clickNextTrack() {
    const btn = document.querySelector('[data-testid="' + CFG.skipForwardTestId + '"]');
    if (btn && !btn.disabled && btn.offsetParent !== null) { btn.click(); return true; }
    return false;
  }

  // 2. seek-forward-15 sparse burst (drains a drainable preroll). The button
  //    is ABSENT on songs, so it self-gates. ONE burst inside ONE advance()
  //    call (CFG.seek15Burst clicks @ CFG.seek15BurstSpacingMs) — not a
  //    per-tick spray.
  function spamSeekForward() {
    const btn = document.querySelector('[data-testid="' + CFG.seekForward15TestId + '"]');
    if (!btn || btn.offsetParent === null) return false;
    // Fire the WHOLE burst SYNCHRONOUSLY within this one advance() tick. v1 used
    // setTimeout spacing, but a deferred click can land AFTER the ad ends and
    // seek a real podcast/track (and bypasses every advance() gate). advance()
    // has already vetted THIS exact tick (CONFIRMED + strong + now-playing==ad),
    // so do it all now and never let a click cross the transition.
    const n = Math.max(1, CFG.seek15Burst | 0);
    let fired = false;
    for (let i = 0; i < n; i++) {
      try {
        const b = document.querySelector('[data-testid="' + CFG.seekForward15TestId + '"]');
        if (b && b.offsetParent !== null) { b.click(); fired = true; } else break;
      } catch {}
    }
    return fired;
  }

  // 3. Ad-video-scoped 'ended'. Spotify's video takeover ad is a <video> with
  //    a blob: src. We dispatch 'ended' ONLY on the specific ad <video> (blob
  //    src AND a sibling strong marker present THIS tick) — never a blanket
  //    querySelectorAll('video') (that was the v1 over-skip vector).
  function killVideoAd() {
    if (!STRONG_PRESENT()) return false; // require a strong marker this tick
    const vids = document.querySelectorAll("video");
    let acted = false;
    for (let i = 0; i < vids.length; i++) {
      const v = vids[i];
      let src = "";
      try { src = v.currentSrc || v.src || ""; } catch {}
      if (typeof src !== "string" || !src.startsWith("blob:")) continue;
      if (!isFinite(v.duration) || v.duration <= 0) continue;
      try { v.muted = true; v.volume = 0; } catch {}
      try { v.currentTime = v.duration - 0.05; } catch {}
      try { v.dispatchEvent(new Event("ended", { bubbles: true })); } catch {}
      acted = true;
    }
    return acted;
  }
  // -------------------------------------------------------------------------

  // Spotify 1.2.88+ uses Web Audio API rather than an <audio> element, so
  // setting .muted on media elements is a no-op (there ARE no media elements
  // in the DOM). The reliable mute is to click Spotify's own volume-bar
  // mute button. We track whether _we_ muted so we don't un-mute the user's
  // own manual mute on ad-end.
  function _muteButton() {
    return document.querySelector('[data-testid="' + (CFG.muteButtonTestId || "volume-bar-toggle-mute-button") + '"]');
  }
  function _isCurrentlyMutedInUI() {
    // The button toggles an icon child; the most reliable way to tell the
    // state cross-locale is to look at aria-pressed, then fall back to icon
    // class names. Returns null if we can't tell.
    const btn = _muteButton();
    if (!btn) return null;
    const ap = btn.getAttribute("aria-pressed");
    if (ap === "true") return true;
    if (ap === "false") return false;
    // Heuristic: the muted-state icon's path tends to include "mute" or
    // a slashed-speaker SVG; otherwise volume-up/-down/-off.
    const svg = btn.querySelector("svg");
    if (svg) {
      const html = svg.outerHTML;
      if (/mute|VolumeOff/i.test(html)) return true;
    }
    return null;
  }
  let _weMuted = false;
  const _mediaVolumeBeforeMute = new WeakMap();
  function muteAllAudio(shouldBeMuted) {
    // Best-effort no-op fallback for any media elements that DO exist
    // (rare in modern Spotify but cheap to keep).
    document.querySelectorAll("audio, video").forEach((el) => {
      try {
        if (shouldBeMuted) {
          if (!_mediaVolumeBeforeMute.has(el)) {
            _mediaVolumeBeforeMute.set(el, { muted: el.muted, volume: el.volume });
          }
          el.muted = true;
          el.volume = 0;
        } else {
          const prior = _mediaVolumeBeforeMute.get(el);
          if (prior) {
            el.muted = prior.muted;
            el.volume = prior.volume;
            _mediaVolumeBeforeMute.delete(el);
          } else {
            el.muted = false;
          }
        }
      } catch {}
    });
    const btn = _muteButton();
    if (!btn) return;
    const uiMuted = _isCurrentlyMutedInUI();
    if (shouldBeMuted) {
      // Mute only if not already muted
      if (uiMuted === false || (uiMuted === null && !_weMuted)) {
        btn.click();
        _weMuted = true;
      }
    } else {
      // Un-mute only if WE muted (don't fight the user's manual mute)
      if (_weMuted) {
        if (uiMuted !== false) btn.click();
        _weMuted = false;
      }
    }
  }

  function setBadgeState(state) {
    const b = document.getElementById("interceptify-badge");
    if (!b) return;
    const palette = {
      idle: "#1ed760",    // green — normal
      ad:   "#ff3b30",    // red — ad detected, blocking
      blocked: "#ffa500", // orange — network-level block just fired
    }[state] || "#1ed760";
    b.style.background = palette;
    b.style.boxShadow = `0 0 6px ${palette}`;
    b.title = "Interceptify: " + state;
  }

  let wasAd = null; // last-seen selector or null — badge/stats ONLY, not a driver
  let stats = { detections: 0, lastDetection: null, lastSelector: null,
                fetchBlocked: 0, xhrBlocked: 0 };

  // ===================================================================
  // FSM (step 3) — adState is the SINGLE source of truth. Replaces v1's
  // tangle of wasAd + eventBasedAd-as-truth + instream-window-as-truth.
  //   IDLE -> SUSPECTED -> CONFIRMED -> SKIPPING -> COOLDOWN -> IDLE
  // ===================================================================
  let adState = "IDLE";
  let cooldownUntil = 0;      // advance() hard-disabled while Date.now() < this
  let lastAdvanceAt = 0;      // global anti-spin timestamp
  let lastStrongTickAt = 0;   // last tick STRONG_PRESENT() was true
  let suspectSinceAt = 0;     // for the suspectMaxMs mute-wedge bound
  let noStrongTicks = 0;      // consecutive ticks with no strong marker
  let strongStreak = 0;       // consecutive ticks WITH a strong marker (debounce vs 1-tick flicker)
  let preAdNowPlaying = null; // fp0 captured at skip-issue (SKIPPING entry)
  let currentAdKey = "";      // adKey for the in-flight ad
  let currentAdFp = null;     // now-playing fingerprint of the confirmed ad — advance() refuses once this changes
  let confirmedSinceAt = 0;   // when CONFIRMED was first entered (maxAdMs ceiling)
  const _satisfiedAdKeys = new Set();      // adKeys whose skip was verified done
  const _adKeyRetries = Object.create(null); // adKey -> remaining retry budget
  let lastSkipIssueAt = 0;    // when the last skip was issued (skipRetryMs gate)

  function fpEqual(a, b) {
    if (!a || !b) return false;
    return a.documentTitle === b.documentTitle && a.title === b.title && a.subtitle === b.subtitle;
  }
  // Does the current now-playing fingerprint look like an ad? (used to refuse
  // declaring a skip "successful" while still on an ad).
  function fpLooksLikeAd(fp) {
    try {
      if (!fp) return false;
      if (/advert/i.test(fp.title || "")) return true;
      if (/advert/i.test(fp.subtitle || "")) return true;
    } catch {}
    return false;
  }

  // Mint a stable adKey on the IDLE/SUSPECTED -> CONFIRMED edge. Prefer the
  // in-stream summarizeAdObject key when available; else DOM selector + fp.
  function mintAdKey(strongMarker) {
    try {
      const api = window.__interceptify_instream_api;
      if (api && api.inStreamAd) {
        const k = inStreamAdKey(api.inStreamAd);
        if (k) return "instream:" + k;
      }
    } catch {}
    const fp = nowPlayingSnapshot();
    return "dom:" + (strongMarker || "?") + "|" + (fp.title || "") + "|" + (fp.subtitle || "");
  }

  // ===================================================================
  // ADVANCE — the ONE choke point (step 4). Every advancing action lives
  // here. Five stacked gates; any failure -> log "advance-suppressed" and
  // return. A real song satisfies none of them.
  // ===================================================================
  function advance(adKey, source) {
    try {
      // (a) state — ONLY CONFIRMED may advance. SUSPECTED/SKIPPING/COOLDOWN/IDLE never.
      if (adState !== "CONFIRMED") {
        snifferLog("advance-suppressed", { source, reason: "state:" + adState });
        return false;
      }
      // (b) present-tick strong DOM, re-queried NOW with no memory.
      if (!STRONG_PRESENT()) {
        snifferLog("advance-suppressed", { source, reason: "no-strong-present" });
        return false;
      }
      // (b2) KEYSTONE no-overskip gate: the now-playing item must STILL be the
      //      confirmed ad. If the fingerprint has moved to a different,
      //      non-ad-looking track, NEVER advance — even if a strong ad NODE is
      //      still lingering in the DOM one render past the audio transition.
      if (currentAdFp) {
        const fpNow = nowPlayingSnapshot();
        if (!fpEqual(fpNow, currentAdFp) && !fpLooksLikeAd(fpNow)) {
          snifferLog("advance-suppressed", { source, reason: "now-playing-moved-off-ad" });
          return false;
        }
      }
      // (c) post-ad/post-skip cooldown lock.
      if (Date.now() < cooldownUntil) {
        snifferLog("advance-suppressed", { source, reason: "cooldown-window" });
        return false;
      }
      // (e1) anti-spin.
      if (Date.now() - lastAdvanceAt < CFG.minAdvanceIntervalMs) {
        snifferLog("advance-suppressed", { source, reason: "anti-spin" });
        return false;
      }
      // (e2) per-adKey idempotency + retry budget.
      const key = adKey || currentAdKey || "?";
      if (_satisfiedAdKeys.has(key)) {
        snifferLog("advance-suppressed", { source, reason: "adKey-satisfied" });
        return false;
      }
      if (!(key in _adKeyRetries)) _adKeyRetries[key] = CFG.maxSkipRetries;
      if (_adKeyRetries[key] <= 0) {
        snifferLog("advance-suppressed", { source, reason: "retry-budget-exhausted" });
        return false;
      }
      // (d) actions — reached ONLY after CONFIRMED + strong + now-playing==ad.
      let acted = false;
      // PREFERRED: in-stream skipToNext() once per unique ad key. The L1 wrap
      // also fires it on neutralize; this is a belt. Song-safe: gated above.
      try {
        const api = window.__interceptify_instream_api;
        if (api && typeof api.skipToNext === "function") {
          window.__interceptify_neutralized_ads = window.__interceptify_neutralized_ads || new Set();
          const skKey = "advance:" + key;
          if (!window.__interceptify_neutralized_ads.has(skKey)) {
            window.__interceptify_neutralized_ads.add(skKey);
            api.skipToNext();
            acted = true;
          }
        }
      } catch {}
      // Native skip-forward click (self-gates: disabled/absent on songs).
      if (clickNextTrack()) acted = true;
      // seek-forward-15 synchronous burst (absent on songs -> no-op).
      if (spamSeekForward()) acted = true;
      // ad-video-scoped 'ended' (blob src + strong marker this tick).
      if (killVideoAd()) acted = true;
      // MediaSource endOfStream — OFF by default last resort.
      if (!acted && CFG.enableMediaSourceEndOfStream) {
        if (killCurrentMediaSources()) acted = true;
      }
      // DOM-spray last resort — DELETED family, only behind the flag + gate.
      if (!acted && CFG.enableDomSprayLastResort) {
        try { domSprayLastResort(); acted = true; } catch {}
      }

      if (!acted) {
        snifferLog("advance-suppressed", { source, reason: "no-primitive-fired" });
        return false;
      }
      // Success bookkeeping -> SKIPPING.
      lastAdvanceAt = Date.now();
      lastSkipIssueAt = Date.now();
      _adKeyRetries[key] -= 1;
      cooldownUntil = Date.now() + CFG.cooldownMs; // lock the transition window
      preAdNowPlaying = nowPlayingSnapshot();
      currentAdKey = key;
      adState = "SKIPPING";
      snifferLog("advance", { source, adKey: key, retriesLeft: _adKeyRetries[key] });
      log("advance:", source, "key=" + key.slice(0, 40));
      return true;
    } catch (e) {
      snifferLog("advance-error", { source, error: String(e && e.message || e) });
    }
    return false;
  }

  // The v1 blind-seek family lives ONLY here, behind CFG.enableDomSprayLastResort
  // (default false) AND the full advance() gate. It is NOT wired on by default.
  function domSprayLastResort() {
    try {
      const sel = CFG.progressInputSelector || '[data-testid="playback-progressbar"] input[type="range"]';
      document.querySelectorAll(sel).forEach((inp) => {
        try {
          const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
          setter.call(inp, inp.max);
          inp.dispatchEvent(new Event("input", { bubbles: true }));
          inp.dispatchEvent(new Event("change", { bubbles: true }));
        } catch {}
      });
    } catch {}
  }

  // ===================================================================
  // MUTE / GAIN LIFECYCLE (step 7)
  //   ARM   — on SUSPECTED or CONFIRMED: click-mute. gain=0 + ad_active
  //           ONLY in CONFIRMED (preserves the 1.5.3 minimized-stall fix).
  //   HOLD  — during COOLDOWN: never toggle.
  //   RESTORE (releaseAdState) — gain->1 BEFORE ad_active=false BEFORE
  //           muteAllAudio(false).
  // ===================================================================
  function armMute() {
    try { const was = _weMuted; muteAllAudio(true); if (_weMuted && !was) _diagLog("MUTED"); } catch {}
  }
  function armAdActive() {
    try {
      const was = window.__interceptify_ad_active;
      window.__interceptify_ad_active = true;
      applyAdActiveGains(true);
      if (!was) _diagLog("GAIN0");
    } catch {}
  }
  function releaseAdState(reason) {
    try { _diagLog("release", { reason: reason }); } catch {}
    try { log("ad cleanup:", reason); } catch {}
    try { setBadgeState("idle"); } catch {}
    // ORDER MATTERS: raise gains to 1 FIRST (audio audible before we disarm the
    // video.play/src hijacks), THEN clear ad_active, THEN the click-unmute. Each
    // step in its OWN try so a throw in one can't strand the next (e.g. leave
    // the next song muted because applyAdActiveGains threw).
    try { applyAdActiveGains(false); } catch {}
    try { window.__interceptify_ad_active = false; } catch {}
    try { muteAllAudio(false); } catch {}
    try { clearExpiredSuppressionCss(); } catch {}
    currentAdFp = null;
    confirmedSinceAt = 0;
  }

  function cleanupExpiredTransientAd(reason) {
    // Detection + restore pass wired to visibilitychange/focus/pageshow and
    // also called each tick. No longer drives the instream window as truth.
    try {
      clearExpiredSuppressionCss();
      runWatchdog(reason || "cleanup");
    } catch {}
  }

  function scheduleTransientAdCleanup(ms, reason) {
    try {
      setTimeout(() => cleanupExpiredTransientAd(reason), ms || 3500);
    } catch {}
  }

  // Watchdog (~2s) + the visibility hooks both call this. Force-restore if
  // ad_active is stuck on with no strong marker, and force gain->1 if a
  // tracked master gain is still 0 while ad_active is false.
  function runWatchdog(reason) {
    try {
      const strong = STRONG_PRESENT();
      // Hard ceiling: an "ad" that persists longer than any real ad is a stuck
      // STRONG false-positive (e.g. a fuzzy match on some persistent node).
      // Force-release REGARDLESS of strong so gain/mute can never be pinned
      // forever — the fuzzy matcher's worst case stays an over-mute, not a
      // permanent one.
      if (window.__interceptify_ad_active && confirmedSinceAt &&
          Date.now() - confirmedSinceAt > CFG.maxAdMs) {
        log("watchdog force-restore (ad_active longer than maxAdMs)");
        adState = "IDLE"; cooldownUntil = 0;
        releaseAdState("watchdog-maxad:" + reason);
        return;
      }
      if (window.__interceptify_ad_active && !strong) {
        if (!runWatchdog._noStrongSince) runWatchdog._noStrongSince = Date.now();
        if (Date.now() - runWatchdog._noStrongSince > CFG.forceRestoreMs) {
          log("watchdog force-restore (ad_active but no strong > forceRestoreMs)");
          adState = "IDLE";
          cooldownUntil = 0;
          releaseAdState("watchdog:" + reason);
          runWatchdog._noStrongSince = 0;
        }
      } else {
        runWatchdog._noStrongSince = 0;
      }
      // Second clause: ad_active is false but a tracked master gain is still 0
      // OR our click-mute is still engaged -> restore BOTH so a real song can
      // never stay silent (closes the watchdog-restores-gain-but-not-mute gap).
      if (!window.__interceptify_ad_active) {
        let forced = false;
        if (window.__interceptify_audioContexts) {
          for (const ctx of window.__interceptify_audioContexts) {
            try {
              const g = ctx.__interceptify_master;
              if (g && g.gain && g.gain.value === 0) { g.gain.setValueAtTime(1, ctx.currentTime); forced = true; }
            } catch {}
          }
        }
        if (forced) log("watchdog forced master gain -> 1");
        if (_weMuted) { try { muteAllAudio(false); } catch {} }
      }
    } catch {}
  }

  try {
    setInterval(() => runWatchdog("interval"), 2000);
    document.addEventListener("visibilitychange", () => cleanupExpiredTransientAd("visibilitychange"), true);
    window.addEventListener("focus", () => cleanupExpiredTransientAd("focus"), true);
    window.addEventListener("pageshow", () => cleanupExpiredTransientAd("pageshow"), true);
  } catch {}

  // ===================================================================
  // TICK (steps 3 + 9) — evaluate the FSM, arm mute, route advancing
  // through advance(), verify the skip via the now-playing fingerprint.
  // ===================================================================
  function check() {
    const strongMarker = STRONG_PRESENT();
    const strong = !!strongMarker;
    const weakReason = WEAK();
    const weak = !!weakReason;
    if (strong) lastStrongTickAt = Date.now();
    noStrongTicks = strong ? 0 : (noStrongTicks + 1);
    strongStreak = strong ? (strongStreak + 1) : 0;
    // DEBOUNCE: a strong ad marker must persist >= confirmTicks consecutive
    // ticks before we CONFIRM (and mute). A 1-tick flicker of [ad-controls] on
    // a real song can no longer trigger a spurious mute; a genuine ad's
    // controls easily last >= confirmTicks (~1s at the default 2 ticks).
    const confirmReady = strong && strongStreak >= (CFG.confirmTicks || 2);

    switch (adState) {
      case "IDLE": {
        if (confirmReady) enterConfirmed(strongMarker);
        else if (weak) enterSuspected(weakReason);
        break;
      }
      case "SUSPECTED": {
        if (confirmReady) { enterConfirmed(strongMarker); break; }
        // The in-stream payload is skipped by L1's OWN neutralize -> skipToNext
        // (keyed to the real ad object). SUSPECTED only MUTES here; it never
        // advances, so a lingering instream bridge-window can't skip a real track.
        if (!weak) {
          // all signals cleared -> short cooldown then IDLE; un-mute.
          enterCooldown("suspect-clear", /*unmute*/ true);
          break;
        }
        // mute-wedge bound: a weak-only signal that never escalates.
        if (suspectSinceAt && Date.now() - suspectSinceAt > CFG.suspectMaxMs) {
          log("suspectMaxMs exceeded — force IDLE + un-mute");
          adState = "IDLE";
          releaseAdState("suspect-max");
        }
        break;
      }
      case "CONFIRMED": {
        // NOTE: do NOT push cooldownUntil into the future here — that would
        // block this ad's own first advance. cooldownUntil is set into the
        // future only (a) inside advance() when a skip fires, and (b) on
        // entry to COOLDOWN (which fires the tick AFTER the last strong tick,
        // so the lock trails the last strong tick by >= cooldownMs).
        if (!strong) { enterCooldown("strong-cleared", /*unmute*/ false); break; }
        // arm + attempt advance through the choke point.
        armMute();
        armAdActive();
        advance(currentAdKey, "confirmed");
        break;
      }
      case "SKIPPING": {
        const fpN = nowPlayingSnapshot();
        // Skip verified when now-playing moved to a non-ad track — REGARDLESS of
        // a lingering strong NODE. This routes us to cooldown (advance locked)
        // instead of re-issuing a skip onto the real song that just started.
        const verifiedAdvance = !fpEqual(fpN, preAdNowPlaying) && !fpLooksLikeAd(fpN);
        if (verifiedAdvance) {
          if (currentAdKey) _satisfiedAdKeys.add(currentAdKey);
          // The real (non-ad) track is verifiably playing now, so UN-MUTE
          // immediately instead of holding the mute on it for a full cooldown
          // (that was an audible stutter + a mini song-mute). The advance-lock
          // still holds via cooldownUntil, so over-skip protection is untouched.
          enterCooldown("verified-advance", /*unmute*/ true);
          break;
        }
        if (!strong) {
          // strong markers gone but fp not yet verified-changed: go to
          // cooldown (advance stays locked) and let verification settle.
          enterCooldown("strong-cleared-skipping", /*unmute*/ false);
          break;
        }
        // strong still present: re-issue ONE retry after skipRetryMs, capped.
        if (Date.now() - lastSkipIssueAt >= CFG.skipRetryMs) {
          const key = currentAdKey || mintAdKey(strongMarker);
          if ((_adKeyRetries[key] || 0) > 0) {
            adState = "CONFIRMED"; // advance() requires CONFIRMED; it re-locks
            advance(key, "retry");
          } else {
            // cap reached: STOP advancing, fall back to mute-only.
            snifferLog("skip-cap-reached", { adKey: key });
            armMute(); armAdActive();
          }
        }
        break;
      }
      case "COOLDOWN": {
        // HARD advance lock. Multi-ad break: a NEW strong marker with a
        // DIFFERENT adKey -> CONFIRMED WITHOUT un-muting; prior advance lock
        // (cooldownUntil) still holds until it expires.
        if (strong) {
          const k = mintAdKey(strongMarker);
          if (k !== currentAdKey && !_satisfiedAdKeys.has(k)) {
            currentAdKey = k;
            currentAdFp = nowPlayingSnapshot();
            confirmedSinceAt = Date.now();
            adState = "CONFIRMED";
            armMute(); armAdActive();
            setBadgeState("ad");
            break;
          }
          // same ad flickering — stay in cooldown, hold mute.
        }
        if (Date.now() >= cooldownUntil && !strong) {
          adState = "IDLE";
          releaseAdState("cooldown-elapsed");
          currentAdKey = "";
          preAdNowPlaying = null;
        }
        break;
      }
    }

    // badge/stats back-compat (no longer drives actions).
    const detected = strongMarker || weakReason || null;
    if (detected && !wasAd) {
      stats.detections++;
      stats.lastDetection = new Date().toISOString();
      stats.lastSelector = detected;
      captureAdPlay(detected);
    }
    wasAd = detected;
  }

  function enterSuspected(reason) {
    adState = "SUSPECTED";
    suspectSinceAt = Date.now();
    var _nps = ""; try { _nps = (nowPlayingSnapshot().title || "").slice(0, 32); } catch {}
    _diagLog("SUSPECTED", { reason: reason, np: _nps });
    log("ad suspected via:", reason);
    setBadgeState("blocked");
    armMute(); // mute is always-safe; NO ad_active / gain=0 here.
  }
  function enterConfirmed(strongMarker) {
    const fresh = adState === "IDLE" || adState === "SUSPECTED";
    if (fresh) {
      currentAdKey = mintAdKey(strongMarker);
      currentAdFp = nowPlayingSnapshot(); // the ad's now-playing fp; advance() refuses once it changes
      confirmedSinceAt = Date.now();
    }
    adState = "CONFIRMED";
    var _npc = ""; try { _npc = (nowPlayingSnapshot().title || "").slice(0, 32); } catch {}
    _diagLog("CONFIRMED", { sel: String(strongMarker), np: _npc });
    log("ad confirmed via:", strongMarker);
    setBadgeState("ad");
    armMute();
    armAdActive(); // gain=0 + video hijacks armed ONLY in CONFIRMED.
  }
  function enterCooldown(reason, unmute) {
    adState = "COOLDOWN";
    cooldownUntil = Math.max(cooldownUntil, Date.now() + CFG.cooldownMs);
    _diagLog("COOLDOWN", { reason: reason, unmute: !!unmute });
    log("cooldown:", reason);
    setBadgeState("idle");
    if (unmute) {
      // only restore when no strong marker — never un-mute mid-ad.
      if (!STRONG_PRESENT()) releaseAdState("cooldown:" + reason);
    }
    // HOLD mute/gain otherwise; the COOLDOWN->IDLE transition restores them.
  }

  // Debug surface for DevTools. Open Spotify, Ctrl+Shift+I, type:
  //   __interceptify.status()       -> detection counts + last hit
  //   __interceptify.scanAds()      -> list any ad-shaped elements right now
  //   __interceptify.testIds()      -> all data-testid values currently in DOM
  window.__interceptify = {
    version: "2026-06-14-v2",
    debugCapture: DEBUG_CAPTURE,
    stats: () => ({ ...stats }),
    state: () => adState,
    instreamModuleIds: () => (window.__interceptify_instream_module_ids || []).slice(),
    // Comprehensive live snapshot — every identifier in one call, for CDP capture.
    // Built to diagnose "ad + song playing at once" (concurrent audio streams):
    // lists ALL MediaSources, <audio>/<video> elements, AudioContexts + master
    // gains, the in-stream ad object, classified ad sources, and recent network.
    snapshot() {
      const safe = (fn, d) => { try { return fn(); } catch { return d; } };
      const mediaEls = [];
      safe(() => document.querySelectorAll("audio, video").forEach((el) => {
        mediaEls.push({
          tag: el.tagName,
          src: String(el.currentSrc || el.src || "").slice(0, 140),
          duration: el.duration, currentTime: el.currentTime,
          paused: el.paused, ended: el.ended, muted: el.muted, volume: el.volume,
          readyState: el.readyState, playbackRate: el.playbackRate,
        });
      }));
      const mediaSources = [];
      safe(() => window.__interceptify_mediasources && window.__interceptify_mediasources.forEach((ms) => {
        mediaSources.push({ readyState: ms.readyState, url: String(ms.__intercept_url || "").slice(0, 140) });
      }));
      const audioContexts = [];
      safe(() => window.__interceptify_audioContexts && window.__interceptify_audioContexts.forEach((c) => {
        audioContexts.push({ state: c.state, currentTime: c.currentTime, masterGain: c.__interceptify_master ? c.__interceptify_master.gain.value : "(none)" });
      }));
      return {
        ts: Date.now(), version: this.version,
        adState: safe(() => adState, "?"), adActive: !!window.__interceptify_ad_active,
        weMuted: safe(() => _weMuted, "?"), cooldownActive: safe(() => Date.now() < cooldownUntil, null),
        docTitle: document.title, nowPlaying: safe(() => nowPlayingSnapshot(), {}),
        strongPresent: safe(() => STRONG_PRESENT(), "?"), weak: safe(() => WEAK(), "?"),
        mediaElements: mediaEls, mediaSources, audioContexts,
        instreamModuleIds: window.__interceptify_instream_module_ids || [],
        knownAdSources: Array.from(window.__interceptify_known_ad_sources || []),
        instreamWindowActiveMs: safe(() => Math.max(0, (window.__interceptify_instream_ad_until || 0) - Date.now()), 0),
        diagLog: (window.__interceptify_diag_log || []).slice(-40),
        errors: window.__interceptify_errors || [],
        // network/ad-intel history (only populated when debug capture is on)
        sniffer: safe(() => (window.__interceptify_sniffer || []).slice(-80), []),
        metaLog: safe(() => (window.__interceptify_meta_log || []).slice(-15), []),
        adIntel: safe(() => ({
          instreamAds: (window.__interceptify_ad_intel && window.__interceptify_ad_intel.instreamAds || []).slice(-15),
          blockedSources: (window.__interceptify_ad_intel && window.__interceptify_ad_intel.blockedSources || []).slice(-15),
          blockedSegments: (window.__interceptify_ad_intel && window.__interceptify_ad_intel.blockedSegments || []).slice(-15),
          adPlays: (window.__interceptify_ad_intel && window.__interceptify_ad_intel.adPlays || []).slice(-8),
        }), null),
      };
    },
    status() {
      const s = {
        ...stats,
        adState,
        cooldownActive: Date.now() < cooldownUntil,
        adActive: !!window.__interceptify_ad_active,
        instreamModuleIds: (window.__interceptify_instream_module_ids || []).slice(),
      };
      console.table(s);
      return s;
    },
    knownAdSources() {
      return Array.from(window.__interceptify_known_ad_sources || []);
    },
    adIntel() {
      return {
        ...(window.__interceptify_ad_intel || {}),
        knownAdSources: Array.from(window.__interceptify_known_ad_sources || []),
      };
    },
    lastAdPlay() {
      const plays = window.__interceptify_ad_intel && window.__interceptify_ad_intel.adPlays || [];
      return plays[plays.length - 1] || null;
    },
    scanAds() {
      const out = [];
      for (const s of STRONG_AD_SELECTORS.concat(VISUAL_AD_SELECTORS)) {
        const els = document.querySelectorAll(s);
        if (els.length) out.push({ selector: s, count: els.length });
      }
      console.table(out);
      return out;
    },
    testIds() {
      const ids = new Set();
      document.querySelectorAll("[data-testid]").forEach(e =>
        ids.add(e.getAttribute("data-testid")));
      const arr = [...ids].sort();
      console.log(`${arr.length} unique test-ids on page`);
      arr.forEach(t => { if (/ad|promo|sponsor/i.test(t)) console.log("  AD-ISH:", t); });
      return arr;
    },
  };

  // Poll every CFG.tickMs (default 500ms). Mutation observers are flakier
  // across Spotify rebuilds because the mounted component changes; a simple
  // poll is more robust.
  setInterval(check, CFG.tickMs || 500);
  log("loaded (v2 FSM)");
})();
