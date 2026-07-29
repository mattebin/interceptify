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
  // Named, so the defaults are a thing code and tests can refer to. They used
  // to be an anonymous literal inside Object.assign(), which meant a use site
  // wanting "the default for X" had to restate the value and drift from it.
  const DEFAULTS = {
    // ---- timing ----
    tickMs: 500,
    cooldownMs: 1500,            // post-ad/post-skip advancing lockout
    confirmTicks: 2,             // a strong ad marker must persist >= this many ticks before CONFIRM+mute (kills 1-tick flickers)
    suspectMaxMs: 8000,          // force un-mute if weak-only never escalates
    skipRetryMs: 900,
    maxSkipRetries: 3,
    minAdvanceIntervalMs: 700,   // global anti-spin
    // How long after ANY queue advance a bare format===AUDIO in-stream object
    // stops counting as self-sufficient proof and has to be corroborated. Guards
    // the one over-skip case the pre-paint fast path could not see: a late or
    // prefetched read of the break we just handled, arriving while a real song
    // has already started.
    authoritativeAfterAdvanceMs: 2500,
    forceRestoreMs: 4000,        // watchdog: force gain/mute restore if ad_active but no strong
    maxAdMs: 90000,              // hard ceiling: force-release if an "ad" persists longer than any real ad
    seek15Burst: 4,
    // (seek15BurstSpacingMs is gone: the burst became synchronous inside one
    // advance() tick, because a deferred click could land after the ad ended and
    // seek a real track. There is no spacing left to configure, and a knob that
    // does nothing reads as tried-and-didn't-help when the truth is never-applied.)
    // Locale-agnostic ad-text markers matched against now-playing
    // title/subtitle/documentTitle to recognize "still on an ad" when the
    // language isn't English. Build/locale-volatile -> externalized.
    adTextMarkers: "advert|annons|reklam|reclame|werb|anunci|publici|annonce|mainos|reklaam|реклама|sponsor",
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
    // (weakOnlySelectors is gone. Weak signals are derived from fuzzyAdTestIdRegex
    // matching with no strong selector present, so the list was never read - it
    // published four selectors that looked like they controlled the mute-only
    // path and controlled nothing. The lingering companion/leavebehind nodes it
    // named are covered by visualHideSelectors below.)
    visualHideSelectors: [
      '[data-testid="context-item-info-ad-title"]',
      '[data-testid="context-item-info-ad-subtitle"]',
      '[data-testid="context-item-info"][aria-label*="Advertisement" i]',
      '[data-testid="ad-controls"]',
      '[data-testid="ad-countdown-timer"]',
      '[data-testid="embedded-ad"]',
      '[data-testid="embedded-ad-creative-link"]',
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
    playPauseTestId: "control-button-playpause",   // used by selftest to establish playback
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
    inspectMode: false,                 // PASSIVE: detect+overlay only, NO skip/mute/hide (so ads stay on screen to Alt+click)
    // ---- fast in-stream skip (audio ads) ----
    enableInStreamPoll: true,           // proactive getInStreamAd() poll -> skip at ad-load, not the 500ms tick
    inStreamPollMs: 80,                 // in-stream poll cadence
    inStreamSkipLockMs: 300,            // short post-skip self-lock (decoupled from the 1500ms FSM cooldown) -> back-to-back multi-ad skips
    // ---- TOTAL BLOCK (SpotX-style pre-play kill) ----
    totalBlock: true,                   // call the ads connector's increaseStreamTime(-1e11) so ad breaks never SCHEDULE (proven SpotX lever). FSM skip+mute stays as the fallback (SSAI + any build where this lever moves).
    streamTimeKillMs: 10000,            // re-apply the stream-time push on this interval (defends vs server ad-state resets)
    streamTimeKillValue: -100000000000, // -1e11: pushes core stream-time so the ad-break threshold is never crossed
    killAdEndpoints: true,              // point the ad-STATE pusher + per-slot ad-SERVER at a dead URL so the client can't be told to play / can't fetch an ad (live-tested stable). This is the real prevention lever (stream-time didn't prevent server-scheduled ads).
    deadAdEndpoint: "https://localhost.invalid/no-ads",
    // Spotify's OWN slot ids, read off the live bundle's *_SLOT_ID constants
    // (2026-07-29, 1.2.94): stream, preroll, sponsored-playlist, leaderboard,
    // hpto, embedded-npv, embedded-playlist, embedded-playlist-leavebehind,
    // podcast-preroll, podcast-postroll, podcast-midroll-1..5.
    //
    // The audio slot is "stream". This list used to lead with "streaming",
    // which is not a slot Spotify has - so every clearSlot() call for the one
    // slot that matters addressed nothing, and an ad already queued when the
    // gate closed was never flushed. Confirmed twice: 25/25 delivered in-stream
    // ads in this install's captures carry slot "stream", and the live bundle
    // defines STREAM_SLOT_ID = "stream" with no "streaming" anywhere.
    //
    // adSlotDiscovery below re-reads these from the bundle at runtime, so the
    // list is a fallback rather than the source of truth. A hard-coded alias is
    // exactly what went stale here.
    adSlots: ["stream", "preroll", "sponsored-playlist", "leaderboard", "hpto",
              "embedded-npv", "embedded-playlist", "embedded-playlist-leavebehind",
              "podcast-preroll", "podcast-postroll",
              "podcast-midroll-1", "podcast-midroll-2", "podcast-midroll-3",
              "podcast-midroll-4", "podcast-midroll-5"],
    // The slot that carries interruptive audio between tracks. Cleared first and
    // confirmed; the rest are best-effort.
    primaryAdSlot: "stream",
    adSlotDiscovery: true,              // re-read *_SLOT_ID constants from the live bundle
    adSlotIdRegex: "([A-Z_]*SLOT[A-Z_]*)\\s*[:=]\\s*[\"']([^\"']+)[\"']",
    adSlotDiscoveryIntervalMs: 2000,    // floor between full module sweeps while no usable primary slot has been found
    // Discovery only helped for slots we DIDN'T already name. If Spotify renames
    // the interruptive audio slot itself - the "streaming" -> "stream" failure
    // again, in the other direction - the new name was merely appended to the
    // list while the dead configured name stayed primary: cleared first,
    // acknowledged first, and the only one readiness keyed off. Discovery that
    // cannot correct the one value that actually matters is not dynamic.
    //
    // So: when the configured primary is absent from a non-empty discovered set,
    // promote the discovered slot that matches this pattern. Podcast slots are
    // excluded because they carry episode-scoped ads, not the between-track
    // audio break, and one of them would otherwise win on a plain /stream/ test.
    primarySlotRegex: "^(?!podcast)[a-z-]*stream[a-z-]*$",
    // ---- snapshot-build ads-connector resurrection (Spotify 1.2.93+ V8 snapshot) ----
    snapshotConnector: true,            // rebuild ads-connector access from window.__webpack_modules__ when the closure require is trapped (chunk.push no longer threads it). Powers adEnabledKill + killAdEndpoints + overrideSkip on snapshot builds.
    adEnabledKill: true,                // THE MASTER PREVENTION LEVER. putState('ad_enabled','false') on the core ad-scheduler state stops ad breaks from being SCHEDULED at all (not reactively skipped). Live-proven on 1.2.93: 10 forced skips that previously triggered an ad -> 0 ads. Re-applied fast to survive product-state refreshes re-pushing ad_enabled:true.
    adEnabledKillMs: 1000,              // fast re-apply cadence for ad_enabled=false (it held ~8s untouched, so 1s is safe headroom)
    clearAdSlots: true,                 // also clearSlot() the ad slots each cycle: ad_enabled=false only stops NEW scheduling, so an ad already queued before the block took hold (e.g. one pre-queued at startup) still needs flushing. With this on, 0/14 forced skips produced an ad (vs 1/14 pre-queued without it).
    clearSlotReason: 1,
    // ---- SELF-HEALING: never hard-code the core's ad-gate key name ----
    // `ad_enabled` is Spotify-internal and can be renamed by any client update.
    // We read the LIVE ad state and match its key names against these patterns,
    // so a rename is auto-discovered instead of silently disabling the block.
    adGateKeyPatterns: ["^ad[_-]?enabled$", "^ads?[_-]?enabled$", "^enable[_-]?ads?$"],
    // Used only when discovery finds nothing. Written here rather than as a
    // literal at the use site so every knob has exactly one declared default.
    adGateFallbackKeys: ["ad_enabled"],
    adGateVerify: true,                 // read the state back and confirm every gate key really reads "false" (a write that doesn't stick = drift -> logged as ad-gate-FAILED)
    // ---- freshness of the evidence readiness is built on ----
    // "verified" and "acknowledged" were both latched booleans with no expiry.
    // A gate read that succeeded once stayed authoritative even if every later
    // getAdState() rejected or hung, and a slot clear acknowledged once stayed
    // acknowledged even when the next clear never resolved. Both are read
    // asynchronously off a live RPC, so a stale yes is exactly how a green
    // status survives the connector dying underneath it.
    gateMaxAgeMs: 30000,                // a gate reading older than this stops counting as evidence (re-read cadence is 1s)
    gateRefreshTimeoutMs: 8000,         // a getAdState() that never settles must not block all future refreshes
    slotClearPendingMs: 6000,           // a clearSlot() promise outstanding longer than this is treated as failed, not pending
    adTripwire: true,                   // permanently observe the core's in-stream ad channel; ANY delivery while the block is on is a hard failure signal (this is what "no load at all" is measured on)
    // ---- tripwire CONTAINMENT ----
    // The tripwire used to observe and do nothing but log. Before readiness it
    // called armMute() alone, which the ~2s watchdog then undid because
    // ad_active was never set - so the ad was muted and un-muted while still
    // playing. After readiness it did not even mute: it left everything to the
    // DOM FSM's 500ms poll and two-tick confirmation, which is ~1s of audible ad
    // in the one case where a layer has already demonstrably failed.
    tripwireContain: true,
    // Bounded mute hold, so containment can never pin a real song silent. The
    // watchdog still owns the ceiling; this only asks it to wait.
    tripwireHoldMs: 8000,
    tripwireHoldMaxMs: 35000,           // absolute cap even when the ad declares a longer duration
    tripwireMinHoldMs: 1200,            // floor before DOM evidence is allowed to release early
    overrideSkip: true,                 // reactive belt ONLY: skipToNextWithOverride() bypasses the Free "skip disabled during ad" lock for any ad that slips the ad_enabled prevention (e.g. the startup window before the connector resolves, or SSAI). Gated ONLY via advance().
    totalBlockIntervalMs: 3000,         // re-apply connector-capture + endpoint-kill on this cadence (faster than the 10s stream-time interval so the kill lands before the first ad once the lazy ads chunk loads)
    // Spotify moved webpack -> rspack; hooking one name silently lost the
    // whole L1 layer. All candidates are hooked and a watchdog reports if
    // none of them ever fires.
    webpackChunkGlobals: ["rspackChunkclient_web", "webpackChunkclient_web"],
    l1WatchdogMs: 20000,                // how long to wait before calling the hook dead
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
  };
  const CFG = Object.assign({}, DEFAULTS,
    (window.__INTERCEPTIFY_CONFIG && typeof window.__INTERCEPTIFY_CONFIG === "object")
      ? window.__INTERCEPTIFY_CONFIG : {});

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
  const blockInStreamSignal = () => CFG.blockInstreamSignal !== false && CFG.inspectMode !== true;

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
  if (CFG.diagnosticOverlay || DEBUG_CAPTURE) {   // overlay shows whenever Debug capture mode is ON
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
          // background ~50% more transparent than before (0.94 -> 0.47); text stays fully opaque (#fff).
          d.style.cssText = "position:fixed;top:44px;left:8px;right:8px;max-height:62%;overflow:auto;z-index:2147483647;background:rgba(25,0,0,0.47);color:#fff;font:11px/1.45 monospace;padding:10px;border:2px solid #ff3b30;white-space:pre-wrap;pointer-events:none;text-shadow:0 1px 2px #000;";
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
      // Selectors come from config. They were hard-coded here while the config
      // advertised a nowPlayingTitleSelectors key that nothing read - so the one
      // knob most likely to need turning after a Spotify UI change did nothing.
      const sels = CFG.nowPlayingTitleSelectors || [];
      let title = null;
      for (const s of sels) {
        try { title = document.querySelector(s); } catch { title = null; }
        if (title) break;
      }
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
    if (CFG.inspectMode) return;        // inspect: don't hide the ad UI
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

  // Is this an INTERRUPTIVE AUDIO ad? The fast pre-paint path used to ask only
  // `ad.format === 1 || ad.format === "AUDIO"`, and every real captured ad
  // object on this install carries its audio classification somewhere else
  // entirely: metadata.product_name = "audio_ad", metadata.format = "audio/ogg".
  // Whether the live object ALSO had a top-level format is unknown - the capture
  // serializer is a whitelist and never recorded it - so this accepts either
  // rather than betting on the answer. Getting it wrong means the silent
  // pre-paint skip never fires and every ad waits for the DOM.
  function isAudioAd(ad) {
    if (!ad || typeof ad !== "object") return false;
    if (ad.format === 1 || ad.format === "AUDIO") return true;
    const md = ad.metadata || {};
    if (String(md.product_name || "").toLowerCase() === "audio_ad") return true;
    if (/^audio\//i.test(String(md.format || ""))) return true;
    if (String(ad.mediaType || "").toLowerCase() === "audio") return true;
    return false;
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
      // Recorded explicitly so the next capture can answer what this one could
      // not: whether the live object carries a top-level format at all.
      format: ad.format,
      formatType: typeof ad.format,
      productName: metadata.product_name,
      metadataFormat: metadata.format,
      classifiedAudio: isAudioAd(ad),
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
        // ACTIVELY skip from the callback. On this build some ads are delivered
        // ONLY via the manager's onAdMessage callback and never populate
        // getInStreamAd(), so the poll/getter never sees them — only this does.
        // neutralizeInStreamAd is deduped + guarded + mutes, so this is the
        // pre-paint fast path for those ads.
        try { const _api = window.__interceptify_instream_api; if (_api && blockInStreamSignal()) neutralizeInStreamAd(_api, ad, method + ".callback"); } catch {}
        return true;
      }
      if (summarizeAdObject(msg)) {
        rememberInStreamAd(msg, method);
        rememberInStreamApiCall(method, { ad: summarizeAdObject(msg), message: compactValue(msg, 0) });
        try { const _api = window.__interceptify_instream_api; if (_api && blockInStreamSignal()) neutralizeInStreamAd(_api, msg, method + ".callback"); } catch {}
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
  function inStreamSkipSafe(authoritative) {
    if (Date.now() < inStreamSkipLockUntil) return false;  // (1) short post-skip self-lock (~300ms, NOT the 1500ms FSM cooldown)
    // (1b) An AUDIO object that turns up shortly AFTER we advanced the queue may
    //      be a late or prefetched read of the break we already dealt with,
    //      while the thing now playing is a real song. Inside that window
    //      "format says AUDIO" stops being self-sufficient evidence and has to
    //      be corroborated like any other object. Outside it, the pre-paint
    //      silent skip is untouched - that is the whole point of the layer - and
    //      a genuine multi-ad break still corroborates, because the previous
    //      ad's controls are still painted and ad_active is still set.
    if (authoritative && (Date.now() - lastAdvanceAt) < (CFG.authoritativeAfterAdvanceMs | 0)) {
      authoritative = false;
    }
    // (2) corroboration. An AUTHORITATIVE signal — a FRESH AUDIO ad object
    //     (format===AUDIO, first sighting of this adId) — is itself proof an
    //     audio ad is here, so we skip PRE-PAINT (no DOM wait). A non-audio /
    //     unknown-format object can be a stale / lingering / prefetched read, so
    //     it must be corroborated by an INDEPENDENT live ad signal (ad-controls
    //     present, ad-looking now-playing, or ad_active) — a real song has none.
    if (!authoritative) {
      let live = false;
      try {
        live = !!STRONG_PRESENT() || fpLooksLikeAd(nowPlayingSnapshot()) || window.__interceptify_ad_active === true;
      } catch { live = false; }
      if (!live) return false;
    }
    // (3) now-playing moved off the confirmed ad to a non-ad track (extra layer).
    try {
      if (currentAdFp) {
        const fpNow = nowPlayingSnapshot();
        if (!fpEqual(fpNow, currentAdFp) && !fpLooksLikeAd(fpNow)) return false;
      }
    } catch {}
    return true;
  }

  // ===================================================================
  // TOTAL BLOCK (SpotX-style): the ad-break SCHEDULER keys off core stream-time
  // (elapsed_stream_time - last_ad_break_stream_time > threshold; see
  // ad-state-storage.bnk). The ads connector exposes increaseStreamTime() — a
  // Cosmos RPC into the C++ core. Pushing it hugely negative means the threshold
  // is never crossed -> ad breaks are never scheduled (silent, pre-play). Found
  // by SIGNATURE (increaseStreamTime + overrideAdServerEndpoint) so it survives
  // module-id churn. The reactive FSM (skip+mute) stays as the fallback for SSAI
  // ads and any build where this lever moves/renames.
  function getAdsDebugConnector() {
    if (window.__interceptify_ads_debug) return window.__interceptify_ads_debug;
    try {
      const req = anyAdsRequire();
      if (!req || !req.m) return null;
      for (const id in req.m) {
        let s = ""; try { s = Function.prototype.toString.call(req.m[id]); } catch {}
        if (s.indexOf("increaseStreamTime") < 0) continue;
        if (s.indexOf("overrideAdServerEndpoint") < 0 && s.indexOf("AdStatePusher") < 0) continue;
        let mod; try { mod = (req.c && req.c[id]) ? req.c[id].exports : req(id); } catch { continue; }
        if (!mod) continue;
        const cands = [mod, mod.D, mod.default].concat(
          Object.keys(mod).map((k) => { try { return mod[k]; } catch { return null; } }));
        for (const c of cands) {
          try {
            if (c && typeof c.increaseStreamTime === "function") {
              window.__interceptify_ads_debug = c;
              snifferLog("total-block-connector", { module: String(id) });
              return c;
            }
          } catch {}
        }
      }
    } catch {}
    return null;
  }
  // =========================================================================
  // SNAPSHOT-BUILD ADS-CONNECTOR RESURRECTION (Spotify 1.2.93+)
  // ------------------------------------------------------------------------
  // On V8-snapshot builds Spotify's webpack require + module cache are trapped
  // in a closure and chunk.push no longer threads a require, so the L1 provider
  // hook never captures the ads connector -> killAdEndpoints/streamTimeKill
  // silently no-op and only the DOM mute survives (the "only mutes now" bug).
  // The one surface still exposed is `window.__webpack_modules__` (the factory
  // registry, writable). A require reconstructed over it can instantiate the ad
  // connector; its RPC methods (skipToNextWithOverride / updateAdStateEndpoint /
  // updateAdServerEndpoint) proxy to the shared C++ core, so they drive the REAL
  // ad flow even from a rebuilt instance — live-proven: an override-skip advanced
  // a real track. We also opportunistically capture the GENUINE live require by
  // wrapping registry factories in place (belt; preferred when available).
  let _snapshotRequire = null;
  function buildSnapshotRequire() {
    if (_snapshotRequire) return _snapshotRequire;
    const M = window.__webpack_modules__;
    if (!M || typeof M !== "object") return null;
    const cache = {};
    const req = function (id) {
      if (cache[id]) return cache[id].exports;
      const mod = cache[id] = { id: id, exports: {}, loaded: false };
      M[id].call(mod.exports, mod, mod.exports, req);
      mod.loaded = true;
      return mod.exports;
    };
    req.m = M; req.c = cache;
    req.d = (e, t) => { for (const o in t) if (Object.prototype.hasOwnProperty.call(t, o) && !Object.prototype.hasOwnProperty.call(e, o)) Object.defineProperty(e, o, { enumerable: true, get: t[o] }); };
    req.o = (o, p) => Object.prototype.hasOwnProperty.call(o, p);
    req.r = (e) => { if (typeof Symbol !== "undefined" && Symbol.toStringTag) Object.defineProperty(e, Symbol.toStringTag, { value: "Module" }); Object.defineProperty(e, "__esModule", { value: true }); };
    req.n = (e) => { const g = e && e.__esModule ? () => e.default : () => e; req.d(g, { a: g }); return g; };
    req.t = function (v) { return v; };
    req.e = () => Promise.resolve();
    req.f = {}; req.u = (e) => e + ".js"; req.g = window; req.p = "";
    try { req.b = document.baseURI || self.location.href; } catch { req.b = ""; }
    req.nmd = (m) => { m.paths = []; m.children = m.children || []; return m; };
    req.hmd = (m) => m;
    _snapshotRequire = req;
    return req;
  }
  // The genuine live require if captured (returns live-cached singletons); else
  // the reconstructed one (parallel instance, RPCs still reach the shared core).
  function anyAdsRequire() {
    const live = window.__interceptify_webpack_require;
    if (live && live.m) return live;
    return buildSnapshotRequire();
  }
  // Capture the GENUINE live require by wrapping registry factories in place; the
  // next time the app instantiates a not-yet-cached wrapped module we grab its
  // require (3rd arg). Idempotent + re-runnable (catches lazily added factories).
  function captureLiveRequire() {
    try {
      if (window.__interceptify_webpack_require) return;
      const M = window.__webpack_modules__;
      if (!M || typeof M !== "object") return;
      for (const id of Object.keys(M)) {
        const orig = M[id];
        if (typeof orig !== "function" || orig.__intc_capwrap) continue;
        const w = function (module, exports, require) {
          if (require && require.m && !window.__interceptify_webpack_require) {
            try { window.__interceptify_webpack_require = require; } catch {}
          }
          return orig.apply(this, arguments);
        };
        w.__intc_capwrap = true; w.__intc_orig = orig;
        try { M[id] = w; } catch {}
      }
    } catch {}
  }
  // Find + instantiate the ad connector (adsCoreConnector exposing
  // skipToNextWithOverride + updateAdStateEndpoint). By SIGNATURE, never a
  // hard-coded id (ids churn every Spotify build; the module also lives in a
  // LAZY chunk, so it appears only once the ads subsystem has loaded — hence the
  // retry loop on the interval). Cached once found.
  let _adsConnector = null;
  function resolveAdsConnector() {
    if (_adsConnector) return _adsConnector;
    if (CFG.snapshotConnector === false) return null;
    const M = window.__webpack_modules__;
    const req = anyAdsRequire();
    if (!M || !req) return null;
    for (const id of Object.keys(M)) {
      let src = "";
      try { const f = M[id] && M[id].__intc_orig ? M[id].__intc_orig : M[id]; src = Function.prototype.toString.call(f); } catch { continue; }
      if (src.indexOf("skipToNextWithOverride") < 0) continue;
      if (src.indexOf("updateAdStateEndpoint") < 0 && src.indexOf("adsCoreConnector") < 0) continue;
      let ex; try { ex = req(id); } catch { continue; }
      const ac = ex && ex.adsCoreConnector;
      if (ac && typeof ac.skipToNextWithOverride === "function") {
        _adsConnector = ac;
        window.__interceptify_ads_connector = ac;
        snifferLog("ads-connector-resolved", { module: String(id), live: !!(window.__interceptify_webpack_require && window.__interceptify_webpack_require.m) });
        return ac;
      }
    }
    return null;
  }
  // ---------------------------------------------------------------------
  // DURABLE INCIDENT RECORD — the single place an ad-experience is written.
  //
  // Every path that means "an ad got to the user" funnels through here:
  //   delivered  the core handed us an ad on its in-stream channel (tripwire)
  //   muted      the reactive belt muted audio, i.e. an ad reached playback
  //   skipped    the override skip fired, same meaning
  //
  // Wiring this to the tripwire alone was the earlier mistake: the tripwire
  // watches one channel, and an ad that arrives another way was invisible while
  // still being audible. The mute is the ground truth for "the user heard it".
  //
  // Each record carries the gate state AT THAT MOMENT, because that is the only
  // time it is knowable, and a record that cannot be diagnosed later is not
  // worth keeping.
  const _INCIDENT_KEY = "__interceptify_ad_incidents";
  // Always-on, bounded counters.
  //
  // These deliberately do NOT go through snifferLog(): that function returns
  // immediately unless DEBUG_CAPTURE is set, and self-heal always patches with
  // debug capture OFF. So every signal derived from the sniffer read zero in
  // production no matter what actually happened, and "reactiveActions === 0"
  // was true by construction. A counter that cannot be non-zero is not
  // evidence, it is decoration.
  //
  // Integers only, fixed set of keys, so this cannot grow without bound.
  const _counters = window.__interceptify_counters = window.__interceptify_counters || {
    delivered: 0,        // core handed us an ad object (the block let one through)
    muted: 0,            // reactive mute fired: an ad was already playing
    skipped: 0,          // reactive skip fired: an ad was already playing
    speculativeMute: 0,  // weak/pre-paint mute: NOT proof the user heard anything
    l1Skip: 0,           // pre-paint L1 skip: the silent path working as intended
    contained: 0,        // tripwire containment skip: a delivery the block failed to prevent, cut short
    since: Date.now(),
  };

  // Install failures that were caught and would otherwise vanish.
  const _layerErrors = window.__interceptify_layer_errors = window.__interceptify_layer_errors || [];

  let _lastIncidentAt = 0;
  // ---- Startup readiness -------------------------------------------------
  // Measured on 1.2.94 (2026-07-29): after a Spotify start the ads connector is
  // reachable at ~2.3s with ad_enabled still "true", and the gate first reads
  // closed at ~3.6s. That is a real ~1.3s window in which the payload is loaded,
  // every hook reports attached, and NOTHING is preventing an ad - and an ad
  // queued in it survives, because ad_enabled=false only stops NEW scheduling.
  //
  // Being loaded is not the same as being protective. Anything that reports
  // health has to be able to say which one it means.
  // Readiness is built entirely on answers that arrive asynchronously from a
  // live RPC, and every one of them used to be a latched boolean with no expiry.
  // A gate read that succeeded once stayed authoritative even if every later
  // getAdState() rejected or hung; an acknowledged slot clear stayed acknowledged
  // even when the next attempt never resolved. Both are how a green status
  // outlives the connector it describes - which matters most at track
  // boundaries, exactly where a queued ad gets promoted.
  function protectionReady() {
    const g = window.__interceptify_ad_gate || null;
    const missing = [];
    if (!window.__interceptify_ads_connector) missing.push("connector");
    if (_baselineKeys === null) missing.push("baseline");          // no populated ad-state seen
    if (!(g && g.verified)) missing.push("gateClosed");            // written AND read back false
    // A reading is evidence for as long as it is fresh. The re-read cadence is
    // 1s, so anything older than gateMaxAgeMs means refreshes have stopped
    // landing - the connector died, the promise hung, or the page is frozen -
    // and the last "closed" describes a client that no longer exists.
    else if (_adGateReadAt && Date.now() - _adGateReadAt > (CFG.gateMaxAgeMs | 0))
      missing.push("gateStale");
    // ok === false is a definite failure, and so is a promise that never
    // settled (see slotClearState). ok === null means clearSlot returned
    // nothing to await, so completion is UNCONFIRMABLE - and treating
    // unconfirmable as "never ready" would make a structural PASS unreachable on
    // such a build, which turns the self-heal into a permanent repair loop. That
    // failure mode has already cost this project once. Unconfirmable is reported
    // rather than punished; only a real failure blocks readiness.
    const sc = slotClearState();
    if (sc.ok === false || sc.t === 0) missing.push("slotCleared");
    else if (sc.ok === "pending") missing.push("slotClearPending");
    if (!window.__interceptify_l1_provider_wrapped) missing.push("l1Provider");
    return { ok: missing.length === 0, missing: missing };
  }

  function recordIncident(kind, info) {
    try {
      const now = Date.now();
      // Count before de-duplicating. The 4s collapse below exists to stop one ad
      // producing three log lines; applying it to the counters would make them
      // undercount real events instead of merely logging them once.
      const key = { delivered: "delivered", muted: "muted", skipped: "skipped",
                    "speculative-mute": "speculativeMute", "l1-skip": "l1Skip" }[kind];
      if (key) _counters[key]++;

      // Collapse a burst: one ad trips several detectors within a second or two,
      // and three records for one ad makes the log lie about frequency.
      //
      // Collapsing used to DISCARD the later ones, which threw away the lifecycle
      // - "delivered" survived and the mute and skip that followed it vanished,
      // so no record could ever answer whether a delivery was contained. Now the
      // burst is merged into the record it belongs to: one line per ad, with
      // every outcome it produced, in order.
      if (kind !== "delivered" && now - _lastIncidentAt < 4000) {
        try {
          const arr = JSON.parse(localStorage.getItem(_INCIDENT_KEY) || "[]");
          const last = arr[arr.length - 1];
          if (last) {
            last.also = last.also || [];
            if (last.also.length < 8) last.also.push({ kind: kind, dt: now - (last.t || now) });
            localStorage.setItem(_INCIDENT_KEY, JSON.stringify(arr));
          }
        } catch {}
        return;
      }
      _lastIncidentAt = now;
      const g = window.__interceptify_ad_gate || null;
      const ready = protectionReady();
      const rec = {
        t: now,
        kind: kind,
        id: (info && info.id) || null,
        format: info && info.format,
        // The fields that would have made the earlier incidents diagnosable.
        // Every record so far said only "an ad happened, gate closed" - which
        // slot it came through, whether we classified it as audio, and how stale
        // our gate reading was are exactly the things needed to tell a queued-ad
        // leak from a scheduling failure, and none of them were kept.
        slot: (info && info.slot) || null,
        audio: info ? info.audio : null,
        outcome: (info && info.outcome) || kind,
        // What containment actually managed to do about this delivery. Without
        // it "delivered" records could not distinguish an ad the user heard in
        // full from one cut off in under a second.
        contained: (info && info.contained) || null,
        v: window.__interceptify && window.__interceptify.version,
        ready: ready.ok,
        notReady: ready.ok ? null : ready.missing,
        slotClear: { slot: _slotClear.slot, ok: _slotClear.ok,
                     ageMs: _slotClear.t ? now - _slotClear.t : null,
                     error: _slotClear.error },
        gate: {
          closed: !!(g && g.verified),
          keys: (g && g.keys) || null,
          connector: !!window.__interceptify_ads_connector,
          // How old the "closed" reading is. refreshAdGate() is asynchronous and
          // cached, so `closed: true` has always meant "true when we last
          // looked", not "true now" - and without the age nobody could tell the
          // difference.
          readAgeMs: _adGateReadAt ? now - _adGateReadAt : null,
          // true only while selftest deliberately opens the gate to prove its
          // own trigger fires, so such a record is EXPECTED, not a failure
          suspended: window.__interceptify_suspend_block === true,
          uptimeMs: Math.round(
            (typeof performance !== "undefined" && performance.now) ? performance.now() : 0)
        }
      };
      const arr = JSON.parse(localStorage.getItem(_INCIDENT_KEY) || "[]");
      arr.push(rec);
      localStorage.setItem(_INCIDENT_KEY, JSON.stringify(arr.slice(-100)));
      snifferLog("incident-" + kind, rec);
    } catch {}
  }

  // Reactive OVERRIDE skip. skipToNextWithOverride() -> skipNext({overrideRestrictions:
  // true}), which bypasses the Free "skip disabled during ad" lock. Gated ONLY
  // through advance() (fully song-safe); pairs with armMute() so the ~1s core
  // advance window is silent. Belt for any ad that slips prevention (SSAI, or the
  // window before the connector/endpoint-kill is live).
  function overrideSkip(reason) {
    if (CFG.overrideSkip === false) return false;
    try {
      const ac = resolveAdsConnector();
      if (ac && typeof ac.skipToNextWithOverride === "function") {
        try { armMute(); } catch {}
        ac.skipToNextWithOverride();
        recordIncident("skipped", { id: (window.__interceptify_last_delivered || {}).id || null });
        snifferLog("override-skip", { reason });
        return true;
      }
    } catch (e) { snifferLog("override-skip-error", { reason, error: String(e && e.message || e) }); }
    return false;
  }

  function streamTimeKill(reason) {
    if (CFG.totalBlock === false) return false;
    try {
      const d = getAdsDebugConnector();
      if (d && typeof d.increaseStreamTime === "function") {
        d.increaseStreamTime(CFG.streamTimeKillValue || -100000000000);
        snifferLog("total-block-streamtime", { reason });
        return true;
      }
    } catch (e) { snifferLog("total-block-error", { reason, error: String(e && e.message || e) }); }
    return false;
  }

  // TOTAL BLOCK (endpoint override): point the ad-STATE channel (the server->
  // client "an ad break is due" pusher) and each ad SLOT's ad-SERVER (fulfillment)
  // at a dead URL, so the client can't be told to play an ad and can't fetch ad
  // media. Live-tested stable (no playback stall). Re-applied on the interval (the
  // server may reset it on reconnect). FSM skip+mute stays as the fallback.
  // ---- Ad slots: read Spotify's own ids, do not trust a hard-coded list ----
  let _discoveredSlots = null;

  function discoverAdSlots() {
    // Spotify declares its slots as *_SLOT_ID constants. Reading them means a
    // renamed or added slot is picked up without a release, which is the whole
    // reason the stale "streaming" alias went unnoticed for so long: nothing
    // ever compared our list against theirs.
    const out = [];
    try {
      const M = window.__webpack_modules__ || {};
      const re = rx(CFG.adSlotIdRegex, "g");
      if (!re) return out;
      for (const id of Object.keys(M)) {
        let s = "";
        try { s = Function.prototype.toString.call(M[id].__intc_orig || M[id]); } catch { continue; }
        if (s.indexOf("SLOT") < 0) continue;
        let m;
        re.lastIndex = 0;
        while ((m = re.exec(s))) {
          const v = m[2];
          // Slot ids are lowercase kebab tokens; the constant NAME is not one.
          if (/^[a-z][a-z0-9-]*$/.test(v) && out.indexOf(v) === -1) out.push(v);
        }
      }
    } catch {}
    return out;
  }

  // The slot readiness is measured on. Normally the configured one; but if
  // discovery produced a real list and the configured name is NOT in it, that
  // name is dead and clearing it is the "streaming" bug repeating. Promote the
  // discovered slot that looks like the interruptive audio slot instead.
  function primarySlot() {
    const configured = CFG.primaryAdSlot || DEFAULTS.primaryAdSlot;
    const found = _discoveredSlots || [];
    if (!found.length || found.indexOf(configured) !== -1) return configured;
    const re = rx(CFG.primarySlotRegex || DEFAULTS.primarySlotRegex, "");
    const promoted = re ? found.filter((s) => re.test(s))[0] : null;
    if (!promoted) return configured;      // nothing better: keep the known name
    if (window.__interceptify_primary_slot !== promoted) {
      window.__interceptify_primary_slot = promoted;
      snifferLog("primary-slot-promoted", { configured, promoted, live: found });
    }
    return promoted;
  }

  // Has discovery yielded a primary we can actually use - either the configured
  // name, or a promotable rename? This is the termination condition, and it has
  // to accept BOTH: keying it on the configured name alone means a renamed slot
  // re-scans the whole module graph on every call, forever.
  function haveUsablePrimary() {
    const found = _discoveredSlots;
    if (found === null || !found.length) return false;
    if (found.indexOf(CFG.primaryAdSlot || DEFAULTS.primaryAdSlot) !== -1) return true;
    const re = rx(CFG.primarySlotRegex || DEFAULTS.primarySlotRegex, "");
    return !!(re && found.some((s) => re.test(s)));
  }

  let _lastSlotDiscoveryAt = 0;

  function adSlots() {
    // Keep re-discovering until the bundle yields a usable primary. Caching the
    // first answer would freeze whatever the module graph happened to hold at
    // the moment of the first call - and the first call happens ~1s after load,
    // from the pre-baseline slot flush, when the ads chunk is usually still
    // lazy. That is the same shape as the empty-first-read that poisoned the
    // ad-gate baseline: a snapshot taken too early, kept forever.
    //
    // Rate-limited because the alternative is a full toString() sweep of every
    // module on a 1s cadence for as long as the bundle has no recognisable slot
    // constant at all - a real state on a future rebuild, and one where the
    // remedy must not be a permanent CPU cost.
    if (CFG.adSlotDiscovery !== false && !haveUsablePrimary() &&
        Date.now() - _lastSlotDiscoveryAt >= (CFG.adSlotDiscoveryIntervalMs | 0)) {
      _lastSlotDiscoveryAt = Date.now();
      _discoveredSlots = discoverAdSlots();
      if (_discoveredSlots.length) {
        window.__interceptify_discovered_slots = _discoveredSlots.slice();
        const configured = CFG.adSlots || DEFAULTS.adSlots;
        const missing = _discoveredSlots.filter((s) => configured.indexOf(s) === -1);
        const stale = configured.filter((s) => _discoveredSlots.indexOf(s) === -1);
        if (missing.length || stale.length)
          snifferLog("ad-slots-drifted", { missing, stale, live: _discoveredSlots });
      }
    }
    const found = (_discoveredSlots && _discoveredSlots.length) ? _discoveredSlots : [];
    // Union, not replacement. Discovery running early can return a partial graph,
    // and a partial list that silently REPLACED the configured one would drop
    // slots we know about to gain ones we just found.
    const configured = CFG.adSlots || DEFAULTS.adSlots;
    const base = found.concat(configured.filter((s) => found.indexOf(s) === -1));
    // Resolved AFTER discovery, so a rename found on this very call takes effect
    // now rather than one call later. The interruptive audio slot goes first and
    // is always present even if discovery missed it: it is the one that actually
    // reaches the user's ears.
    const primary = primarySlot();
    return [primary].concat(base.filter((s) => s !== primary));
  }

  // The result of the LAST attempt to flush the primary slot. clearSlot() is
  // asynchronous in Spotify's own code and this used to be fire-and-forget, so
  // "we cleared the slot" was never a fact anyone had checked - a rejected call,
  // or one that never resolved, looked exactly like success.
  //
  // `ok` is four-valued, and the distinctions are the whole point:
  //   true      resolved - the core acknowledged this attempt
  //   false     rejected, threw, or a promise that never settled in time
  //   null      clearSlot returned no thenable: UNCONFIRMABLE on this build, and
  //             punishing that would make a structural PASS unreachable, which
  //             is a permanent Spotify-restarting repair loop
  //   "pending" a thenable is outstanding for the CURRENT attempt
  //
  // The pending state exists because the old code latched: once one clear
  // resolved, a later clear that never resolved left the stale `true` in place
  // and readiness kept reporting green off an acknowledgement for an attempt
  // that had already been superseded.
  const _slotClear = window.__interceptify_slot_clear = {
    slot: null, ok: null, t: 0, error: null, epoch: 0, startedAt: 0 };

  function clearAdSlots(ac, reason) {
    if (CFG.clearAdSlots === false || !ac || typeof ac.clearSlot !== "function") return;
    const code = CFG.clearSlotReason != null ? CFG.clearSlotReason : 1;
    const slots = adSlots();
    const primary = slots[0];
    // Every round is a new attempt, and the previous round's answer stops being
    // evidence the moment this one starts. Late settlements from an older epoch
    // are ignored below rather than overwriting a newer result.
    const epoch = ++_slotClear.epoch;
    for (const s of slots) {
      try {
        const p = ac.clearSlot(s, code);
        if (s !== primary) continue;
        if (p && typeof p.then === "function") {
          _slotClear.slot = s; _slotClear.ok = "pending"; _slotClear.startedAt = Date.now();
          _slotClear.error = null;
          p.then(function () {
            if (_slotClear.epoch !== epoch) return;       // superseded
            _slotClear.ok = true; _slotClear.t = Date.now(); _slotClear.error = null;
          }, function (e) {
            if (_slotClear.epoch !== epoch) return;
            _slotClear.ok = false; _slotClear.t = Date.now();
            _slotClear.error = String((e && e.message) || e);
            snifferLog("slot-clear-failed", { slot: s, error: _slotClear.error });
          });
        } else {
          // Synchronous return: nothing to await, so record that it was called
          // and that we have no acknowledgement, rather than implying one.
          _slotClear.slot = s; _slotClear.ok = null; _slotClear.t = Date.now();
          _slotClear.startedAt = 0;
          _slotClear.error = "clearSlot returned no promise; completion unconfirmed";
        }
      } catch (e) {
        if (s === primary) {
          _slotClear.slot = s; _slotClear.ok = false; _slotClear.startedAt = 0;
          _slotClear.t = Date.now(); _slotClear.error = String((e && e.message) || e);
        }
      }
    }
  }

  // A thenable that never settles is a hung RPC into the ads core, not an
  // unconfirmable build. Time it out into a definite failure so it surfaces as
  // FAIL instead of sitting "pending" forever, and so it can never be confused
  // with the sync-return escape hatch above.
  function slotClearState() {
    if (_slotClear.ok === "pending" && _slotClear.startedAt &&
        Date.now() - _slotClear.startedAt > (CFG.slotClearPendingMs | 0)) {
      _slotClear.ok = false;
      _slotClear.t = Date.now();
      _slotClear.error = "clearSlot promise never settled within slotClearPendingMs";
      snifferLog("slot-clear-stuck", { slot: _slotClear.slot });
    }
    return _slotClear;
  }

  function killAdEndpoints(reason) {
    if (CFG.killAdEndpoints === false) return false;
    try {
      const api = window.__interceptify_instream_api;
      // Prefer the L1-hooked instream api's connector (old builds); on snapshot
      // builds that hook is dead, so fall back to the resurrected connector.
      const acc = (api && api.adsCoreConnector) || resolveAdsConnector();
      if (!acc) return false;
      const DEAD = CFG.deadAdEndpoint || "https://localhost.invalid/no-ads";
      // Per-method acknowledgement. This returned true whenever a connector
      // existed, so a build that renamed or dropped BOTH endpoint methods
      // reported the endpoint kill as applied while nothing had been called -
      // the same shape of false green as a config that is published but never
      // injected. Only a method that exists AND did not throw counts.
      const applied = [];
      const failed = [];
      if (typeof acc.updateAdStateEndpoint === "function") {
        try { acc.updateAdStateEndpoint(DEAD); applied.push("updateAdStateEndpoint"); }
        catch (e) { failed.push("updateAdStateEndpoint:" + String((e && e.message) || e)); }
      }
      if (typeof acc.updateAdServerEndpoint === "function") {
        let ok = 0;
        for (const sid of adSlots()) {
          try { acc.updateAdServerEndpoint([sid], DEAD); ok++; } catch {}
        }
        if (ok) applied.push("updateAdServerEndpoint x" + ok);
        else failed.push("updateAdServerEndpoint: every slot threw");
      }
      window.__interceptify_ad_endpoints = { applied, failed, t: Date.now() };
      if (!applied.length) {
        window.__interceptify_ad_endpoints_killed = false;
        snifferLog("ad-endpoint-MISSING", { reason, failed,
                                            methods: Object.keys(acc || {}).slice(0, 60) });
        return false;
      }
      if (!window.__interceptify_ad_endpoints_killed) {
        window.__interceptify_ad_endpoints_killed = true;
        snifferLog("ad-endpoint-killed", { reason, applied });
      }
      return true;
    } catch (e) { snifferLog("ad-endpoint-error", { reason, error: String(e && e.message || e) }); }
    return false;
  }

  // MASTER PREVENTION (Spotify 1.2.93+): flip the core ad-scheduler's `ad_enabled`
  // state to "false" via the connector's putState RPC. This is the switch the core
  // reads to decide whether to SCHEDULE ad breaks — setting it false stops ads from
  // ever loading/playing (not a reactive skip). Live-proven: with it held, 10 forced
  // skips that reliably triggered an ad break produced zero ads. Re-applied fast
  // because a product-state refresh (reconnect/login) can re-push ad_enabled:true.
  // ---- SELF-HEALING ad-gate discovery -------------------------------------
  // The core scheduler's master switch is a STATE KEY, and its name is Spotify
  // -internal (today `ad_enabled`). Rather than trust that name forever, read
  // the live ad state and match key names against CFG.adGateKeyPatterns. If a
  // Spotify update renames it we auto-adopt the new name; if NOTHING matches we
  // log `ad-gate-MISSING` with the real key list, which is the exact signal the
  // automated repair loop escalates on (silent no-op was the old failure mode).
  let _adGateKeys = null;          // discovered gate key names
  let _adGateVerified = false;     // read-back confirmed every gate reads "false"
  // When that read-back happened. refreshAdGate() is asynchronous and cached, so
  // "verified" has always meant "true when we last looked". Incidents now carry
  // the age, because a gate that read closed eight seconds ago and a gate that
  // read closed 200ms ago are different claims.
  let _adGateReadAt = 0;
  let _adGateRefreshing = false;
  // BASELINE of the key names Spotify's own state had BEFORE we ever wrote to it.
  // Critical: putState() CREATES any key you name, so "write a key then read it
  // back" is circular and would happily 'verify' a key that does not exist. A
  // discovered gate key is only trustworthy if Spotify itself published it.
  let _baselineKeys = null;
  function adGateFallbackKeys() {
    const f = CFG.adGateFallbackKeys;
    return Array.isArray(f) && f.length ? f : DEFAULTS.adGateFallbackKeys;
  }
  function adGateKeys() { return _adGateKeys && _adGateKeys.length ? _adGateKeys : adGateFallbackKeys(); }
  let _adGateRefreshStartedAt = 0;
  function refreshAdGate(ac) {
    // A getAdState() that never settles used to pin _adGateRefreshing true
    // forever, so no later refresh could ever run and the last "verified"
    // reading stayed frozen as the answer for the rest of the page's life.
    if (_adGateRefreshing && _adGateRefreshStartedAt &&
        Date.now() - _adGateRefreshStartedAt > (CFG.gateRefreshTimeoutMs | 0)) {
      _adGateRefreshing = false;
      _adGateVerified = false;
      window.__interceptify_ad_gate = { keys: _adGateKeys || [], verified: false,
                                        readAt: _adGateReadAt,
                                        error: "getAdState never settled" };
      snifferLog("ad-gate-read-stuck", { sinceMs: Date.now() - _adGateRefreshStartedAt });
    }
    if (_adGateRefreshing || !ac || typeof ac.getAdState !== "function") return;
    _adGateRefreshing = true;
    _adGateRefreshStartedAt = Date.now();
    try {
      const p = ac.getAdState();
      if (!p || !p.then) { _adGateRefreshing = false; return; }
      p.then((s) => {
        _adGateRefreshing = false;
        const st = (s && s.state) || {};
        const keys = Object.keys(st);
        // Freeze the baseline ONLY from a real, populated snapshot. The ads
        // connector can answer before the core has published anything, and an
        // empty first read used to be frozen as "Spotify's key set is {}". Every
        // genuine key that arrived afterwards was then rejected as one we
        // invented, the gate fell back to writing CFG.adGateFallbackKeys into a
        // baseline that could never contain them, and the poisoning was
        // permanent for the life of the page.
        if (_baselineKeys === null) {
          if (!keys.length) { window.__interceptify_baseline_empty_reads =
            (window.__interceptify_baseline_empty_reads || 0) + 1; return; }
          _baselineKeys = {};
          for (const k of keys) _baselineKeys[k] = true;
          window.__interceptify_baseline_keys = keys.slice();
        }
        const pats = (CFG.adGateKeyPatterns || []).map((x) => rx(x, "i")).filter(Boolean);
        // Only keys Spotify itself published count — never one we invented.
        const found = keys.filter((k) => pats.some((r) => r.test(k)) && _baselineKeys[k]);
        if (found.length) {
          if (!_adGateKeys || found.join(",") !== _adGateKeys.join(",")) snifferLog("ad-gate-discovered", { keys: found });
          _adGateKeys = found;
          const notFalse = found.filter((k) => String(st[k] && st[k].value).toLowerCase() !== "false");
          _adGateVerified = notFalse.length === 0;
          if (!_adGateVerified && CFG.adGateVerify !== false) snifferLog("ad-gate-FAILED", { notFalse });
        } else {
          _adGateKeys = null; _adGateVerified = false;
          snifferLog("ad-gate-MISSING", { keys: keys.slice(0, 60) });   // <- drift: key was renamed
        }
        _adGateReadAt = Date.now();
        window.__interceptify_ad_gate = { keys: found, verified: _adGateVerified,
                                          readAt: _adGateReadAt };
      }).catch((e) => {
        // A REJECTED read is not "no new information", it is evidence the
        // channel the gate lives on is broken. Swallowing it left the previous
        // `verified: true` standing as the current answer indefinitely.
        _adGateRefreshing = false;
        _adGateVerified = false;
        window.__interceptify_ad_gate = { keys: _adGateKeys || [], verified: false,
                                          readAt: _adGateReadAt,
                                          error: String((e && e.message) || e) };
        snifferLog("ad-gate-read-failed", { error: String((e && e.message) || e) });
      });
    } catch (e) {
      _adGateRefreshing = false;
      _adGateVerified = false;
      snifferLog("ad-gate-read-threw", { error: String((e && e.message) || e) });
    }
  }
  // TRIPWIRE: watch the core's in-stream ad delivery channel forever. This is the
  // ground truth for "no load at all" — if the core hands us an ad while the block
  // is on, the block failed (a skipped/muted ad still counts as a failure here).
  // ---- tripwire CONTAINMENT ------------------------------------------------
  // A delivered ad object is the strongest evidence this payload ever receives:
  // Spotify's own ads core is telling us an ad exists, right now, with an id.
  // It drove nothing but a log line. Before readiness the tripwire called
  // armMute() and nothing else, so the ~2s watchdog un-muted it again (ad_active
  // was never set) and the ad played on; after readiness it did not even mute,
  // and waited for the DOM FSM's 500ms poll plus two-tick confirmation in the
  // one situation where a layer has already provably failed.
  let _containUntil = 0;
  let _containSince = 0;

  function adDurationMs(ad) {
    const md = (ad && ad.metadata) || {};
    for (const v of [ad && ad.duration, md.duration, md.duration_ms, md.duration_seconds]) {
      const n = Number(v);
      // Ads are never under a second, so a small number is seconds, not ms.
      if (isFinite(n) && n > 0) return n < 1000 ? n * 1000 : n;
    }
    return 0;
  }

  function holdContainment(ad) {
    const cap = CFG.tripwireHoldMaxMs | 0;
    const d = adDurationMs(ad);
    const ms = Math.min(d ? d + 1000 : (CFG.tripwireHoldMs | 0), cap);
    _containUntil = Math.max(_containUntil, Date.now() + ms);
    if (!_containSince) _containSince = Date.now();
    window.__interceptify_contain_until = _containUntil;
  }

  function containmentHeld() { return Date.now() < _containUntil; }
  function containmentAgeMs() { return _containSince ? Date.now() - _containSince : 0; }

  function releaseContainment(reason) {
    if (!_containUntil && !_containSince) return;
    _containUntil = 0; _containSince = 0;
    window.__interceptify_contain_until = 0;
    snifferLog("contain-released", { reason });
  }

  function containDeliveredAd(ac, ad, ready) {
    const out = { muted: false, cleared: false, skipped: false, held: 0 };
    if (CFG.tripwireContain === false) return out;
    // 1. MUTE FIRST, always, ready or not. It is the cheapest step, the only
    //    reversible one, and the only one that still helps if the rest fail.
    //    Held so the watchdog waits instead of undoing it two seconds later.
    try { armMute(); holdContainment(ad); out.muted = true; out.held = _containUntil - Date.now(); } catch {}
    // 2. Flush the slot, so the remainder of the break does not follow this ad
    //    in. Uses the RESOLVED primary rather than a configured guess.
    try { if (ac) { clearAdSlots(ac, "tripwire-contain"); out.cleared = true; } } catch {}
    // 3. Advance past it - through the SAME over-skip envelope the L1 path uses.
    //    A fresh audio ad object is authoritative in precisely the way
    //    inStreamSkipSafe() already models, so this reuses that gate rather than
    //    inventing a second, less-tested one, and shares the dedup set so this
    //    path and L1 can never both skip the same ad onto a real song.
    try {
      const stableKey = inStreamAdKey(ad);
      if (!stableKey) return out;              // thin object: never authorize a skip
      window.__interceptify_neutralized_ads = window.__interceptify_neutralized_ads || new Set();
      if (window.__interceptify_neutralized_ads.has(stableKey)) return out;
      if (!inStreamSkipSafe(isAudioAd(ad))) {
        snifferLog("contain-skip-suppressed", { id: stableKey, ready: ready && ready.ok });
        return out;
      }
      window.__interceptify_neutralized_ads.add(stableKey);
      const api = window.__interceptify_instream_api;
      // The in-stream api first (it is keyed to the ad object), then the
      // connector's override skip - which is the only lever that exists at all
      // on snapshot builds, where the L1 in-stream hook is dead.
      if (api && typeof api.skipToNext === "function") { api.skipToNext(); out.skipped = "instream"; }
      else if (overrideSkip("tripwire-contain")) { out.skipped = "override"; }
      if (out.skipped) {
        // Same shared advance clock the L1 path uses, so the guard that stops a
        // late ad object from skipping the song this skip started can see it.
        lastAdvanceAt = Date.now();
        inStreamSkipLockUntil = Date.now() + (CFG.inStreamSkipLockMs || 300);
        _counters.contained++;
      }
    } catch (e) { snifferLog("contain-error", { error: String((e && e.message) || e) }); }
    return out;
  }

  function installAdTripwire(ac) {
    if (CFG.adTripwire === false || window.__interceptify_tripwire || !ac) return;
    try {
      if (typeof ac.subscribeToInStreamAds !== "function") return;
      ac.subscribeToInStreamAds((msg) => {
        try {
          const ad = (msg && msg.ad) || msg;
          window.__interceptify_ads_delivered = (window.__interceptify_ads_delivered || 0) + 1;
          window.__interceptify_last_delivered = { t: Date.now(), id: (ad && (ad.adId || ad.id)) || null, format: ad && ad.format };
          snifferLog("TRIPWIRE-ad-delivered", { id: (ad && (ad.adId || ad.id)) || null, format: ad && ad.format });
          const ready = protectionReady();
          // CONTAIN FIRST, RECORD SECOND. Both branches contain: an ad arriving
          // before protection is established and one arriving through an
          // established block are different FAILURES to report, but they are the
          // same emergency to handle, and only one of them used to be handled at
          // all (with a mute the watchdog then undid).
          const contained = containDeliveredAd(ac, ad, ready);
          recordIncident("delivered", {
            id: (ad && (ad.adId || ad.id)) || null,
            format: ad && ad.format,
            slot: (ad && ad.slot) || null,
            audio: isAudioAd(ad),
            contained: contained,
          });
          if (!ready.ok) snifferLog("ad-before-protection-ready", { missing: ready.missing, contained });
        } catch {}
      });
      window.__interceptify_tripwire = true;
      window.__interceptify_ads_delivered = window.__interceptify_ads_delivered || 0;
    } catch {}
  }

  function suppressAdState(reason) {
    if (CFG.adEnabledKill === false) return false;
    try {
      const ac = (window.__interceptify_instream_api && window.__interceptify_instream_api.adsCoreConnector) || resolveAdsConnector();
      if (ac && typeof ac.putState === "function") {
        installAdTripwire(ac);
        refreshAdGate(ac);                                   // discover + verify (async, cached)
        // Verifier-controlled A/B: lets selftest OPEN the gate to prove its ad
        // trigger actually works, before trusting a "no ads" result.
        if (window.__interceptify_suspend_block === true) return false;
        // Never write before we've seen Spotify's own key set (see _baselineKeys).
        if (_baselineKeys === null) {
          clearAdSlots(ac, "pre-baseline");
          return false;
        }
        for (const k of adGateKeys()) { try { ac.putState(k, "false"); } catch {} }
        // Flush any ad already QUEUED before the block took hold (ad_enabled=false
        // only stops NEW scheduling; a pre-queued ad — e.g. one queued at startup —
        // still plays on the next transition unless cleared). No-op when no ad is
        // queued, so it's cheap to run every cycle.
        clearAdSlots(ac, reason);
        if (!window.__interceptify_ad_enabled_killed) {
          window.__interceptify_ad_enabled_killed = true;
          snifferLog("ad-enabled-killed", { reason });
        }
        return true;
      }
    } catch (e) { snifferLog("ad-enabled-error", { reason, error: String(e && e.message || e) }); }
    return false;
  }

  function neutralizeInStreamAd(api, ad, reason) {
    const summary = summarizeAdObject(ad);
    if (!summary) return false;
    streamTimeKill("ad:" + (reason || ""));   // SpotX-style pre-play kill, alongside the skip

    suppressAdUi(reason || "neutralize", 3000);
    rememberInStreamAd(ad, reason);
    rememberInStreamApiCall(`${reason}.neutralize`, { ad: summary });
    if (!blockInStreamSignal()) return false;
    try {
      const stableKey = inStreamAdKey(ad);
      const key = stableKey || `${Date.now()}`;
      // FRESH AUDIO ad object (format===AUDIO; first sighting of this adId since
      // we're inside the not-yet-skipped dedup block) -> authoritative -> skip
      // PRE-PAINT. Other/unknown format falls back to DOM-corroborated skipping.
      const audioAdAuthoritative = isAudioAd(ad);
      window.__interceptify_neutralized_ads = window.__interceptify_neutralized_ads || new Set();
      if (!window.__interceptify_neutralized_ads.has(key)) {
        window.__interceptify_neutralized_ads.add(key);
        if (api && typeof api.skipToNext === "function") {
          if (!stableKey) {
            // No stable adId/uri/clickthrough -> do NOT authorize a skip. A thin
            // /partial object must not drive skipToNext (its dedup key would be
            // an unstable timestamp -> re-skip storm onto whatever plays next).
            rememberInStreamApiCall("skipToNext.no-stable-key", { ad: summary });
          } else if (!inStreamSkipSafe(audioAdAuthoritative)) {
            // Over-skip guard tripped: suppress the skip. The ad object is still
            // nulled below (UI suppressed), and advance() will skip it once
            // CONFIRMED + fully gated, so a real ad is never leaked here.
            rememberInStreamApiCall("skipToNext.suppressed", { ad: summary });
          } else {
            try {
              rememberInStreamApiCall("skipToNext.forAd", { ad: summary });
              // MUTE INSTANTLY (before the skip) so the ~1.4s Spotify-core takes
              // to actually advance the audio is SILENT. We skip at ~+1ms but the
              // core keeps playing the ad audio until it processes the skip; the
              // FSM's own mute lags up to one 500ms tick (the <0.5s you hear).
              // The FSM unmutes on verified-advance when the real song starts.
              try { armMute(); } catch {}
              api.skipToNext();
              // ONE queue-advance clock for the whole payload. This skip
              // advances the queue exactly as advance() does, so it has to be
              // visible to everything that reasons about "we just advanced" -
              // otherwise the L1 path is invisible to the very guard that stops
              // a late ad object from skipping the song that skip started.
              lastAdvanceAt = Date.now();
              // Short SELF-lock (decoupled from the FSM's 1500ms cooldown) so the
              // NEXT ad of a multi-ad break skips almost immediately, while a
              // re-read of THIS ad is still blocked (dedup) + a real song that
              // just started is blocked (corroboration above goes false).
              inStreamSkipLockUntil = Date.now() + (CFG.inStreamSkipLockMs || 300);
              // Clear the lingering "instream-ad-object" WEAK window so it can't
              // make the FSM mute the REAL song that starts right after the skip
              // (the brief double-mute). The next ad re-sets it on arrival.
              try { window.__interceptify_instream_ad_until = 0; } catch {}
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
      try { killAdEndpoints("api-capture"); streamTimeKill("api-capture"); } catch {}
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
      // Every plausible name, plus anything already on window with the right
      // shape. Seeding is deliberate: this payload runs before the bundle, so
      // the array must exist for the bundle to push into.
      const names = (CFG.webpackChunkGlobals || ["rspackChunkclient_web"]).slice();
      try {
        for (const k of Object.keys(window)) {
          if (/Chunk[a-z_]*client_web$/i.test(k) && names.indexOf(k) < 0) names.push(k);
        }
      } catch {}
      window.__interceptify_chunk_globals = names;
      window.__interceptify_l1_fired = false;

      // If nothing ever pushes, the layer is dead and the old code had no way to
      // say so - the only diagnostic lived inside the callback that never ran.
      try {
        setTimeout(function () {
          if (window.__interceptify_l1_fired) return;
          const live = [];
          try {
            for (const k of Object.keys(window)) {
              if (/Chunk[a-z_]*client_web$/i.test(k) && (window[k] || []).length) live.push(k);
            }
          } catch {}
          window.__interceptify_l1_dead = { hooked: names, populated: live };
          recordIncident("l1-hook-dead", { id: "l1", format: null });
          log("L1 HOOK DEAD — hooked " + names.join(",") + " but the bundle used " +
              (live.join(",") || "none of them") + "; the fast in-stream layer is NOT running");
        }, CFG.l1WatchdogMs || 20000);
      } catch {}

      const chunkGlobal = names[0];
      const chunks = names.map(function (n) { return (window[n] = window[n] || []); });
      const chunk = window[chunkGlobal];
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
          // The factory has now RUN. "We replaced a factory" and "that factory
          // executed and produced something we could wrap" are different claims,
          // and only the first was ever reported - so a provider that was
          // swapped in but never instantiated (a lazy chunk nobody loaded)
          // reported the layer as installed.
          try {
            window.__interceptify_l1_provider_ran = true;
            const ex = (module && module.exports) || exports;
            wrapInStreamExports(ex);
            if (window.__interceptify_instream_api) window.__interceptify_l1_provider_active = true;
          } catch {}
          return result;
        };
        wrappedFactory.__interceptify_wrapped = true;
        return wrappedFactory;
      };
      // Wrap EVERY discovered in-stream module in a modules object (replaces
      // the literal modules[46849] lookup). Falls back to the literal hint id
      // only when the scan finds nothing.
      // Record what we ACTUALLY wrap (the diagnostic overlay reads this).
      // Recording that we wrapped the INTENDED provider is a different claim
      // from "the bundle pushed something through our wrapper", and health used
      // to report only the second one. Any unrelated chunk push set the L1-fired
      // flag, so a bundle-layout change could leave the ad provider completely
      // unwrapped while the layer still reported green.
      const _recordWrapped = (key) => {
        try {
          if (window.__interceptify_instream_module_ids.indexOf(String(key)) === -1)
            window.__interceptify_instream_module_ids.push(String(key));
          window.__interceptify_l1_provider_wrapped = true;
        } catch {}
      };
      // The known-good provider id present in `map`, else null. getInStreamAd+
      // inStreamApi can match MORE than the provider (this build also carries a
      // decoy 80755), and wrapping a non-provider destructively blanks the UI —
      // so per-chunk we wrap ONLY the fallback provider id. The source scan is a
      // whole-graph fallback used at bootstrap when that id is genuinely gone.
      // The hint id is only accepted if the module SITTING at it still looks like
      // the in-stream provider. Bundler ids are reused across builds, so "46849
      // exists" was never evidence that 46849 is still the provider - and because
      // the source scan only ran when the id was absent, a rebuild that moved the
      // provider and left something unrelated at the old id would wrap the wrong
      // module, report success, and block nothing.
      const providerKeyIn = (map, want) => {
        if (want == null || !map) return null;
        const key = map[want] ? want : (map[String(want)] ? String(want) : null);
        if (key == null) return null;
        const fn = map[key];
        if (typeof fn !== "function") return null;
        if (fn.__interceptify_wrapped) return key;      // already ours: it matched once
        try {
          if (!_factoryMatchesInstream(fn.__intc_orig || fn)) return null;
        } catch { return null; }
        return key;
      };
      const fbKeyIn = (map) => {
        // Whatever the whole-graph scan settled on wins, so chunks pushed after
        // bootstrap get the provider this build actually has rather than the one
        // the config remembers.
        const resolved = providerKeyIn(map, window.__interceptify_instream_id);
        if (resolved != null) return resolved;
        const fb = CFG.instreamModuleFallbackId;
        const key = providerKeyIn(map, fb);
        if (key == null && map && fb != null && (map[fb] || map[String(fb)])
            && !window.__interceptify_fallback_id_stale) {
          window.__interceptify_fallback_id_stale = String(fb);
          log("instreamModuleFallbackId " + fb + " is present but no longer looks like the ad " +
              "provider — using the source scan instead");
        }
        return key;
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
      // Sweep the modules ALREADY in every candidate array, not just the first.
      // Only chunks[0] used to be swept, so on a build where the provider had
      // arrived through a second chunk global it was never seen.
      chunks.forEach(function (arr) {
        try { arr.forEach((payload) => patchModules(payload && payload[1])); } catch {}
      });
      // Wrap EVERY candidate array. Wrapping only the first would leave the
      // fallbacks decorative, which is the same silent-miss the rename caused.
      // __interceptify_l1_fired is what tells the watchdog the layer is alive,
      // so it must only ever be set by a push the BUNDLE made. The raw push is
      // captured here, before wrapping, precisely so our own injection below
      // cannot trip our own liveness flag - a self-satisfying signal would make
      // the watchdog unable to fire and health permanently, falsely green.
      const rawPush = new Map();
      chunks.forEach(function (arr) {
        if (!arr || arr.__interceptify_wrapped_push) return;
        const push = arr.push.bind(arr);
        rawPush.set(arr, push);
        arr.push = function () {
          window.__interceptify_l1_fired = true;
          for (let i = 0; i < arguments.length; i++) {
            patchModules(arguments[i] && arguments[i][1]);
          }
          return push.apply(this, arguments);
        };
        try { Object.defineProperty(arr, "__interceptify_wrapped_push", { value: true }); } catch {}
      });
      // Bootstrap through EVERY candidate array, not only the first. Each chunk
      // global has its own webpack runtime and therefore its own module graph;
      // injecting into one of them left the others unreached, so a build that
      // moved the provider into a second runtime went unhooked while the layer
      // still reported alive.
      const bootstrapInto = (arr) => {
        // Falls back to the live push only for an array someone else already
        // wrapped, where no raw handle exists to take.
        const originalPush = rawPush.get(arr) || arr.push.bind(arr);
        originalPush([[`interceptify-${Date.now()}-${Math.round(performance.now())}`], {},
          function (require) {
        try {
          window.__interceptify_webpack_require = window.__interceptify_webpack_require || require;
          patchRequire(require);
          // Whole-graph view of require.m: prefer the known provider id; only if
          // it is genuinely absent (renamed build) wrap the SINGLE best source
          // match — never multiple (that is what blanked the UI).
          let id = fbKeyIn(require.m || {});
          if (id == null) {
            const matched = discoverInStreamModuleIds(require.m || {});
            id = matched.length ? matched[0] : null;
          }
          // Remember it, so later chunk pushes wrap this build's provider and
          // not whichever id the config was last told about.
          if (id != null) window.__interceptify_instream_id = id;
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
      };
      chunks.forEach(function (arr) { try { bootstrapInto(arr); } catch {} });
    } catch {}
  }

  // Hook installers are wrapped in try/catch so one failing layer cannot take
  // the rest of the payload down with it. That is right, but a bare `catch {}`
  // also means a layer can stop installing after a Spotify change and nothing
  // anywhere says so - which is how L1 stayed dead through the rspack rename.
  // The exception is kept out of the way AND kept.
  function tryInstall(name, fn) {
    try {
      fn();
      return true;
    } catch (e) {
      _layerErrors.push({ layer: name, error: String((e && e.message) || e), t: Date.now() });
      log("LAYER FAILED TO INSTALL: " + name + " — " + String((e && e.message) || e));
      return false;
    }
  }

  tryInstall("webpack-ad-provider", installWebpackAdProviderHook);

  // TOTAL BLOCK: proactively point the ad-state/ad-server endpoints at a dead URL
  // so ad breaks are never scheduled/fetched (not just reactively skipped). On
  // snapshot builds this first resurrects the connector from __webpack_modules__
  // (the ads chunk is lazy, so resolveAdsConnector retries until it appears; once
  // found the endpoint-kill is applied and re-applied to defend vs server resets).
  if (CFG.totalBlock !== false || CFG.killAdEndpoints !== false || CFG.snapshotConnector !== false || CFG.adEnabledKill !== false) {
    const applyTotalBlock = (reason) => {
      try { captureLiveRequire(); } catch {}   // best-effort: prefer the genuine live require
      try { resolveAdsConnector(); } catch {}   // find the lazy ads connector once loaded
      try { suppressAdState(reason); } catch {} // MASTER: ad_enabled=false -> ads never scheduled
      try { killAdEndpoints(reason); } catch {}
      try { streamTimeKill(reason); } catch {}
    };
    try { applyTotalBlock("init"); } catch {}
    // Fast cadence so the kill lands the moment the lazy ads chunk loads (before
    // the first ad); the connector + require are cached once found so this is cheap.
    try { setInterval(() => applyTotalBlock("interval"), CFG.totalBlockIntervalMs || 3000); } catch {}
    // Dedicated FAST re-apply of the master ad_enabled=false switch — the one lever
    // proven to prevent ad loading — so a product-state refresh can't reopen ads
    // for more than ~1s (endpoint/stream-time kills stay on the slower interval).
    try { setInterval(() => { try { suppressAdState("fast"); } catch {} }, CFG.adEnabledKillMs || 1000); } catch {}
  }

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
  // EXACTLY ONE window.fetch wrapper at a time (v1's duplicate second
  // reassignment is gone; its looksLikeAdUrl 403 layer is folded in below as
  // BLOCK 0).
  //
  // Re-assertable, not one-shot. This used to run once at bootstrap and install
  // only if window.fetch existed at that instant. Spotify's runtime replaces
  // window.fetch after our payload has run, which silently threw the wrapper
  // away - and health reported `fetch: false` for exactly that reason while the
  // self-heal still returned PASS. installFetchHook() re-wraps whatever fetch is
  // current, so a later replacement is repaired on the next maintenance tick
  // instead of ending the layer permanently.
  function installFetchHook() {
    if (!window.fetch || window.fetch.__interceptify_hooked) return false;
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
    return true;
  }

  tryInstall("fetch", installFetchHook);
  // Spotify's own runtime finishes booting well after we do, and whatever it
  // installs over window.fetch wins. Re-check on a short cadence early (when the
  // replacement happens) and then keep a slow watch running, because a lazily
  // loaded chunk can do it much later. Cheap: one property read per tick.
  (function watchFetchHook() {
    let fast = 0;
    const tick = () => {
      if (installFetchHook()) log("re-installed the fetch hook (Spotify had replaced window.fetch)");
      fast++;
      setTimeout(tick, fast < 40 ? 250 : 5000);
    };
    setTimeout(tick, 250);
  })();

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
        // Present a COMPLETE failed request, not just an error event.
        //
        // Firing "error" alone leaves readyState at OPENED forever. A caller
        // written against readyState/onreadystatechange - which is most XHR
        // code, including anything transpiled from an older library - never
        // observes the request finishing, so its promise never settles and
        // whatever it guards hangs. Blocking a request should look like a
        // network failure, and a real network failure still reaches DONE.
        const self = this;
        setTimeout(function () {
          try {
            Object.defineProperty(self, "readyState", { value: 4, configurable: true });
            Object.defineProperty(self, "status", { value: 0, configurable: true });
            Object.defineProperty(self, "responseText", { value: "", configurable: true });
          } catch {}
          for (const type of ["readystatechange", "error", "loadend"]) {
            try { self.dispatchEvent(new Event(type)); } catch {}
          }
        }, 0);
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
  // linger past audio end and are the v1 over-skip leftovers; they are hidden
  // via CFG.visualHideSelectors and can only ever arm the mute path).
  const STRONG_AD_SELECTORS = (CFG.strongAdSelectors || []).slice();
  // Visual-only ad surfaces — hidden via CSS, never used to skip/mute.
  const VISUAL_AD_SELECTORS = (CFG.visualHideSelectors || []).slice();

  // Hide visual-only ads with CSS so they never render.
  function injectAdHidingCSS() {
    if (CFG.inspectMode) return;        // inspect: keep ad UI visible/clickable
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
  //    call (CFG.seek15Burst clicks, all in this tick) — not a
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
        // Two very different events used to be recorded identically as "the user
        // heard an ad". armMute() is called from the CONFIRMED path (an ad is
        // genuinely painted and audible until this click lands) AND from the
        // SUSPECTED / pre-paint L1 paths, where muting is a cheap precaution
        // against something that may never have made a sound. Reporting the
        // second as a delivery failure is what drove the repair loop to "fix"
        // a system that was working, so the FSM's own confidence decides which
        // one this is.
        const confirmed = (adState === "CONFIRMED" || adState === "SKIPPING");
        recordIncident(confirmed ? "muted" : "speculative-mute",
                       { id: (window.__interceptify_last_delivered || {}).id || null });
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
  let inStreamSkipLockUntil = 0; // L1 in-stream skip self-lock (short; decoupled from cooldownUntil)
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
  const _adKeyPrimitives = Object.create(null); // adKey -> Set of primitives already used
  let lastSkipIssueAt = 0;    // when the last skip was issued (skipRetryMs gate)

  function fpEqual(a, b) {
    if (!a || !b) return false;
    return a.documentTitle === b.documentTitle && a.title === b.title && a.subtitle === b.subtitle;
  }
  // Does the current now-playing fingerprint look like an ad? (used to refuse
  // declaring a skip "successful" while still on an ad). Locale-aware: the old
  // English-only /advert/ missed Swedish "Annons"/"Reklam" etc., so a real ad
  // read as "not an ad" -> false verified-advance -> the ad got marked done and
  // never skipped (the 2026-06-15 post-update regression). Markers in CFG.
  function fpLooksLikeAd(fp) {
    try {
      if (!fp) return false;
      const re = rx(CFG.adTextMarkers || "advert", "i");
      if (!re) return false;
      if (re.test(fp.title || "")) return true;
      if (re.test(fp.subtitle || "")) return true;
      if (re.test(fp.documentTitle || "")) return true;
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
      if (CFG.inspectMode) { snifferLog("advance-suppressed", { source, reason: "inspect-mode" }); return false; }
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
      //
      // EXACTLY ONE primitive per call. Every one of these advances the play
      // queue on its own, and they all used to fire in the same pass: a single
      // ad decision could issue an override-skip, an in-stream skip, a next
      // click, a seek burst and a video-end before anything checked whether the
      // first had already worked. The dedupe keys made that survivable rather
      // than correct - the moment one of them landed a fraction later than
      // expected, the rest were operating on the next track.
      //
      // Now it is a ladder: fire the most reliable primitive that has not been
      // tried for this ad, then stop. If the ad is still there on the next tick,
      // the retry path re-runs the whole gate (still CONFIRMED, still strong,
      // now-playing still the ad) and only then escalates one rung. Retrying is
      // therefore always preceded by fresh confirmation, never assumed.
      const tried = _adKeyPrimitives[key] || (_adKeyPrimitives[key] = new Set());
      const ladder = [
        // PRIMARY on snapshot builds (1.2.93+): bypasses the Free skip-lock.
        ["override", () => overrideSkip("advance:" + key)],
        // PREFERRED on older builds: the in-stream API's own skip.
        ["instream", () => {
          const api = window.__interceptify_instream_api;
          if (!api || typeof api.skipToNext !== "function") return false;
          api.skipToNext();
          return true;
        }],
        // Native skip-forward click (self-gates: disabled/absent on songs).
        ["click", () => clickNextTrack()],
        // seek-forward-15 synchronous burst (absent on songs -> no-op).
        ["seek", () => spamSeekForward()],
        // ad-video-scoped 'ended' (blob src + strong marker this tick).
        ["video", () => killVideoAd()],
        // OFF by default; last resorts, still behind the full gate above.
        ["mediasource", () => CFG.enableMediaSourceEndOfStream && killCurrentMediaSources()],
        ["domspray", () => {
          if (!CFG.enableDomSprayLastResort) return false;
          domSprayLastResort();
          return true;
        }],
      ];

      let acted = false, usedPrimitive = null;
      for (const [name, fire] of ladder) {
        if (tried.has(name)) continue;
        tried.add(name);
        try {
          if (fire()) { acted = true; usedPrimitive = name; }
        } catch (e) {
          snifferLog("advance-primitive-error", { source, primitive: name, error: String(e && e.message || e) });
        }
        if (acted) break;
        // A primitive that reported "not applicable" (no button, no api, flag
        // off) has not touched playback, so moving to the next rung in the same
        // pass is safe - that is a selection step, not a second advance.
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
    if (CFG.inspectMode) return;        // inspect: let the ad play (audible)
    try { const was = _weMuted; muteAllAudio(true); if (_weMuted && !was) _diagLog("MUTED"); } catch {}
  }
  function armAdActive() {
    if (CFG.inspectMode) return;
    try {
      const was = window.__interceptify_ad_active;
      window.__interceptify_ad_active = true;
      applyAdActiveGains(true);
      if (!was) _diagLog("GAIN0");
    } catch {}
  }
  function releaseAdState(reason) {
    try { _diagLog("release", { reason: reason }); } catch {}
    // The FSM finished the ad, so the tripwire's provisional hold has been
    // superseded by a real lifecycle. Leaving it up would silence the song the
    // release is happening for.
    try { releaseContainment("ad-state-released:" + reason); } catch {}
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
        // The ceiling outranks a containment hold too. Nothing may keep audio
        // down past maxAdMs, whatever asked for it.
        releaseContainment("watchdog-maxad");
        releaseAdState("watchdog-maxad:" + reason);
        return;
      }
      // A containment hold is the tripwire asking the watchdog to WAIT: the ads
      // core handed us a real ad object and we muted before any UI existed to
      // corroborate it. Released early once the DOM can actually be consulted
      // and says the ad is gone - but never on a DOM that has not painted, which
      // is exactly the startup case the hold exists for.
      if (containmentHeld() && !window.__interceptify_ad_active) {
        let over = false;
        try {
          const fp = nowPlayingSnapshot();
          const painted = !!(fp && fp.title);
          over = painted && !STRONG_PRESENT() && !fpLooksLikeAd(fp)
                 && containmentAgeMs() > (CFG.tripwireMinHoldMs | 0);
        } catch {}
        if (over) releaseContainment("now-playing-is-not-an-ad");
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
      // ...unless a containment hold is live. This is the clause that made the
      // pre-readiness mute useless: it saw ad_active === false (the tripwire
      // never set it) and un-muted an ad that was still playing.
      if (!window.__interceptify_ad_active && !containmentHeld()) {
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
        // VERIFIED only when the ad-controls marker is GONE (!strong). now-playing
        // TEXT is unreliable across locales (Swedish "Annons"/"Reklam" ARE ads but
        // don't match /advert/) and changes mid-break while an ad still plays;
        // ad-controls unmounts cleanly with the ad audio (verified live on the
        // 2026-06-15 build), so it is the authoritative "ad ended" signal. Using
        // text here marked a still-playing ad "satisfied", then advance() refused
        // to re-skip it (adKey-satisfied) and the ad played out fully, muted.
        const verifiedAdvance = !strong && !fpEqual(fpN, preAdNowPlaying);
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
        // STILL on an ad (strong) but now-playing MOVED -> skipToNext advanced us
        // to the NEXT ad of a multi-ad break. Re-confirm with a FRESH key/fp so it
        // gets its own gated skip: a new "advance:" dedup key lets skipToNext fire
        // again (reusing the prior key no-ops it, leaving the ad stuck muted).
        if (!fpEqual(fpN, preAdNowPlaying)) {
          currentAdKey = mintAdKey(strongMarker);
          currentAdFp = fpN;
          preAdNowPlaying = fpN;
          confirmedSinceAt = Date.now();
          adState = "CONFIRMED";
          break;
        }
        // same ad still showing after our skip -> retry ONCE after skipRetryMs, capped.
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
          // Break fully over -> RESET per-break skip bookkeeping. adKeys are
          // DOM-fingerprint based and COLLIDE across breaks (subtitle "Annons N
          // av M" / "1 av 2" recurs), so a satisfied key from a prior break
          // would permanently suppress an identical-looking future ad
          // (advance-suppressed: adKey-satisfied — the observed bug).
          //
          // The escalation ladder is per-break state for the same reason: a key
          // that had exhausted every primitive last time must start again from
          // the top, or the second identical break gets no skip at all.
          // Per-ad in-stream neutralize keys (unique ad ids) are kept.
          _satisfiedAdKeys.clear();
          for (const k in _adKeyRetries) delete _adKeyRetries[k];
          for (const k in _adKeyPrimitives) delete _adKeyPrimitives[k];
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
    version: "2026-07-29-honest-verify",
    debugCapture: DEBUG_CAPTURE,
    // Machine-readable health, for the automated repair loop (selfheal.py) and
    // for a human over CDP. Cheap, no side effects.
    health() {
      const gate = window.__interceptify_ad_gate || null;
      const _ready = protectionReady();
      return {
        version: window.__interceptify.version,
        connector: !!window.__interceptify_ads_connector,
        gateKeys: gate ? gate.keys : null,
        gateVerified: !!(gate && gate.verified),
        adsDelivered: window.__interceptify_ads_delivered || 0,
        lastDelivered: window.__interceptify_last_delivered || null,
        // Always-on since page load, independent of debug capture. This is the
        // only ad-outcome record that exists in a production patch.
        counters: { ..._counters },
        debugCaptureOn: DEBUG_CAPTURE,   // says whether the sniffer-based views mean anything
        webpackModules: (() => { try { return Object.keys(window.__webpack_modules__ || {}).length; } catch { return 0; } })(),
        // L1 = the fast in-stream skip layer. It hangs off the bundler chunk
        // array, and when Spotify renamed that (webpack -> rspack) the layer
        // died silently for weeks. Surfaced here so the repair loop can fail on
        // it instead of only the in-page log knowing.
        l1Hooked: !!window.__interceptify_l1_fired,
        l1Dead: window.__interceptify_l1_dead || null,
        // Per-layer attachment, read from EVIDENCE that the hook is in place -
        // not from "the installer ran without throwing". Those are different
        // claims, and only the first one survives a Spotify rebuild.
        layers: {
          fetch: !!(window.fetch && window.fetch.__interceptify_hooked),
          xhr: !!(typeof XMLHttpRequest !== "undefined"
                  && XMLHttpRequest.prototype.__interceptify_url_block_hooked),
          // The bundle is pushing through our wrapper. Necessary for L1, and on
          // its own it says nothing about the ad provider: ANY chunk push sets
          // it, so a bundle-layout change could leave the provider unwrapped
          // with this still green. l1Provider is the claim that matters.
          l1Chunk: !!window.__interceptify_l1_fired,
          // The provider factory was REPLACED. Necessary, and deliberately still
          // what readiness requires: on a build where nothing ever loads the ads
          // chunk the factory legitimately never runs, and demanding execution
          // would make readiness depend on the user encountering an ad path.
          // l1ProviderRan / l1ProviderActive below are the stronger claims, and
          // they are reported separately rather than folded into this one.
          l1Provider: !!window.__interceptify_l1_provider_wrapped,
          instreamApi: !!window.__interceptify_instream_api,
          adsConnector: !!window.__interceptify_ads_connector,
          adGate: !!(gate && gate.verified),
        },
        l1ProviderRan: !!window.__interceptify_l1_provider_ran,
        l1ProviderActive: !!window.__interceptify_l1_provider_active,
        instreamModuleIds: (window.__interceptify_instream_module_ids || []).slice(),
        baselineEmptyReads: window.__interceptify_baseline_empty_reads || 0,
        // Loaded is not protective. See protectionReady().
        protectionReady: _ready.ok,
        notReady: _ready.missing,
        slotClearConfirmed: window.__interceptify_slot_clear.ok === true,
        slotClear: { ...slotClearState() },
        adSlots: (function () { try { return adSlots(); } catch { return null; } })(),
        discoveredSlots: window.__interceptify_discovered_slots || null,
        primarySlot: (function () { try { return primarySlot(); } catch { return null; } })(),
        primarySlotPromoted: window.__interceptify_primary_slot || null,
        gateReadAgeMs: (function () { const g = window.__interceptify_ad_gate;
          return (g && g.readAt) ? Date.now() - g.readAt : null; })(),
        gateError: (window.__interceptify_ad_gate || {}).error || null,
        adEndpoints: window.__interceptify_ad_endpoints || null,
        containHeldMs: (function () { try {
          return containmentHeld() ? window.__interceptify_contain_until - Date.now() : 0; } catch { return 0; } })(),
        layerErrors: _layerErrors.slice(-20),
        chunkGlobals: window.__interceptify_chunk_globals || null,
        liveRequire: !!window.__interceptify_webpack_require,
      };
    },
    // STRUCTURAL self-test. Named for what it actually establishes.
    //
    // WHAT IT PROVES: the block's machinery is present and under our control.
    // Spotify's own ad-state switch moves both ways when we write it, the core
    // echoes the value back, the maintenance loop re-closes the gate unaided
    // after we reopen it, the delivery tripwire is armed, and every layer is
    // attached. That is state plumbing, and it is worth proving.
    //
    // WHAT IT DOES NOT PROVE: that closing the gate PREVENTS an ad. There is no
    // controlled positive control here - we cannot make the server schedule an
    // ad on demand, so "the gate was open and an ad arrived / the gate was
    // closed and it did not" is not a comparison this test can make. Ads are
    // server-scheduled; a fresh client delivers none whatever the gate says.
    //
    // So a pass here must NEVER be used to clear a RECORDED delivery: the
    // tripwire logging an ad that reached the user is direct evidence about the
    // thing this test can only approach indirectly. selfheal.py keeps an
    // unresolved-delivery flag that a structural pass cannot clear.
    // Three-valued on purpose:
    //   FAIL    -> the gate proof broke, OR something ad-shaped was observed
    //              (delivery, ad UI, or a reactive skip/mute: an ad reached
    //              playback). A positive observation is always meaningful.
    //   UNKNOWN -> the gate proof held, but no audio streamed during the window.
    //              "No ads appeared" while nothing was playing is entailed by the
    //              silence, not by the block, so it is not a pass.
    //   PASS    -> the gate proof held AND the window actually exercised playback
    //              AND nothing ad-shaped occurred.
    // ======================================================================
    // VERIFICATION — deterministic, end to end, and independent of where the
    // user happens to be in the app. It follows Spotify's OWN ad path in code:
    //   adsCoreConnector.getAdState() / .putState()  (the core ad scheduler)
    //   adsCoreConnector.subscribeToInStreamAds()    (the ad delivery channel)
    //
    // Every way this check could lie has been closed:
    //  * "0 ads seen" might just mean none was due   -> never the proof on its own;
    //                                                   the proof is a CAUSAL TOGGLE
    //                                                   of Spotify's own switch.
    //  * a key we invented reads back fine           -> gate keys must come from the
    //                                                   BASELINE set Spotify itself
    //                                                   published before we wrote.
    //  * our write might be a phantom / no-op        -> we move the switch BOTH ways
    //                                                   and require the core to echo.
    //  * the block might apply once then die         -> we reopen it and require our
    //                                                   maintenance loop to re-close.
    //  * the ad detector might be dead (0 forever)   -> the tripwire must be armed.
    // Nothing here depends on navigation, playback position, or the current page.
    // ======================================================================
    structuralSelftest(opts) {
      opts = opts || {};
      const observeMs = opts.durationMs || 12000;
      const sampleMs = opts.sampleMs || 50;
      const ac = window.__interceptify_ads_connector || null;
      const adRe = /Reklam|Annons|Advertisement|Werbung|Publicidad|Anuncio/i;
      if (!ac || typeof ac.putState !== "function" || typeof ac.getAdState !== "function") {
        return Promise.resolve({ verdict: "FAIL", connector: false, reasons: ["ads connector not reachable"] });
      }
      const readState = () => ac.getAdState().then((s) => {
        const o = {}; const st = (s && s.state) || {};
        for (const k in st) { try { o[k] = String(st[k].value); } catch {} }
        return o;
      });
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

      return (async () => {
        const reasons = [];
        const baseline = window.__interceptify_baseline_keys || [];
        const gate0 = window.__interceptify_ad_gate || null;
        const keys = (gate0 && gate0.keys && gate0.keys.length) ? gate0.keys.slice() : [];
        const tripwireArmed = window.__interceptify_tripwire === true;
        if (!tripwireArmed) reasons.push("ad-delivery tripwire not armed (an ad could pass uncounted)");
        if (!keys.length) reasons.push("no ad-gate key discovered from Spotify's own ad state");
        const fromBaseline = keys.length > 0 && keys.every(function (k) { return baseline.indexOf(k) !== -1; });
        if (keys.length && !fromBaseline) reasons.push("gate key is not one Spotify published (phantom key we created)");

        // ---- CAUSAL TOGGLE PROOF (pure state, no UI dependency) -----------
        let toggleProven = false, reassertProven = false;
        if (fromBaseline) {
          window.__interceptify_suspend_block = true;      // pause our 1s maintenance loop
          let allTrue = false, allFalse = false;
          try {
            for (const k of keys) { try { ac.putState(k, "true"); } catch (e) {} }
            await sleep(1200);
            const opened = await readState();
            allTrue = keys.every(function (k) { return String(opened[k]).toLowerCase() === "true"; });
            for (const k of keys) { try { ac.putState(k, "false"); } catch (e) {} }
            await sleep(1200);
            const closed = await readState();
            allFalse = keys.every(function (k) { return String(closed[k]).toLowerCase() === "false"; });
            toggleProven = allTrue && allFalse;
            if (!allTrue) reasons.push("could not OPEN the gate — our write is not reaching core state");
            if (!allFalse) reasons.push("could not CLOSE the gate — our write is not reaching core state");
            // leave it OPEN so the maintenance loop has something to fix
            for (const k of keys) { try { ac.putState(k, "true"); } catch (e) {} }
            await sleep(600);
          } finally {
            window.__interceptify_suspend_block = false;   // maintenance resumes
          }
          await sleep(3500);
          const after = await readState();
          reassertProven = keys.every(function (k) { return String(after[k]).toLowerCase() === "false"; });
          if (!reassertProven) reasons.push("block did not re-assert itself after the gate was reopened");
        }

        // ---- ESTABLISH THE CONTROL ----------------------------------------
        // The observation window is only meaningful while audio is streaming,
        // and verification necessarily restarts Spotify, which leaves it
        // paused. Without this the run can only ever return UNKNOWN, the state
        // file never records a pass, and every scheduled run restarts Spotify
        // again chasing a verdict it structurally cannot reach.
        //
        // So the test starts playback itself rather than hoping. If it cannot,
        // it says so and the verdict stays UNKNOWN - the honest outcome, not a
        // silent downgrade.
        const streamTime = async () => parseInt((await readState()).elapsed_stream_time, 10) || 0;
        let startedByTest = false;
        {
          const a = await streamTime();
          await sleep(1200);
          if ((await streamTime()) === a) {           // nothing is streaming
            try {
              const btn = document.querySelector(
                '[data-testid="' + (CFG.playPauseTestId || "control-button-playpause") + '"]');
              if (btn) { btn.click(); startedByTest = true; }
            } catch (e) {}
            await sleep(2500);                        // let the stream spin up
          }
        }

        // ---- OBSERVATION WINDOW -------------------------------------------
        // Opportunistic provocation while watching for ANY ad-shaped event.
        // Absence of ads here is corroboration, never the proof.
        const t0 = Date.now();
        const adsBefore = window.__interceptify_ads_delivered || 0;
        const c0 = { ..._counters };          // snapshot: deltas, not lifetime totals
        const s0 = await readState();
        let adUiFrames = 0, firstAdUiAt = null;
        const sampler = setInterval(function () {
          try {
            const ui = !!document.querySelector('[data-testid="ad-controls"],[data-testid="ad-countdown-timer"],[data-testid="ads-video-player-npv"]')
                     || adRe.test(document.title || "");
            if (ui) { adUiFrames++; if (firstAdUiAt === null) firstAdUiAt = Date.now() - t0; }
          } catch (e) {}
        }, sampleMs);
        const driver = setInterval(function () {
          try { ac.putState("last_ad_break_stream_time", "0"); } catch (e) {}
        }, 1500);
        await sleep(observeMs);
        clearInterval(sampler); clearInterval(driver);
        const s1 = await readState();

        // Leave the client as we found it. The user did not ask for music to
        // start; a check that quietly leaves playback running has changed the
        // thing it was supposed to observe.
        if (startedByTest) {
          try {
            const btn = document.querySelector(
              '[data-testid="' + (CFG.playPauseTestId || "control-button-playpause") + '"]');
            if (btn) btn.click();
          } catch (e) {}
        }

        const adsDelivered = (window.__interceptify_ads_delivered || 0) - adsBefore;
        // Reactive actions come from the always-on counters. They used to be
        // counted by filtering the sniffer buffer, which snifferLog() only fills
        // when DEBUG_CAPTURE is on - and self-heal always patches with it off.
        // So this term was structurally zero in every automated run: the check
        // could not fail, which made its contribution to PASS worth nothing.
        const reactiveActions = (_counters.muted - c0.muted) + (_counters.skipped - c0.skipped);
        const speculativeMutes = _counters.speculativeMute - c0.speculativeMute;

        // Spotify's own counter for how much audio actually streamed. The UNIT
        // here is Spotify's and is NOT assumed to be milliseconds, so the test
        // is "did it move at all", which is true regardless of unit. A magnitude
        // threshold would silently encode a guess about the unit.
        const streamedDelta = (parseInt(s1.elapsed_stream_time, 10) || 0) - (parseInt(s0.elapsed_stream_time, 10) || 0);
        const playbackObserved = streamedDelta > 0;
        const gateClosed = keys.length > 0 && keys.every(function (k) { return String(s1[k]).toLowerCase() === "false"; });

        if (adsDelivered) reasons.push("core delivered " + adsDelivered + " ad(s) during the window");
        if (adUiFrames) reasons.push("ad UI was on screen for " + adUiFrames + " sample(s)");
        if (reactiveActions) reasons.push("reactive skip/mute fired " + reactiveActions + "x (an ad reached playback)");
        if (!gateClosed) reasons.push("ad gate is not closed at end of window");

        // ---- ARE THE LAYERS ACTUALLY THERE ---------------------------------
        // Read at the END of the window, when every lazily-loaded chunk has had
        // time to arrive. A run once reported PASS while its own health said
        // fetch, l1Chunk and adGate were all missing: the gate toggle was being
        // proven through a connector reached by one route, and nothing required
        // the rest of the advertised block to exist. The toggle proof is real,
        // but it is a proof about one layer, not about the product.
        //
        // instreamApi is NOT required: it only exists once Spotify hands over an
        // in-stream ad object, so requiring it would make an ad-free session -
        // the outcome we are testing for - impossible to pass.
        const liveLayers = window.__interceptify.health().layers || {};
        const missingLayers = ["fetch", "xhr", "l1Chunk", "l1Provider", "adsConnector", "adGate"]
          .filter(function (k) { return !liveLayers[k]; });
        if (missingLayers.length)
          reasons.push("block layers not installed: " + missingLayers.join(", "));

        // Hooks attached is not the same as protection established. The gate has
        // to have been written AND read back closed, and the interruptive audio
        // slot has to have been flushed with an acknowledgement - measured, that
        // takes ~3.6s after a Spotify start, during which every layer already
        // reports attached.
        const ready = protectionReady();
        if (!ready.ok)
          reasons.push("protection not established: " + ready.missing.join(", "));

        // The block is PROVEN by the causal toggle: we move Spotify's own switch
        // both ways, the core echoes it, and our maintenance loop re-closes it
        // unaided. None of that depends on what is playing. It is necessary, not
        // sufficient - every layer has to be attached as well.
        const proven = tripwireArmed && fromBaseline && toggleProven && reassertProven
                       && gateClosed && missingLayers.length === 0 && ready.ok;
        // A positive observation is always meaningful, whatever was playing.
        const observedFailure = adsDelivered > 0 || adUiFrames > 0 || reactiveActions > 0;

        // ...but the ABSENCE of ads only means something if the window actually
        // exercised the thing under test. With nothing streaming, "no ads
        // appeared" is guaranteed by the silence, not by the block, so calling
        // that PASS reports a fact the run never established.
        let verdict;
        if (observedFailure || !proven) verdict = "FAIL";
        else if (!playbackObserved) {
          verdict = "UNKNOWN";
          reasons.push("no audio streamed during the window, so 'no ads appeared' " +
                       "is not evidence: the gate proof passed but nothing exercised it");
        } else verdict = "PASS";

        return {
          verdict: verdict,
          // Says plainly what a PASS covers, so no caller can read it as "no ad
          // reached the user". It cannot: nothing here schedules an ad.
          scope: "structural",
          provesAdPrevention: false,
          reasons: reasons,
          version: window.__interceptify.version,
          connector: true,
          tripwireArmed: tripwireArmed,
          gateKeys: keys,
          gateFromBaseline: fromBaseline,
          baselineKeyCount: baseline.length,
          toggleProven: toggleProven,       // we can move Spotify's real switch both ways
          reassertProven: reassertProven,   // the block re-closes it by itself
          gateClosed: gateClosed,
          layers: liveLayers,
          missingLayers: missingLayers,
          protectionReady: ready.ok,
          notReady: ready.missing,
          slotClear: { ...window.__interceptify_slot_clear },
          adSlots: (function () { try { return adSlots(); } catch { return null; } })(),
          proven: proven,
          adsDelivered: adsDelivered,
          adUiFrames: adUiFrames,
          firstAdUiAt: firstAdUiAt,
          reactiveActions: reactiveActions,
          speculativeMutes: speculativeMutes,   // precautionary, NOT a delivery
          streamedDelta: streamedDelta,         // Spotify's unit, not assumed to be ms
          playbackObserved: playbackObserved,
          startedByTest: startedByTest,   // did the check have to start playback itself
          observeMs: observeMs,
        };
      })();
    },
    // Old name, kept so an older self-heal or a hand-typed console call still
    // works. It was always the structural test; only the name was flattering.
    selftest(opts) { return window.__interceptify.structuralSelftest(opts); },
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
        inStreamLockActive: safe(() => Date.now() < inStreamSkipLockUntil, null),
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

  // High-frequency in-stream poll: skip the AUDIO ad the instant the provider
  // populates getInStreamAd(), beating the 500ms FSM tick AND the confirmTicks
  // debounce. Song-safe: routed through neutralizeInStreamAd -> inStreamSkipSafe
  // (requires a live ad signal: ad-controls/ad-countdown present, OR ad-looking
  // now-playing, OR ad_active) + a stable adId. A real song has no ad object
  // (early-return) AND no live ad signal, so it can never be skipped here.
  if (CFG.enableInStreamPoll !== false && CFG.enableInstreamHook !== false) {
    setInterval(() => {
      try {
        const api = window.__interceptify_instream_api;
        if (!api || !blockInStreamSignal()) return;
        let ad = null;
        try { ad = (typeof api.getInStreamAd === "function") ? api.getInStreamAd() : api.inStreamAd; } catch {}
        if (ad && (ad.adId || ad.id || ad.uri) && summarizeAdObject(ad)) {
          neutralizeInStreamAd(api, ad, "instream-poll");
        }
      } catch {}
    }, CFG.inStreamPollMs || 80);
  }
  log("loaded (v2 FSM)");
})();
