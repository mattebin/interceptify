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

  // Visible signal the script loaded — adds a small green dot to the top-right
  // corner of the Spotify window. No DevTools needed to confirm.
  // Set window.__INTERCEPTIFY_SHOW_BADGE = false (injected at patch time)
  // to suppress it.
  const SHOW_BADGE = window.__INTERCEPTIFY_SHOW_BADGE !== false;
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
  const AD_URL_SIGNALS = [
    "/ads/",
    "/ad-logic/",
    "/gabo-receiver-service/",
    "/pagead",
    "doubleclick.net",
    "adeventtracker",
  ];

  function looksLikeAdUrl(url) {
    if (typeof url !== "string") {
      try { url = String(url); } catch { return false; }
    }
    return AD_URL_SIGNALS.some((s) => url.includes(s));
  }

  const _fetch = window.fetch;
  window.fetch = function (input, init) {
    try {
      const url = typeof input === "string" ? input : input && input.url;
      if (url && looksLikeAdUrl(url)) {
        log("blocked fetch:", url);
        try { setBadgeState("blocked"); setTimeout(() => setBadgeState(wasAd ? "ad" : "idle"), 800); } catch {}
        return Promise.resolve(
          new Response("{}", { status: 403, headers: { "Content-Type": "application/json" } })
        );
      }
    } catch {}
    return _fetch.apply(this, arguments);
  };

  const _xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__interceptify_url = url;
    return _xhrOpen.apply(this, arguments);
  };
  const _xhrSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (body) {
    if (looksLikeAdUrl(this.__interceptify_url)) {
      log("blocked xhr:", this.__interceptify_url);
      // Simulate a dead request — fire error after a microtask
      setTimeout(() => this.dispatchEvent(new Event("error")), 0);
      return;
    }
    return _xhrSend.apply(this, arguments);
  };

  // ------------------------------------------------------------------
  // 2 + 3. Detect ad playback and skip / mute
  // ------------------------------------------------------------------

  function isAdPlaying() {
    // Spotify marks ad context on the "now playing" title area.
    // Historically any of these have existed — check broadly.
    const sels = [
      '[data-testid="context-item-info-ad-title"]',
      '[data-testid="context-item-info"][aria-label*="Advertisement" i]',
      '[aria-label*="Advertisement" i][data-testid*="track"]',
    ];
    for (const s of sels) {
      if (document.querySelector(s)) return true;
    }
    // Also inspect the <title> — while an ad plays it often reads "Spotify" (music titles name the track)
    const titleEl = document.querySelector('[data-testid="context-item-link"]');
    if (titleEl && /advert/i.test(titleEl.textContent || "")) return true;
    return false;
  }

  function clickNextTrack() {
    const btn = document.querySelector('[data-testid="control-button-skip-forward"]');
    if (btn && !btn.disabled) { btn.click(); return true; }
    return false;
  }

  function muteAllAudio(muted) {
    document.querySelectorAll("audio, video").forEach((el) => {
      el.muted = muted;
      if (muted) el.volume = 0;
    });
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

  let wasAd = false;
  function check() {
    const isAd = isAdPlaying();
    if (isAd && !wasAd) {
      log("ad detected — attempting skip");
      setBadgeState("ad");
      muteAllAudio(true);
      // Try to advance. Spotify Free blocks "skip" on ads, but sometimes
      // seeking to the end works — try both.
      if (!clickNextTrack()) {
        const audio = document.querySelector("audio");
        if (audio && isFinite(audio.duration)) {
          try { audio.currentTime = Math.max(0, audio.duration - 0.25); } catch {}
        }
      }
    } else if (!isAd && wasAd) {
      log("ad ended — unmuting");
      setBadgeState("idle");
      muteAllAudio(false);
    }
    wasAd = isAd;
  }

  // Poll every 500ms. Mutation observers are flakier across Spotify rebuilds
  // because the mounted component changes; a simple poll is more robust.
  setInterval(check, 500);
  log("loaded");
})();
