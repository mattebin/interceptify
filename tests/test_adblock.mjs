/*
 * Interceptify v2 — dependency-free regression test for extensions/adblock.js
 *
 * Loads the real adblock.js IIFE inside a node:vm sandbox with a minimal but
 * sufficient browser-ish global stub, then exercises two invariants:
 *
 *   TEST A  NO OVER-SKIP — the critical one. An audio ad must trigger >=1
 *           skip/advance, but the ad->song transition (including a lingering
 *           weak ad text node for one tick) must trigger ZERO additional
 *           advances on the real song, and the FSM must settle to COOLDOWN/IDLE.
 *           A weak-only "SUSPECTED" signal must never advance (mute-only).
 *
 *   TEST B  MANIFEST CLASSIFIER — /manifests/.../options responses are passed
 *           through by default (manifestDurationBlock OFF), blocked to
 *           {"contents":[]} only when durationBlock is ON + short + corroborated,
 *           and passed through for long (music-duration) manifests.
 *
 * Nothing here touches adblock.js. Everything is driven through the captured
 * check() tick and the captured window.fetch. A controllable virtual clock makes
 * the cooldown / anti-spin / retry windows deterministic.
 *
 * Run:  node tests/test_adblock.mjs    (from the "interceptify v2" dir)
 */

import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ADBLOCK_PATH = path.resolve(__dirname, "..", "extensions", "adblock.js");
const ADBLOCK_SRC = fs.readFileSync(ADBLOCK_PATH, "utf8");

// ---------------------------------------------------------------------------
// Assertion harness
// ---------------------------------------------------------------------------
const results = [];
function assert(label, cond, detail) {
  results.push({ label, pass: !!cond, detail: detail || "" });
}

// ---------------------------------------------------------------------------
// Controllable virtual clock. The IIFE leans on Date.now() for cooldown,
// anti-spin, retry and watchdog windows; a real wall-clock would barely move
// between manually-driven ticks. We feed it a mutable clock instead.
// ---------------------------------------------------------------------------
function makeClock(start = 1_000_000) {
  const state = { now: start };
  class FakeDate extends Date {
    constructor(...args) {
      if (args.length === 0) super(state.now);
      else super(...args);
    }
    static now() { return state.now; }
  }
  return { state, FakeDate, advance: (ms) => { state.now += ms; } };
}

// ---------------------------------------------------------------------------
// DOM fixture. A mutable description of "what is painted right now". The DOM
// stub's querySelector / querySelectorAll read from it so the test can flip
// between "ad painted", "real song", and "lingering node" states.
// ---------------------------------------------------------------------------
function makeFixture() {
  return {
    // set of data-testid selector strings currently "present" (exact-match)
    present: new Set(),
    // now-playing title text (read via [data-testid="context-item-link"])
    nowPlayingTitle: "",
    // now-playing subtitle text (read via context-item-info-subtitle / -ad-subtitle)
    nowPlayingSubtitle: "",
    documentTitle: "",
    // button behavior knobs
    skipForwardDisabled: false,
    skipForwardVisible: true,
    seek15Visible: false,
    muteVisible: true,
    // click counters
    counts: {
      skipForwardClicks: 0,
      seek15Clicks: 0,
      muteClicks: 0,
      skipToNext: 0,
    },
  };
}

// ---------------------------------------------------------------------------
// Node stubs returned by document.createElement and matched by querySelector.
// ---------------------------------------------------------------------------
function makeGenericNode(tag = "div") {
  const node = {
    tagName: (tag || "div").toUpperCase(),
    _attrs: {},
    _children: [],
    style: {},
    textContent: "",
    id: "",
    offsetParent: {},      // visible by default (non-null)
    disabled: false,
    setAttribute(k, v) { this._attrs[k] = String(v); if (k === "id") this.id = String(v); },
    getAttribute(k) { return Object.prototype.hasOwnProperty.call(this._attrs, k) ? this._attrs[k] : null; },
    removeAttribute(k) { delete this._attrs[k]; },
    appendChild(c) { this._children.push(c); return c; },
    addEventListener() {},
    removeEventListener() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
    click() {},
  };
  // cssText support for the badge / style nodes
  Object.defineProperty(node.style, "cssText", { value: "", writable: true });
  return node;
}

// ---------------------------------------------------------------------------
// Build a fresh sandbox + load adblock.js. Returns the captured surfaces.
// ---------------------------------------------------------------------------
function loadAdblock({ fixture, clock, baseFetch, config }) {
  // ---- captured handles ----
  let checkTick = null;        // fn passed to setInterval(fn, 500) == CFG.tickMs
  let installedFetch = null;   // window.fetch after adblock wraps baseFetch
  const intervals = [];        // [{fn, ms}]
  const timeouts = [];         // [{fn, ms}]

  // ---- button / interactive nodes wired to the fixture ----
  const skipForwardNode = (() => {
    const n = makeGenericNode("button");
    n.setAttribute("data-testid", "control-button-skip-forward");
    Object.defineProperty(n, "disabled", { get: () => fixture.skipForwardDisabled });
    Object.defineProperty(n, "offsetParent", { get: () => (fixture.skipForwardVisible ? {} : null) });
    n.click = () => { fixture.counts.skipForwardClicks++; };
    return n;
  })();
  const seek15Node = (() => {
    const n = makeGenericNode("button");
    n.setAttribute("data-testid", "control-button-seek-forward-15");
    Object.defineProperty(n, "offsetParent", { get: () => (fixture.seek15Visible ? {} : null) });
    n.click = () => { fixture.counts.seek15Clicks++; };
    return n;
  })();
  const muteNode = (() => {
    const n = makeGenericNode("button");
    n.setAttribute("data-testid", "volume-bar-toggle-mute-button");
    n._muted = false;
    Object.defineProperty(n, "offsetParent", { get: () => (fixture.muteVisible ? {} : null) });
    n.getAttribute = (k) => {
      if (k === "aria-pressed") return n._muted ? "true" : "false";
      if (k === "data-testid") return "volume-bar-toggle-mute-button";
      return null;
    };
    n.querySelector = () => null; // no svg child -> aria-pressed drives state
    n.click = () => { fixture.counts.muteClicks++; n._muted = !n._muted; };
    return n;
  })();

  // now-playing title node (text driven by fixture)
  const nowPlayingTitleNode = makeGenericNode("a");
  nowPlayingTitleNode.setAttribute("data-testid", "context-item-link");
  Object.defineProperty(nowPlayingTitleNode, "textContent", { get: () => fixture.nowPlayingTitle });

  const nowPlayingSubtitleNode = makeGenericNode("div");
  nowPlayingSubtitleNode.setAttribute("data-testid", "context-item-info-subtitle");
  Object.defineProperty(nowPlayingSubtitleNode, "textContent", { get: () => fixture.nowPlayingSubtitle });

  // A weak lingering ad-subtitle node (only "present" when fixture lists it).
  const adSubtitleNode = makeGenericNode("div");
  adSubtitleNode.setAttribute("data-testid", "context-item-info-ad-subtitle");
  Object.defineProperty(adSubtitleNode, "textContent", { get: () => fixture.nowPlayingSubtitle });

  // ---- selector resolver ----
  // Exact single-selector lookups the adblock code performs. Returns a node or null.
  function resolveSingle(sel) {
    // now-playing reads
    if (sel === '[data-testid="context-item-link"]') {
      return (fixture.nowPlayingTitle !== "" || fixture.present.has(sel)) ? nowPlayingTitleNode : null;
    }
    if (sel === '[data-testid="context-item-info-title"]') return null;
    if (sel === '[data-testid="now-playing-widget"] a') return null;
    if (sel === '[data-testid="context-item-info-subtitle"]') {
      return fixture.nowPlayingSubtitle !== "" ? nowPlayingSubtitleNode : null;
    }
    if (sel === '[data-testid="context-item-info-ad-subtitle"]') {
      return fixture.present.has(sel) ? adSubtitleNode : null;
    }
    // buttons
    if (sel === '[data-testid="control-button-skip-forward"]') return skipForwardNode;
    if (sel === '[data-testid="control-button-seek-forward-15"]') {
      return fixture.seek15Visible ? seek15Node : null;
    }
    if (sel === '[data-testid="volume-bar-toggle-mute-button"]') {
      return fixture.muteVisible ? muteNode : null;
    }
    // installed style markers (getElementById handles these elsewhere)
    // any other exact selector: present iff in the fixture set
    if (fixture.present.has(sel)) return makeGenericNode("div");
    return null;
  }

  // document.querySelector handles BOTH single selectors and the comma-joined
  // groups the adblock code builds (strongAdSelectors.join(", "), weakOnly join,
  // and the class[*=Advertisement] group). querySelectorAll handles "audio",
  // "video", "[data-testid]", "audio, video".
  const documentStub = {
    title: "",
    createElement: (tag) => makeGenericNode(tag),
    getElementById: () => null,
    addEventListener: () => {},
    removeEventListener: () => {},
    querySelector(sel) {
      try {
        if (typeof sel !== "string") return null;
        // comma-joined group: match if ANY sub-selector resolves
        if (sel.includes(",")) {
          const parts = sel.split(",").map((s) => s.trim()).filter(Boolean);
          for (const p of parts) {
            // class[*=Advertisement] group is never present in our fixtures
            if (p.startsWith("[class*=")) continue;
            const n = resolveSingle(p);
            if (n) return n;
          }
          return null;
        }
        if (sel.startsWith("[class*=")) return null;
        if (sel === "audio") return null;
        if (sel === "video") return null;
        return resolveSingle(sel);
      } catch { return null; }
    },
    querySelectorAll(sel) {
      try {
        if (sel === "audio" || sel === "video" || sel === "audio, video") return [];
        if (sel === "[data-testid]") {
          // Used by STRONG_PRESENT fuzzy fallback and debug surface. Return the
          // currently-present nodes carrying a data-testid so the fuzzy regex
          // can be exercised when the test wants it.
          const out = [];
          for (const s of fixture.present) {
            const m = /^\[data-testid="([^"]+)"\]$/.exec(s);
            if (m) {
              const n = makeGenericNode("div");
              n.setAttribute("data-testid", m[1]);
              out.push(n);
            }
          }
          return out;
        }
        return [];
      } catch { return []; }
    },
  };
  const headStub = makeGenericNode("head");
  const bodyStub = makeGenericNode("body");
  const docElStub = makeGenericNode("html");
  documentStub.head = headStub;
  documentStub.body = bodyStub;
  documentStub.documentElement = docElStub;

  // ---- timers: capture, do NOT auto-fire (test drives ticks manually) ----
  const fakeSetTimeout = (fn, ms) => { timeouts.push({ fn, ms }); return timeouts.length; };
  const fakeClearTimeout = () => {};
  const fakeSetInterval = (fn, ms) => {
    intervals.push({ fn, ms });
    // The LAST setInterval(check, CFG.tickMs) is the FSM tick. Capture by delay.
    if (ms === 500 && typeof fn === "function") checkTick = fn;
    return intervals.length;
  };
  const fakeClearInterval = () => {};

  // ---- window ----
  const windowStub = {
    __INTERCEPTIFY_SHOW_BADGE: false,
    __INTERCEPTIFY_DEBUG_CAPTURE: false,
  };
  if (config) windowStub.__INTERCEPTIFY_CONFIG = config;

  // ---- in-stream api stub (skipToNext counter) ----
  const instreamApi = {
    skipToNext() { fixture.counts.skipToNext++; },
  };
  windowStub.__interceptify_instream_api = instreamApi;

  // base fetch the adblock wrapper must chain to (install BEFORE load)
  windowStub.fetch = baseFetch;

  // webpack chunk array the ad-provider hook pushes onto
  windowStub.webpackChunkclient_web = [];

  // ---- prototype-bearing globals the load-time hooks reference ----
  class FakeHTMLElement {}
  FakeHTMLElement.prototype.click = function () {};
  class FakeHTMLMediaElement extends FakeHTMLElement {}
  FakeHTMLMediaElement.prototype.play = function () { return Promise.resolve(); };
  // a writable src descriptor so the (d) hook can wrap it
  Object.defineProperty(FakeHTMLMediaElement.prototype, "src", {
    configurable: true,
    get() { return this._src || ""; },
    set(v) { this._src = v; },
  });
  class FakeHTMLInputElement extends FakeHTMLElement {}
  Object.defineProperty(FakeHTMLInputElement.prototype, "value", {
    configurable: true, get() { return this._value; }, set(v) { this._value = v; },
  });

  class FakeAudioNode { connect() {} }
  class FakeAudioDestinationNode extends FakeAudioNode {}

  class FakeEventTarget {
    addEventListener() {}
    removeEventListener() {}
    dispatchEvent() { return true; }
  }

  // Minimal XMLHttpRequest with a prototype (open/send wrapped at load).
  class FakeXMLHttpRequest extends FakeEventTarget {
    open() {}
    send() {}
  }

  // Response stub good enough for emptyManifestResponse() + clone().text().
  class FakeResponse {
    constructor(body, init) {
      this._body = typeof body === "string" ? body
        : body == null ? ""
        : (body.byteLength !== undefined ? "" : String(body));
      this.status = (init && init.status) || 200;
      this.statusText = (init && init.statusText) || "";
      this.headers = (init && init.headers) || {};
      this.__interceptify_test_response = true;
    }
    clone() { return new FakeResponse(this._body, { status: this.status, headers: this.headers }); }
    async text() { return this._body; }
    async json() { return JSON.parse(this._body); }
  }

  // ---- assemble sandbox ----
  const sandbox = {
    window: windowStub,
    document: documentStub,
    navigator: { sendBeacon: undefined, serviceWorker: undefined },
    location: { href: "https://xpui.app.spotify.com/", host: "xpui.app.spotify.com" },
    console: {
      log: () => {}, warn: () => {}, error: () => {}, info: () => {},
      table: () => {}, debug: () => {},
    },
    setTimeout: fakeSetTimeout,
    clearTimeout: fakeClearTimeout,
    setInterval: fakeSetInterval,
    clearInterval: fakeClearInterval,
    Date: clock.FakeDate,
    Response: FakeResponse,
    HTMLElement: FakeHTMLElement,
    HTMLMediaElement: FakeHTMLMediaElement,
    HTMLInputElement: FakeHTMLInputElement,
    AudioNode: FakeAudioNode,
    AudioDestinationNode: FakeAudioDestinationNode,
    EventTarget: FakeEventTarget,
    XMLHttpRequest: FakeXMLHttpRequest,
    Event: class FakeEvent { constructor(type, init) { this.type = type; Object.assign(this, init); } },
    URL: { createObjectURL: undefined },
    sessionStorage: { getItem: () => null, setItem: () => {} },
    localStorage: { getItem: () => null, setItem: () => {} },
  };
  // window === globalThis in a real renderer; the IIFE reads both `window.x`
  // and bare globals (document, navigator, ...). Make window a self-alias and
  // expose the bare globals as window properties too.
  sandbox.window.window = sandbox.window;
  sandbox.window.document = documentStub;
  sandbox.window.navigator = sandbox.navigator;
  sandbox.window.location = sandbox.location;
  sandbox.window.console = sandbox.console;
  sandbox.window.setTimeout = fakeSetTimeout;
  sandbox.window.clearTimeout = fakeClearTimeout;
  sandbox.window.setInterval = fakeSetInterval;
  sandbox.window.clearInterval = fakeClearInterval;
  sandbox.window.Response = FakeResponse;
  sandbox.window.HTMLElement = FakeHTMLElement;
  sandbox.window.HTMLMediaElement = FakeHTMLMediaElement;
  sandbox.window.HTMLInputElement = FakeHTMLInputElement;
  sandbox.window.AudioNode = FakeAudioNode;
  sandbox.window.AudioContext = undefined;
  sandbox.window.WebSocket = undefined;
  sandbox.window.EventSource = undefined;
  sandbox.window.BroadcastChannel = undefined;
  sandbox.window.MediaSource = undefined;
  sandbox.window.Worker = undefined;
  sandbox.window.PerformanceObserver = undefined;
  sandbox.window.XMLHttpRequest = FakeXMLHttpRequest;
  sandbox.window.Event = sandbox.Event;
  sandbox.window.URL = sandbox.URL;
  sandbox.window.EventTarget = FakeEventTarget;

  const context = vm.createContext(sandbox);

  // Filename includes "interceptify-adblock" so the safe-skip guard's
  // fromOurScript() stack test matches (belt+braces; advance() gates already).
  const loadError = (() => {
    try {
      const script = new vm.Script(ADBLOCK_SRC, { filename: "interceptify-adblock.js" });
      script.runInContext(context);
      return null;
    } catch (e) {
      return e;
    }
  })();

  installedFetch = sandbox.window.fetch;

  return {
    sandbox, context, loadError, intervals, timeouts,
    get checkTick() { return checkTick; },
    get installedFetch() { return installedFetch; },
    nodes: { skipForwardNode, seek15Node, muteNode },
  };
}

// helper: present-set mutators
function setAdPainted(fixture) {
  fixture.present.add('[data-testid="ad-controls"]');
}
function clearAdPainted(fixture) {
  fixture.present.delete('[data-testid="ad-controls"]');
}

function totalAdvanceActions(fixture) {
  return fixture.counts.skipForwardClicks + fixture.counts.seek15Clicks + fixture.counts.skipToNext;
}

// ===========================================================================
// TEST A — NO OVER-SKIP
// ===========================================================================
function testA() {
  const clock = makeClock();
  const fixture = makeFixture();

  // base fetch: nothing networked in this test
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST A"); };

  const env = loadAdblock({ fixture, clock, baseFetch });
  assert("A.load: adblock.js loaded without throwing", env.loadError === null,
    env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
  assert("A.capture: check() tick captured from setInterval(fn,500)", typeof env.checkTick === "function");
  if (typeof env.checkTick !== "function") return; // can't continue
  const check = env.checkTick;

  // helper to advance virtual time + run a tick
  const tick = (ms = 500) => { clock.advance(ms); try { check(); } catch (e) { /* surfaced via state */ } };

  const state = () => env.sandbox.window.__interceptify.state();

  // ---- phase 1: audio ad painted (Premium model: skip-forward present+enabled) ----
  setAdPainted(fixture);
  fixture.skipForwardVisible = true;
  fixture.skipForwardDisabled = false;   // Premium -> skip is a real action
  fixture.seek15Visible = false;
  fixture.nowPlayingTitle = "Advertisement";
  fixture.documentTitle = "Advertisement";
  env.sandbox.document.title = "Advertisement";

  // drive several ticks: IDLE -> CONFIRMED -> (advance) SKIPPING ...
  for (let i = 0; i < 6; i++) tick(500);

  const advancesDuringAd = totalAdvanceActions(fixture);
  assert("A1: at least one skip/advance fired during the audio ad", advancesDuringAd >= 1,
    `skipForwardClicks=${fixture.counts.skipForwardClicks} seek15=${fixture.counts.seek15Clicks} skipToNext=${fixture.counts.skipToNext}`);
  assert("A1: FSM left IDLE (reached CONFIRMED/SKIPPING/COOLDOWN) during ad",
    ["CONFIRMED", "SKIPPING", "COOLDOWN"].includes(state()), `state=${state()}`);

  // snapshot the action counts at the transition point
  const skipAtTransition = fixture.counts.skipForwardClicks;
  const seekAtTransition = fixture.counts.seek15Clicks;
  const skipToNextAtTransition = fixture.counts.skipToNext;

  // ---- phase 2: ad -> song transition. Strong gone. Now-playing = real song.
  //      BUT a lingering weak ad-subtitle node is still present for one tick.
  clearAdPainted(fixture);
  fixture.nowPlayingTitle = "Real Song Name";
  fixture.documentTitle = "Real Song Name";
  env.sandbox.document.title = "Real Song Name";
  // lingering weak node for the first transition tick
  fixture.present.add('[data-testid="context-item-info-ad-subtitle"]');
  fixture.nowPlayingSubtitle = "Some Artist"; // NOT ad-looking
  // on a real Free/Premium song seek-15 is absent; skip-forward present but a
  // skip here would be an over-skip — assert it does NOT get clicked.
  fixture.seek15Visible = false;

  tick(500); // first transition tick: weak node still lingering
  // drop the lingering weak node now
  fixture.present.delete('[data-testid="context-item-info-ad-subtitle"]');

  for (let i = 0; i < 8; i++) tick(500);

  const skipAfter = fixture.counts.skipForwardClicks;
  const seekAfter = fixture.counts.seek15Clicks;
  const skipToNextAfter = fixture.counts.skipToNext;

  assert("A2 (KEYSTONE): NO additional skip-forward click on the real song after transition",
    skipAfter === skipAtTransition, `before=${skipAtTransition} after=${skipAfter}`);
  assert("A2 (KEYSTONE): NO additional seek-forward-15 click on the real song after transition",
    seekAfter === seekAtTransition, `before=${seekAtTransition} after=${seekAfter}`);
  assert("A2 (KEYSTONE): NO additional skipToNext() on the real song after transition",
    skipToNextAfter === skipToNextAtTransition, `before=${skipToNextAtTransition} after=${skipToNextAfter}`);
  assert("A2: FSM settled to IDLE or COOLDOWN after transition",
    ["IDLE", "COOLDOWN"].includes(state()), `state=${state()}`);

  // ---- phase 3: weak-only SUSPECTED signal must NEVER advance (mute only) ----
  // fresh env so prior cooldown/anti-spin state doesn't mask the result.
  const clock3 = makeClock();
  const fixture3 = makeFixture();
  const env3 = loadAdblock({ fixture: fixture3, clock: clock3, baseFetch });
  assert("A3.load: reload for weak-only case did not throw", env3.loadError === null,
    env3.loadError ? String(env3.loadError) : "");
  const check3 = env3.checkTick;
  const tick3 = (ms = 500) => { clock3.advance(ms); try { check3(); } catch {} };
  const state3 = () => env3.sandbox.window.__interceptify.state();

  // weak-only: instream bridge window in the future, NO strong selector painted.
  fixture3.skipForwardVisible = true;
  fixture3.skipForwardDisabled = false;
  fixture3.seek15Visible = false;
  fixture3.nowPlayingTitle = "Real Song Name"; // not ad-looking
  fixture3.nowPlayingSubtitle = "Artist";
  env3.sandbox.window.__interceptify_instream_ad_until = clock3.state.now + 5000;

  for (let i = 0; i < 6; i++) tick3(500);

  assert("A3: weak-only SUSPECTED fired ZERO advances (mute-only)",
    totalAdvanceActions(fixture3) === 0,
    `skip=${fixture3.counts.skipForwardClicks} seek=${fixture3.counts.seek15Clicks} skipToNext=${fixture3.counts.skipToNext}`);
  assert("A3: weak-only stayed in SUSPECTED (never CONFIRMED/SKIPPING)",
    state3() === "SUSPECTED", `state=${state3()}`);
  assert("A3: weak-only armed mute (mute button clicked)",
    fixture3.counts.muteClicks >= 1, `muteClicks=${fixture3.counts.muteClicks}`);
}

// ===========================================================================
// TEST B — MANIFEST CLASSIFIER
// ===========================================================================
const MANIFEST_URL =
  "https://spclient.wg.spotify.com/manifests/v9/json/sources/abc123def456/options/supports_drm";

async function isEmptyManifest(resp) {
  if (!resp) return false;
  try {
    const txt = await resp.clone().text();
    const obj = JSON.parse(txt);
    return Array.isArray(obj.contents) && obj.contents.length === 0 && Object.keys(obj).length === 1;
  } catch { return false; }
}

async function testB() {
  // ---- Case 1: durationBlock disabled (default) + short body -> passthrough ----
  {
    const clock = makeClock();
    const fixture = makeFixture();
    const shortBody = JSON.stringify({ contents: [{ end_time_millis: 30000 }] });
    let baseCalled = 0;
    // Duck-typed Response the adblock code can clone().text() on.
    const makeResp = (body) => ({
      _body: body, status: 200, headers: {},
      clone() { return makeResp(this._body); },
      async text() { return this._body; },
      async json() { return JSON.parse(this._body); },
    });
    const baseFetch1 = async () => { baseCalled++; return makeResp(shortBody); };

    const env = loadAdblock({ fixture, clock, baseFetch: baseFetch1 });
    assert("B1.load: loaded (durationBlock default OFF)", env.loadError === null,
      env.loadError ? String(env.loadError) : "");
    const fetch = env.installedFetch;
    assert("B1.capture: window.fetch was wrapped", typeof fetch === "function" && fetch.__interceptify_hooked === true);

    // NO strong ad marker present (default config -> manifestDurationBlock false)
    const resp = await fetch(MANIFEST_URL);
    const empty = await isEmptyManifest(resp);
    assert("B1: durationBlock OFF + short manifest -> PASSTHROUGH (not blocked)",
      !empty && baseCalled >= 1, `empty=${empty} baseCalled=${baseCalled}`);
    // sanity: passthrough body is the original short body
    const passTxt = resp && (await resp.clone().text());
    assert("B1: passthrough returns the ORIGINAL manifest body",
      passTxt === shortBody, `body=${passTxt}`);
  }

  // ---- Case 2: durationBlock ON + strong marker present + short body -> blocked ----
  {
    const clock = makeClock();
    const fixture = makeFixture();
    // strong ad marker present so corroboration (strongNow) passes
    setAdPainted(fixture);
    const shortBody = JSON.stringify({ contents: [{ end_time_millis: 30000 }] });
    const makeResp = (body) => ({
      _body: body, status: 200, headers: {},
      clone() { return makeResp(this._body); },
      async text() { return this._body; },
      async json() { return JSON.parse(this._body); },
    });
    const baseFetch = async () => makeResp(shortBody);

    const env = loadAdblock({
      fixture, clock, baseFetch,
      config: { manifestDurationBlock: true },
    });
    assert("B2.load: loaded with manifestDurationBlock:true", env.loadError === null,
      env.loadError ? String(env.loadError) : "");
    const fetch = env.installedFetch;
    const resp = await fetch(MANIFEST_URL);
    const empty = await isEmptyManifest(resp);
    assert("B2: durationBlock ON + short + corroborated -> BLOCKED ({\"contents\":[]})",
      empty, `empty=${empty}`);
  }

  // ---- Case 3: durationBlock ON + music-length body -> passthrough ----
  {
    const clock = makeClock();
    const fixture = makeFixture();
    setAdPainted(fixture); // corroboration available, but duration is out of ad window
    const musicBody = JSON.stringify({ contents: [{ end_time_millis: 240000 }] });
    const makeResp = (body) => ({
      _body: body, status: 200, headers: {},
      clone() { return makeResp(this._body); },
      async text() { return this._body; },
      async json() { return JSON.parse(this._body); },
    });
    const baseFetch = async () => makeResp(musicBody);

    const env = loadAdblock({
      fixture, clock, baseFetch,
      config: { manifestDurationBlock: true },
    });
    assert("B3.load: loaded with manifestDurationBlock:true (music case)", env.loadError === null,
      env.loadError ? String(env.loadError) : "");
    const fetch = env.installedFetch;
    const resp = await fetch(MANIFEST_URL);
    const empty = await isEmptyManifest(resp);
    const txt = resp && (await resp.clone().text());
    assert("B3: durationBlock ON + music duration (240s) -> PASSTHROUGH",
      !empty && txt === musicBody, `empty=${empty} body=${txt}`);
  }
}

// ===========================================================================
// TEST C — IN-STREAM (L1) SKIP IS GATED  (regression for the audited bypass)
// The L1 webpack-driven neutralizeInStreamAd() used to call api.skipToNext()
// with NONE of advance()'s over-skip gates, so a re-read / lingering /
// prefetched in-stream ad object could skip a REAL song. This test drives the
// REAL webpack provider hook so the skip runs through the installed inStreamAd
// getter/setter, then asserts the skip is SUPPRESSED in the two over-skip cases
// the new inStreamSkipSafe() gate must block:
//   C2 — inside the post-skip transition cooldown window
//   C3 — when now-playing has moved off the confirmed ad to a real song
// ===========================================================================
function wireInStreamProvider(env, fixture) {
  const chunk = env.sandbox.window.webpackChunkclient_web;
  if (!Array.isArray(chunk)) return null;
  const providerApi = {
    inStreamAd: null,
    skipToNext() { fixture.counts.skipToNext++; },
  };
  // NB: this factory's SOURCE must not contain BOTH "getInStreamAd" and
  // "inStreamApi" or the hook takes its require.d fast-path. It exports d()
  // (api accessor) + m() (ad accessor) so wrapInStreamExports accepts it.
  function providerFactory(module) {
    module.exports = {
      d: function () { return providerApi; },
      m: function () { return providerApi.inStreamAd; },
    };
  }
  // 46849 == CFG.instreamModuleFallbackId; the hook replaces it with a wrapper.
  chunk.push([["test-instream-chunk"], { 46849: providerFactory }]);
  const pushed = chunk[chunk.length - 1];
  const wrappedFactory = pushed && pushed[1] && pushed[1][46849];
  if (typeof wrappedFactory !== "function") return null;
  const moduleObj = { exports: {} };
  wrappedFactory(moduleObj, moduleObj.exports, undefined); // webpack-style invoke
  const api = moduleObj.exports && typeof moduleObj.exports.d === "function"
    ? moduleObj.exports.d()   // calling d() installs the inStreamAd getter/setter
    : null;
  return api ? { api, providerApi } : null;
}

function testC() {
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST C"); };

  // ---- C1 + C2: the post-skip cooldown lock ----
  {
    const clock = makeClock();
    const fixture = makeFixture();
    const env = loadAdblock({ fixture, clock, baseFetch });
    assert("C.load: adblock.js loaded without throwing", env.loadError === null,
      env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
    const wired = wireInStreamProvider(env, fixture);
    assert("C.wire: in-stream provider hook installed the inStreamAd accessor", !!(wired && wired.api),
      wired ? "" : "wrappedFactory / exports.d() not reachable");
    if (!wired || !wired.api) return;
    const api = wired.api;
    const snap = () => env.sandbox.window.__interceptify.snapshot();

    // C1: from IDLE, an in-stream ad object fires skipToNext AND arms cooldown.
    fixture.nowPlayingTitle = "Advertisement";
    env.sandbox.document.title = "Advertisement";
    const c1Before = fixture.counts.skipToNext;
    api.inStreamAd = { adId: "ad-c1", uri: "spotify:ad:c1", advertiser: "AcmeCo" };
    assert("C1: in-stream ad (idle) fires skipToNext once — the lever still works",
      fixture.counts.skipToNext === c1Before + 1,
      `before=${c1Before} after=${fixture.counts.skipToNext}`);
    assert("C1: the skip armed the short in-stream self-lock",
      snap().inStreamLockActive === true, `inStreamLockActive=${snap().inStreamLockActive}`);

    // C2 (FIX): a DIFFERENT in-stream ad WITHIN the self-lock window is suppressed.
    // Pre-fix this was ungated and would skipToNext onto a freshly-started real
    // song. The distinct ad key rules out the dedupe Set as the cause.
    clock.advance(100); // still < inStreamSkipLockMs (300)
    const c2Before = fixture.counts.skipToNext;
    api.inStreamAd = { adId: "ad-c2", uri: "spotify:ad:c2", advertiser: "AcmeCo" };
    assert("C2 (FIX): in-stream skip SUPPRESSED inside the post-skip cooldown window",
      fixture.counts.skipToNext === c2Before,
      `before=${c2Before} after=${fixture.counts.skipToNext}`);
  }

  // ---- C3 (FIX, gate b2): now-playing moved off the confirmed ad -> suppressed ----
  {
    const clock = makeClock();
    const fixture = makeFixture();
    const env = loadAdblock({ fixture, clock, baseFetch });
    const wired = wireInStreamProvider(env, fixture);
    assert("C3.wire: in-stream provider hook installed", !!(wired && wired.api),
      wired ? "" : "wrappedFactory / exports.d() not reachable");
    if (!wired || !wired.api) return;
    const api = wired.api;
    const check = env.checkTick;
    const tick = (ms = 500) => { clock.advance(ms); try { check(); } catch {} };
    const state = () => env.sandbox.window.__interceptify.state();

    // Drive the FSM through a painted ad so currentAdFp (the ad's now-playing
    // fingerprint) is captured and we land in SKIPPING/COOLDOWN.
    setAdPainted(fixture);
    fixture.skipForwardVisible = true; fixture.skipForwardDisabled = false; fixture.seek15Visible = false;
    fixture.nowPlayingTitle = "Advertisement";
    env.sandbox.document.title = "Advertisement";
    for (let i = 0; i < 3; i++) tick(500);
    assert("C3.setup: FSM confirmed the ad (currentAdFp captured)",
      ["CONFIRMED", "SKIPPING", "COOLDOWN"].includes(state()), `state=${state()}`);

    // Real song is now playing. Expire the cooldown WITHOUT running a tick — a
    // tick would release the ad state and null currentAdFp, leaving nothing for
    // gate b2 to test. So here the cooldown gate passes and ONLY gate b2
    // (now-playing moved off the ad) can stop the skip.
    clearAdPainted(fixture);
    fixture.nowPlayingTitle = "Real Song Name";
    env.sandbox.document.title = "Real Song Name";
    fixture.nowPlayingSubtitle = "Some Artist"; // NOT ad-looking
    clock.advance(3000); // > cooldownMs (1500): the cooldown gate no longer applies

    const before = fixture.counts.skipToNext;
    api.inStreamAd = { adId: "ad-c3", uri: "spotify:ad:c3", advertiser: "AcmeCo" };
    assert("C3 (FIX): in-stream skip SUPPRESSED when now-playing moved off the ad to a real song",
      fixture.counts.skipToNext === before,
      `before=${before} after=${fixture.counts.skipToNext}`);
  }
}

// ===========================================================================
// TEST D — LOCALE multi-ad break + cross-break key reset
// Regression for the 2026-06-15 post-Spotify-update bug: Swedish ads
// ("Annons"/"Reklam") weren't recognized by the English-only fpLooksLikeAd, so
// the FSM falsely "verified" a skip mid-ad, marked the ad's adKey satisfied, and
// then advance() permanently suppressed it (advance-suppressed: adKey-satisfied)
// — the ad played out fully, muted. Also: DOM-fingerprint adKeys COLLIDE across
// breaks, so a satisfied key from a prior break blocked an identical later ad.
// ===========================================================================
function testD() {
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST D"); };
  const clock = makeClock();
  const fixture = makeFixture();
  const env = loadAdblock({ fixture, clock, baseFetch });
  assert("D.load: adblock.js loaded without throwing", env.loadError === null,
    env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
  if (env.loadError) return;
  const check = env.checkTick;
  const tick = (ms = 500) => { clock.advance(ms); try { check(); } catch {} };
  const state = () => env.sandbox.window.__interceptify.state();

  const paintAd = (title, sub) => {
    fixture.present.add('[data-testid="ad-controls"]');
    fixture.skipForwardVisible = true; fixture.skipForwardDisabled = false; fixture.seek15Visible = false;
    fixture.nowPlayingTitle = title; fixture.nowPlayingSubtitle = sub;
    env.sandbox.document.title = "Spotify – Reklam"; // Swedish "Reklam" = ads
  };
  const realSong = (title) => {
    fixture.present.delete('[data-testid="ad-controls"]');
    fixture.nowPlayingTitle = title; fixture.nowPlayingSubtitle = "Some Artist";
    env.sandbox.document.title = title;
  };

  // ---- Break 1: a 2-ad Swedish break ----
  paintAd("Spotify", "Annons • 1 av 2");
  for (let i = 0; i < 3; i++) tick(500);            // confirm + skip ad1
  const afterAd1 = fixture.counts.skipToNext;
  assert("D1: Swedish ad1 triggered an in-stream skip (locale recognized)",
    afterAd1 >= 1, `skipToNext=${afterAd1}`);

  paintAd("Spotify", "Annons • 2 av 2");        // skip landed on ad2 (controls still up)
  for (let i = 0; i < 6; i++) tick(500);            // re-confirm ad2 + skip (waits out cooldown)
  const afterAd2 = fixture.counts.skipToNext;
  assert("D2: ad2 of the multi-ad break ALSO skipped (not stuck adKey-satisfied)",
    afterAd2 > afterAd1, `before=${afterAd1} after=${afterAd2}`);

  realSong("Real Song One");                         // skip landed on a real song
  for (let i = 0; i < 6; i++) tick(500);
  const afterSong = fixture.counts.skipToNext;
  assert("D3: NO further skip once a real song plays (over-skip protection holds)",
    afterSong === afterAd2, `before=${afterAd2} after=${afterSong}`);
  assert("D4: FSM returned to IDLE after the break", state() === "IDLE", `state=${state()}`);

  // ---- Break 2: an ad whose key was SATISFIED in break 1 ----
  // Without the per-break reset, "Annons 2 av 2" is still in _satisfiedAdKeys /
  // the "advance:" dedup set -> advance() suppresses it forever (the bug).
  const beforeB2 = fixture.counts.skipToNext;
  paintAd("Spotify", "Annons • 2 av 2");
  for (let i = 0; i < 3; i++) tick(500);
  const afterB2 = fixture.counts.skipToNext;
  assert("D5 (KEY RESET): an identical ad in a LATER break still skips (satisfied/dedupe keys cleared on IDLE)",
    afterB2 > beforeB2, `before=${beforeB2} after=${afterB2}`);
}

// ===========================================================================
// Runner
// ===========================================================================
async function main() {
  try { testA(); } catch (e) {
    assert("TEST A crashed", false, String(e && e.stack || e));
  }
  try { await testB(); } catch (e) {
    assert("TEST B crashed", false, String(e && e.stack || e));
  }
  try { testC(); } catch (e) {
    assert("TEST C crashed", false, String(e && e.stack || e));
  }
  try { testD(); } catch (e) {
    assert("TEST D crashed", false, String(e && e.stack || e));
  }

  const pad = Math.max(...results.map((r) => r.label.length));
  let failed = 0;
  console.log("\n=== Interceptify v2 adblock.js regression ===\n");
  for (const r of results) {
    const tag = r.pass ? "PASS" : "FAIL";
    if (!r.pass) failed++;
    const line = `[${tag}] ${r.label.padEnd(pad)}`;
    console.log(r.detail && (!r.pass || process.env.VERBOSE) ? `${line}   :: ${r.detail}` : line);
  }
  console.log(`\n${results.length - failed}/${results.length} assertions passed.`);
  if (failed) {
    console.log(`${failed} FAILED.`);
    process.exit(1);
  }
  console.log("ALL PASSED.");
  process.exit(0);
}

main();
