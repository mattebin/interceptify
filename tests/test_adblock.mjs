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
  // The factory's SOURCE carries both provider signatures ("getInStreamAd" and
  // "inStreamApi"), because the hook now REQUIRES the module at the fallback id
  // to look like the provider before it will wrap it - a bundler id existing is
  // not evidence that the same thing still lives there. The require.d fast-path
  // those needles also select is unreachable here: this fixture invokes the
  // factory with `require === undefined`, so `require.d` throws and the hook
  // falls through to the generic wrapInStreamExports path, which is the path
  // TEST C is about.
  function providerFactory(module) {
    module.exports = {
      d: function () { return providerApi; },              // inStreamApi accessor
      m: function () { return providerApi.inStreamAd; },   // getInStreamAd accessor
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
// TEST F — ONE ADVANCING PRIMITIVE PER DECISION
// advance() used to fire every primitive it had in a single pass: an override
// skip, the in-stream skipToNext, a next-track click, a seek burst and an
// ad-video 'ended'. All five advance the play queue on their own, so one ad
// decision issued up to five advances and relied on dedupe keys plus timing to
// avoid running into the next track. This asserts the ladder: one primitive per
// gated decision, escalating only on a later tick that re-passed the gate.
// ===========================================================================
function testF() {
  const clock = makeClock();
  const fixture = makeFixture();
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST F"); };
  const env = loadAdblock({ fixture, clock, baseFetch });
  assert("F.load: adblock.js loaded without throwing", env.loadError === null,
    env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
  if (typeof env.checkTick !== "function") { assert("F.capture: check() tick captured", false); return; }
  const check = env.checkTick;
  const tick = (ms = 500) => { clock.advance(ms); try { check(); } catch (e) {} };

  // Paint a confirmed ad and hold it there, so the gate keeps passing and the
  // ladder is free to escalate as far as it wants to.
  fixture.nowPlayingTitle = "Advertisement";
  env.sandbox.document.title = "Advertisement";
  setAdPainted(fixture);

  let maxPerTick = 0;
  for (let i = 0; i < 6; i++) {
    const before = totalAdvanceActions(fixture);
    tick(500);
    maxPerTick = Math.max(maxPerTick, totalAdvanceActions(fixture) - before);
  }
  assert("F1 (ONE PRIMITIVE): a single gated decision never fires more than one advancing action",
    maxPerTick <= 1, `worst tick fired ${maxPerTick} advancing actions`);
  assert("F2: the ad still got advanced at least once",
    totalAdvanceActions(fixture) >= 1, `total=${totalAdvanceActions(fixture)}`);
}

// ===========================================================================
// TEST E — L1 LIVENESS IS AN HONEST SIGNAL
// Spotify migrated webpack -> rspack, so the payload hooked a chunk array the
// bundle never pushed to: the whole L1 layer was dead while looking installed.
// The fix hooks every candidate name and arms a watchdog. That watchdog is only
// worth having if its input cannot be self-satisfied — the first cut bound the
// push handle AFTER wrapping, so our own bootstrap push set the "alive" flag
// and the watchdog could never fire on any build, ever.
//
// E1 is the regression: with NO bundle push, liveness must read false.
// ===========================================================================
function fireL1Watchdog(env) {
  const w = env.timeouts.find((t) => t.ms === 20000);
  if (w) w.fn();
  return !!w;
}

function testE() {
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST E"); };

  // ---- E1 + E3: nothing but our own bootstrap push ----
  {
    const env = loadAdblock({ fixture: makeFixture(), clock: makeClock(), baseFetch });
    assert("E.load: adblock.js loaded without throwing", env.loadError === null,
      env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
    const win = env.sandbox.window;

    assert("E1 (SELF-SATISFYING SIGNAL): our own bootstrap push must NOT mark L1 alive",
      win.__interceptify_l1_fired === false, `l1_fired=${win.__interceptify_l1_fired}`);

    const armed = fireL1Watchdog(env);
    assert("E2: a dead-hook watchdog was actually armed", armed, "no 20000ms timeout registered");
    assert("E3: with no bundle push the watchdog declares L1 dead",
      !!win.__interceptify_l1_dead, JSON.stringify(win.__interceptify_l1_dead));
    const h = win.__interceptify.health();
    assert("E4: health() reports the dead hook (this is what selfheal.py reads)",
      h.l1Hooked === false && !!h.l1Dead, `l1Hooked=${h.l1Hooked} l1Dead=${JSON.stringify(h.l1Dead)}`);
  }

  // ---- E5 + E6: a real bundle push ----
  {
    const env = loadAdblock({ fixture: makeFixture(), clock: makeClock(), baseFetch });
    const win = env.sandbox.window;
    win.webpackChunkclient_web.push([["bundle-chunk"], {}]);
    assert("E5: a push from the bundle DOES mark L1 alive",
      win.__interceptify_l1_fired === true, `l1_fired=${win.__interceptify_l1_fired}`);

    fireL1Watchdog(env);
    assert("E6: the watchdog stays silent once the hook has genuinely fired",
      !win.__interceptify_l1_dead && win.__interceptify.health().l1Hooked === true,
      JSON.stringify(win.__interceptify_l1_dead));

    // health().layers must read the world, not a "we called the installer" flag.
    const layers = win.__interceptify.health().layers;
    assert("E7: health().layers reports fetch/xhr from actual hook evidence",
      layers.fetch === (typeof win.fetch === "function" && win.fetch.__interceptify_hooked === true)
      && layers.xhr === (env.sandbox.XMLHttpRequest.prototype.__interceptify_url_block_hooked === true)
      && layers.fetch === true,
      JSON.stringify(layers));
    assert("E8: health().layerErrors exists and no layer threw on install",
      Array.isArray(win.__interceptify.health().layerErrors)
      && win.__interceptify.health().layerErrors.length === 0,
      JSON.stringify(win.__interceptify.health().layerErrors));
  }
}

// ===========================================================================
// TEST G — A REUSED BUNDLER ID MUST NOT PASS FOR THE AD PROVIDER
//
// instreamModuleFallbackId is a fast-path hint, and the hook used to accept it
// on presence alone: `map[46849]` existing was treated as "the provider is at
// 46849". Bundler ids are recycled between builds, so a rebuild that moved the
// provider and left something unrelated at the old id would get that unrelated
// module wrapped, report a successful hook, and block nothing - while the source
// scan that would have found the real one only ran when the id was ABSENT.
//
// G1: a non-provider sitting at the fallback id is refused.
// G2: the real provider, at a different id, is found by the source scan anyway.
// ===========================================================================
function testG() {
  const clock = makeClock();
  const fixture = makeFixture();
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST G"); };
  const env = loadAdblock({ fixture, clock, baseFetch });
  assert("G.load: adblock.js loaded without throwing", env.loadError === null,
    env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
  const chunk = env.sandbox.window.webpackChunkclient_web;
  if (!Array.isArray(chunk)) { assert("G.capture: chunk array present", false); return; }

  // Something else entirely, now living at the id the config remembers.
  function strangerFactory(module) { module.exports = { hello: function () { return 1; } }; }
  chunk.push([["test-recycled-id-chunk"], { 46849: strangerFactory }]);
  const afterPush = chunk[chunk.length - 1][1][46849];
  assert("G1 (RECYCLED ID): a module that is not the provider is NOT wrapped",
    afterPush === strangerFactory && !afterPush.__interceptify_wrapped,
    afterPush && afterPush.__interceptify_wrapped ? "it was wrapped anyway" : "");
  assert("G2: the stale hint is reported rather than silently trusted",
    String(env.sandbox.window.__interceptify_fallback_id_stale) === "46849",
    `flag=${env.sandbox.window.__interceptify_fallback_id_stale}`);
}

// ===========================================================================
// TEST H — L1 READINESS IS ABOUT THE PROVIDER, NOT ABOUT ANY PUSH
//
// health().layers.l1Chunk means "the bundle is pushing through our wrapper",
// and ANY chunk push sets it - including a push carrying nothing to do with
// ads. It was the only L1 signal, so a Spotify bundle-layout change could leave
// the ad provider completely unwrapped while the layer still reported green and
// verification still passed.
//
// l1Provider is the claim that matters: we found the in-stream provider and
// wrapped it. The two must be able to disagree.
// ===========================================================================
function testH() {
  const clock = makeClock();
  const fixture = makeFixture();
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST H"); };
  const env = loadAdblock({ fixture, clock, baseFetch });
  assert("H.load: adblock.js loaded without throwing", env.loadError === null,
    env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
  const chunk = env.sandbox.window.webpackChunkclient_web;
  if (!Array.isArray(chunk)) { assert("H.capture: chunk array present", false); return; }
  const layers = () => env.sandbox.window.__interceptify.health().layers;

  // A push of something entirely unrelated to ads.
  function unrelatedFactory(module) { module.exports = { paintTheSidebar: () => 1 }; }
  chunk.push([["test-unrelated-chunk"], { 12345: unrelatedFactory }]);

  assert("H1: an unrelated bundle push marks the chunk hook alive",
    layers().l1Chunk === true, `l1Chunk=${layers().l1Chunk}`);
  assert("H2 (THE POINT): ...but does NOT claim the ad provider is hooked",
    layers().l1Provider === false, `l1Provider=${layers().l1Provider}`);

  // Now the real provider turns up.
  const wired = wireInStreamProvider(env, fixture);
  assert("H3: wiring the real provider is what turns l1Provider green",
    !!(wired && wired.api) && layers().l1Provider === true,
    `wired=${!!wired} l1Provider=${layers().l1Provider}`);
}

// ===========================================================================
// TEST I — A LATE AUDIO AD OBJECT MUST NOT SKIP THE SONG WE JUST STARTED
//
// The pre-paint fast path treats format===AUDIO as self-sufficient evidence, on
// the reasoning that a fresh audio ad object IS an audio ad. That holds when it
// arrives at the start of a break. It does not hold for a delayed or prefetched
// object that turns up AFTER we already advanced past the break, because by
// then the thing playing is a real song - and this path bypasses the FSM's
// cooldown entirely, so nothing else was going to stop it.
//
// The queue-advance clock is now shared: the L1 skip records it too, so the
// window after a skip is visible to the guard whether the skip came from
// advance() or from L1.
// ===========================================================================
function testI() {
  const clock = makeClock();
  const fixture = makeFixture();
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST I"); };
  const env = loadAdblock({ fixture, clock, baseFetch });
  assert("I.load: adblock.js loaded without throwing", env.loadError === null,
    env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
  const wired = wireInStreamProvider(env, fixture);
  assert("I.wire: in-stream provider hook installed", !!(wired && wired.api));
  if (!wired || !wired.api) return;
  const api = wired.api;

  // A genuine break: ad object arrives, we skip it pre-paint. This is the
  // feature and it must keep working.
  fixture.nowPlayingTitle = "Advertisement";
  env.sandbox.document.title = "Advertisement";
  const before = fixture.counts.skipToNext;
  api.inStreamAd = { adId: "ad-first", format: 1, clickThroughUrl: "https://x/1" };
  assert("I1: a fresh AUDIO ad still skips pre-paint (the silent-skip feature)",
    fixture.counts.skipToNext === before + 1, `skips=${fixture.counts.skipToNext - before}`);

  // The skip lands on a real song. Then a DIFFERENT audio ad object shows up
  // late - a prefetch, or a re-delivery of the break we already handled.
  fixture.nowPlayingTitle = "Real Song One";
  fixture.nowPlayingSubtitle = "Some Artist";
  env.sandbox.document.title = "Real Song One";
  fixture.present.delete('[data-testid="ad-controls"]');
  env.sandbox.window.__interceptify_ad_active = false;
  clock.advance(600);                       // past the 300ms self-lock, inside the guard window

  const beforeLate = fixture.counts.skipToNext;
  api.inStreamAd = { adId: "ad-late", format: 1, clickThroughUrl: "https://x/2" };
  assert("I2 (OVER-SKIP): a late AUDIO object does NOT skip the real song",
    fixture.counts.skipToNext === beforeLate,
    `it skipped ${fixture.counts.skipToNext - beforeLate}x onto "${fixture.nowPlayingTitle}"`);

  // Far enough past the advance, a fresh break is authoritative again - the
  // guard is a window, not a permanent downgrade.
  clock.advance(5000);
  const beforeNext = fixture.counts.skipToNext;
  fixture.nowPlayingTitle = "Advertisement";
  env.sandbox.document.title = "Advertisement";
  api.inStreamAd = { adId: "ad-next-break", format: 1, clickThroughUrl: "https://x/3" };
  assert("I3: a later break is still skipped pre-paint (the guard is a window)",
    fixture.counts.skipToNext === beforeNext + 1,
    `skips=${fixture.counts.skipToNext - beforeNext}`);
}

// ===========================================================================
// A stub of Spotify's ads core connector, shaped like the real one.
//
// `state` starts EMPTY on purpose and `getAdState` resolves asynchronously,
// because that is what the live client does: measured on 1.2.94, the connector
// answers ~2.3s after launch with ad_enabled still "true", and the gate first
// reads closed at ~3.6s. Anything that reports protection has to survive that
// window honestly.
// ===========================================================================
function makeConnectorStub(opts = {}) {
  const state = {};
  for (const [k, v] of Object.entries(opts.initialState || {})) state[k] = { value: String(v) };
  const calls = { clearSlot: [], putState: [], triggerSlot: [] };
  let adCallback = null;
  let emptyReadsLeft = opts.emptyReads || 0;
  return {
    calls,
    raw: state,
    deliver(ad) { if (adCallback) adCallback({ ad }); },
    getAdState() {
      if (emptyReadsLeft > 0) { emptyReadsLeft--; return Promise.resolve({ state: {} }); }
      return Promise.resolve({ state });
    },
    putState(k, v) { calls.putState.push([k, v]); state[k] = { value: String(v) }; },
    clearSlot(slot, reason) {
      calls.clearSlot.push({ slot, reason });
      if (opts.clearSlotRejects) return Promise.reject(new Error("clearSlot refused"));
      if (opts.clearSlotNeverResolves) return new Promise(() => {});
      return Promise.resolve();
    },
    subscribeToInStreamAds(cb) { adCallback = cb; },
    updateAdStateEndpoint() {},
    updateAdServerEndpoint() {},
  };
}

const flush = () => new Promise((r) => setImmediate(r));

// ===========================================================================
// TEST J — THE SLOT NAME, AND WHAT "PROTECTED" MEANS
//
// Interceptify cleared slot "streaming". Spotify has no such slot: its bundle
// defines STREAM_SLOT_ID = "stream", and 25/25 delivered in-stream ads in this
// install's own captures carry slot "stream". So every clearSlot() call for the
// one slot that reaches the user's ears addressed nothing, and an ad queued
// before the gate closed was never flushed - it just waited for the next track
// boundary. `ad_enabled=false` stops NEW scheduling; it cannot un-queue.
//
// J1/J2: the canonical slot is used, and discovered rather than trusted.
// J3-J5: "protected" requires the gate read back closed AND the slot flush
//        acknowledged - not merely called, because clearSlot is async and this
//        used to be fire-and-forget.
// ===========================================================================
async function testJ() {
  const clock = makeClock();
  const fixture = makeFixture();
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST J"); };
  const env = loadAdblock({ fixture, clock, baseFetch });
  assert("J.load: adblock.js loaded without throwing", env.loadError === null,
    env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
  const W = env.sandbox.window;
  const slots = W.__interceptify.health().adSlots || [];
  assert("J1 (THE BUG): the interruptive audio slot is 'stream', not 'streaming'",
    slots[0] === "stream" && !slots.includes("streaming"), `slots=${JSON.stringify(slots)}`);

  // A build that renames the slot must be followed, not overridden by our list.
  W.__webpack_modules__ = {
    900: function fakeSlotModule() { return 'STREAM_SLOT_ID="audio-stream",HPTO_SLOT_ID="hpto"'; },
  };
  delete W.__interceptify_discovered_slots;
  const env2 = loadAdblock({ fixture: makeFixture(), clock: makeClock(), baseFetch });
  env2.sandbox.window.__webpack_modules__ = W.__webpack_modules__;
  const found = env2.sandbox.window.__interceptify.health().adSlots || [];
  assert("J2: slot ids are read from the live bundle, so a rename is followed",
    found.includes("audio-stream"), `slots=${JSON.stringify(found)}`);

  // ---- readiness ----
  const env3 = loadAdblock({ fixture: makeFixture(), clock: makeClock(), baseFetch });
  const W3 = env3.sandbox.window;
  const h3 = () => W3.__interceptify.health();
  assert("J3: with no connector, protection is NOT reported as ready",
    h3().protectionReady === false && h3().notReady.includes("connector"),
    JSON.stringify(h3().notReady));

  const conn = makeConnectorStub({ initialState: { ad_enabled: "true" }, clearSlotNeverResolves: true });
  W3.__interceptify_ads_connector = conn;
  W3.__interceptify_instream_api = { adsCoreConnector: conn, skipToNext() {} };
  W3.__interceptify_l1_provider_wrapped = true;
  // The total-block maintenance runs on its own interval (CFG.totalBlockIntervalMs),
  // not on the 500ms FSM tick. Drive every non-FSM interval a few times: the
  // first pass sees an empty baseline, a later one writes the gate and flushes.
  const maintenance = env3.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
  for (let i = 0; i < 4; i++) {
    for (const fn of maintenance) { try { fn(); } catch {} }
    await flush();
  }
  const cleared = conn.calls.clearSlot.map((c) => c.slot);
  assert("J4: the flush targets the canonical slot first",
    cleared[0] === "stream", `cleared=${JSON.stringify(cleared.slice(0, 3))}`);
  assert("J5 (ASYNC): a clearSlot that never resolves is NOT counted as protected",
    h3().protectionReady === false && h3().notReady.includes("slotCleared"),
    `ready=${h3().protectionReady} notReady=${JSON.stringify(h3().notReady)}`);

  // A build whose clearSlot returns nothing to await is UNCONFIRMABLE, not
  // failed. Treating the two the same would make a structural PASS unreachable
  // there, and an unreachable PASS turns the self-heal into a permanent repair
  // loop that restarts Spotify forever - a failure this project has already had
  // once. Report the gap; do not punish it.
  const env4 = loadAdblock({ fixture: makeFixture(), clock: makeClock(), baseFetch });
  const W4 = env4.sandbox.window;
  const syncConn = makeConnectorStub({ initialState: { ad_enabled: "true" } });
  syncConn.clearSlot = function (slot) { syncConn.calls.clearSlot.push({ slot }); };  // no promise
  W4.__interceptify_ads_connector = syncConn;
  W4.__interceptify_instream_api = { adsCoreConnector: syncConn, skipToNext() {} };
  W4.__interceptify_l1_provider_wrapped = true;
  const maint4 = env4.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
  for (let i = 0; i < 4; i++) { for (const fn of maint4) { try { fn(); } catch {} } await flush(); }
  const h4 = W4.__interceptify.health();
  assert("J6: a clearSlot with nothing to await is unconfirmed, not a failure",
    !h4.notReady.includes("slotCleared") && h4.slotClearConfirmed === false,
    `notReady=${JSON.stringify(h4.notReady)} confirmed=${h4.slotClearConfirmed}`);
}

// ===========================================================================
// TEST K — THE REAL PRE-PAINT CALLBACK SHAPE
//
// Every captured in-stream ad on this install looks like this: no top-level
// `format`, slot "stream", and the audio classification only in
// metadata.product_name = "audio_ad" / metadata.format = "audio/ogg". The fast
// pre-paint path asked ONLY for `ad.format === 1 || "AUDIO"`.
//
// If the live object has no top-level format - which the captures cannot settle,
// because the serializer is a whitelist that never recorded it - then the silent
// skip never fired on a real ad and every break waited for the DOM instead.
// Accept either, so the answer stops mattering.
// ===========================================================================
function testK() {
  const clock = makeClock();
  const fixture = makeFixture();
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST K"); };
  const env = loadAdblock({ fixture, clock, baseFetch });
  assert("K.load: adblock.js loaded without throwing", env.loadError === null,
    env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
  const wired = wireInStreamProvider(env, fixture);
  assert("K.wire: in-stream provider hook installed", !!(wired && wired.api));
  if (!wired || !wired.api) return;

  // Exactly the shape from capture_20260613-210549.json, with NO ad DOM yet.
  const realAd = {
    adId: "dc55a42182f44e2b89a2593b969d19f1",
    requestId: "ec2b0d42-fc90-483d-afe2-be57588315dd",
    slot: "stream",
    clickthroughUrl: "spotify:playlist:37i9dQZF1DWTh5RC6ek3nb",
    advertiser: "La Roche-Posay",
    metadata: { product_name: "audio_ad", format: "audio/ogg", advertiser: "La Roche-Posay" },
  };
  fixture.present.delete('[data-testid="ad-controls"]');   // pre-paint: no ad UI
  env.sandbox.document.title = "Spotify";                  // and no ad-ish title
  const before = fixture.counts.skipToNext;
  wired.api.inStreamAd = realAd;
  assert("K1 (PRE-PAINT): the real callback shape is treated as an audio ad and skipped",
    fixture.counts.skipToNext === before + 1,
    `skips=${fixture.counts.skipToNext - before} (no top-level format; audio_ad is in metadata)`);
}

// ===========================================================================
// TEST L — A DELIVERED AD IS CONTAINED, BEFORE AND AFTER READINESS
//
// The tripwire observed deliveries and did essentially nothing with them.
// Before readiness it called armMute() alone: ad_active was never set, so the
// ~2s watchdog saw "no ad" and un-muted while the ad was still playing - mute,
// then unmute, then the ad. After readiness it did not even mute; it left
// everything to the DOM FSM's 500ms poll plus two-tick confirmation, in the one
// case where a layer has already provably failed.
//
// L1/L2: pre-readiness delivery mutes AND survives a watchdog pass.
// L3:    post-readiness delivery is contained too (readiness is not a licence
//        to do nothing - a delivery means something already failed).
// L4:    the hold is bounded, so containment can never pin a real song silent.
// ===========================================================================
async function testL() {
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST L"); };

  // ---- pre-readiness: no connector resolved, no gate, no slot flush ----
  const clock = makeClock();
  const env = loadAdblock({ fixture: makeFixture(), clock, baseFetch });
  assert("L.load: adblock.js loaded without throwing", env.loadError === null,
    env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
  const W = env.sandbox.window;
  const conn = makeConnectorStub({ initialState: { ad_enabled: "true" } });
  // Reachable connector so the tripwire arms, but the L1 provider is NOT wrapped
  // - so this stays genuinely pre-readiness, which is the whole point of L1/L2.
  W.__interceptify_ads_connector = conn;
  W.__interceptify_instream_api = { adsCoreConnector: conn };
  const maint = env.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
  for (let i = 0; i < 4; i++) { for (const fn of maint) { try { fn(); } catch {} } await flush(); }

  const h0 = W.__interceptify.health();
  assert("L0: the fixture really is pre-readiness (otherwise L1/L2 prove nothing)",
    h0.protectionReady === false && W.__interceptify_tripwire === true,
    `notReady=${JSON.stringify(h0.notReady)} tripwire=${W.__interceptify_tripwire}`);

  // The observable is the MUTE BUTTON's real state, not our own hold timer. An
  // assertion on the timer would pass even with the watchdog fix reverted -
  // it would be measuring our intent instead of the audio the user hears.
  const muteBtn = env.nodes.muteNode;
  conn.deliver({ adId: "pre-ready-1", slot: "stream",
                 metadata: { product_name: "audio_ad", format: "audio/ogg" } });
  await flush();
  assert("L1: an ad delivered before readiness is muted at once",
    muteBtn._muted === true,
    `muted=${muteBtn._muted} clicks=${env.sandbox.window.__interceptify ? "" : ""}`);

  // THE REGRESSION: the watchdog is what used to undo that mute two seconds
  // later, because the tripwire never set ad_active and the watchdog reads
  // "no ad in progress" as "restore the audio".
  const watchdog = env.intervals.filter((i) => i.ms === 2000).map((i) => i.fn);
  clock.advance(2000);
  for (const fn of watchdog) { try { fn(); } catch {} }
  assert("L2 (THE REGRESSION): the watchdog does NOT un-mute an ad that is still playing",
    muteBtn._muted === true,
    `muted=${muteBtn._muted} (was: watchdog saw ad_active=false and restored audio mid-ad)`);

  // ...and it DOES restore once the bounded hold expires, so a stuck hold can
  // never leave the user silent.
  clock.advance(40000);
  for (const fn of watchdog) { try { fn(); } catch {} }
  assert("L2b: once the hold expires the watchdog restores audio as before",
    muteBtn._muted === false, `muted=${muteBtn._muted}`);

  // ---- post-readiness delivery ----
  const clock3 = makeClock();
  const env3 = loadAdblock({ fixture: makeFixture(), clock: clock3, baseFetch });
  const W3 = env3.sandbox.window;
  const conn3 = makeConnectorStub({ initialState: { ad_enabled: "true" } });
  W3.__interceptify_ads_connector = conn3;
  W3.__interceptify_instream_api = { adsCoreConnector: conn3, skipToNext() {} };
  W3.__interceptify_l1_provider_wrapped = true;
  const maint3 = env3.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
  for (let i = 0; i < 4; i++) { for (const fn of maint3) { try { fn(); } catch {} } await flush(); }
  const ready = W3.__interceptify.health();
  assert("L3.setup: this fixture IS ready (otherwise L3 tests the wrong branch)",
    ready.protectionReady === true, JSON.stringify(ready.notReady));

  const clearsBefore = conn3.calls.clearSlot.length;
  conn3.deliver({ adId: "post-ready-1", slot: "stream",
                  metadata: { product_name: "audio_ad", format: "audio/ogg" } });
  await flush();
  const h3 = W3.__interceptify.health();
  assert("L3: a delivery through an ESTABLISHED block is contained, not just logged",
    h3.containHeldMs > 0 && conn3.calls.clearSlot.length > clearsBefore,
    `held=${h3.containHeldMs} clears=${conn3.calls.clearSlot.length - clearsBefore}`);

  // ---- the hold is bounded ----
  clock3.advance(40000);                       // past tripwireHoldMaxMs
  const h4 = W3.__interceptify.health();
  assert("L4: the containment hold expires, so it can never silence a real song",
    h4.containHeldMs <= 0, `heldMs=${h4.containHeldMs}`);
}

// ===========================================================================
// TEST M — STALE EVIDENCE IS NOT EVIDENCE
//
// Readiness is built entirely on answers that arrive asynchronously over a live
// RPC, and every one of them was a latched boolean with no expiry:
//   M1  a gate read that succeeded once stayed authoritative even after every
//       later getAdState() rejected;
//   M2  a reading nobody has refreshed for a long time still counted as "the
//       gate is closed" - it describes a client that may no longer exist;
//   M3  a slot clear acknowledged once stayed acknowledged even when the NEXT
//       attempt never resolved (the old result was never invalidated).
//   M4  discovery could not correct the one value that matters: a renamed
//       primary slot was appended to the list while the dead configured name
//       stayed primary, cleared first and driving readiness.
// ===========================================================================
async function testM() {
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST M"); };
  const clock = makeClock();
  const env = loadAdblock({ fixture: makeFixture(), clock, baseFetch });
  assert("M.load: adblock.js loaded without throwing", env.loadError === null,
    env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
  const W = env.sandbox.window;
  const conn = makeConnectorStub({ initialState: { ad_enabled: "true" } });
  W.__interceptify_ads_connector = conn;
  W.__interceptify_instream_api = { adsCoreConnector: conn, skipToNext() {} };
  W.__interceptify_l1_provider_wrapped = true;
  const maint = env.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
  for (let i = 0; i < 4; i++) { for (const fn of maint) { try { fn(); } catch {} } await flush(); }
  assert("M.setup: the gate reads closed and protection is ready",
    W.__interceptify.health().protectionReady === true,
    JSON.stringify(W.__interceptify.health().notReady));

  // M1 — the channel the gate lives on starts failing.
  conn.getAdState = () => Promise.reject(new Error("core disconnected"));
  for (const fn of maint) { try { fn(); } catch {} }
  await flush();
  const h1 = W.__interceptify.health();
  assert("M1: a REJECTED gate read invalidates the old 'closed', it is not ignored",
    h1.protectionReady === false && h1.notReady.includes("gateClosed"),
    `ready=${h1.protectionReady} notReady=${JSON.stringify(h1.notReady)} err=${h1.gateError}`);

  // M2 — a reading that simply stops being refreshed goes stale.
  const clock2 = makeClock();
  const env2 = loadAdblock({ fixture: makeFixture(), clock: clock2, baseFetch });
  const W2 = env2.sandbox.window;
  const conn2 = makeConnectorStub({ initialState: { ad_enabled: "true" } });
  W2.__interceptify_ads_connector = conn2;
  W2.__interceptify_instream_api = { adsCoreConnector: conn2, skipToNext() {} };
  W2.__interceptify_l1_provider_wrapped = true;
  const maint2 = env2.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
  for (let i = 0; i < 4; i++) { for (const fn of maint2) { try { fn(); } catch {} } await flush(); }
  assert("M2.setup: ready before the clock moves",
    W2.__interceptify.health().protectionReady === true);
  clock2.advance(60000);                       // past gateMaxAgeMs, no refresh runs
  const h2 = W2.__interceptify.health();
  assert("M2: a gate reading nobody refreshed stops counting as evidence",
    h2.protectionReady === false && h2.notReady.includes("gateStale"),
    `ageMs=${h2.gateReadAgeMs} notReady=${JSON.stringify(h2.notReady)}`);

  // M3 — one acknowledged clear, then a clear that never resolves.
  const clock3 = makeClock();
  const env3 = loadAdblock({ fixture: makeFixture(), clock: clock3, baseFetch });
  const W3 = env3.sandbox.window;
  const conn3 = makeConnectorStub({ initialState: { ad_enabled: "true" } });
  W3.__interceptify_ads_connector = conn3;
  W3.__interceptify_instream_api = { adsCoreConnector: conn3, skipToNext() {} };
  W3.__interceptify_l1_provider_wrapped = true;
  const maint3 = env3.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
  for (let i = 0; i < 4; i++) { for (const fn of maint3) { try { fn(); } catch {} } await flush(); }
  assert("M3.setup: the first flush was acknowledged",
    W3.__interceptify.health().slotClearConfirmed === true,
    JSON.stringify(W3.__interceptify.health().slotClear));
  conn3.clearSlot = function (slot) { conn3.calls.clearSlot.push({ slot }); return new Promise(() => {}); };
  for (const fn of maint3) { try { fn(); } catch {} }
  await flush();
  clock3.advance(10000);                       // past slotClearPendingMs
  const h3 = W3.__interceptify.health();
  assert("M3: a superseding clear that never resolves invalidates the old acknowledgement",
    h3.protectionReady === false && h3.notReady.includes("slotCleared"),
    `confirmed=${h3.slotClearConfirmed} notReady=${JSON.stringify(h3.notReady)}`);

  // M4 — Spotify renames the interruptive audio slot.
  const env4 = loadAdblock({ fixture: makeFixture(), clock: makeClock(), baseFetch });
  const W4 = env4.sandbox.window;
  W4.__webpack_modules__ = {
    900: function fakeSlotModule() {
      return 'STREAM_SLOT_ID="audio-stream",HPTO_SLOT_ID="hpto",PODCAST_MIDROLL_SLOT_ID="podcast-midroll-1"';
    },
  };
  const conn4 = makeConnectorStub({ initialState: { ad_enabled: "true" } });
  W4.__interceptify_ads_connector = conn4;
  W4.__interceptify_instream_api = { adsCoreConnector: conn4, skipToNext() {} };
  W4.__interceptify_l1_provider_wrapped = true;
  const maint4 = env4.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
  for (let i = 0; i < 4; i++) { for (const fn of maint4) { try { fn(); } catch {} } await flush(); }
  const h4 = W4.__interceptify.health();
  const cleared4 = conn4.calls.clearSlot.map((c) => c.slot);
  assert("M4: a RENAMED primary slot is promoted, cleared first, and drives readiness",
    h4.primarySlot === "audio-stream" && cleared4[0] === "audio-stream"
      && h4.slotClear.slot === "audio-stream",
    `primary=${h4.primarySlot} firstCleared=${cleared4[0]} ackFor=${h4.slotClear.slot}`);
  assert("M4b: the promotion does not pick a podcast slot",
    h4.primarySlot !== "podcast-midroll-1", `primary=${h4.primarySlot}`);
}

// ===========================================================================
// TEST N — THE FOUR FAIL-OPEN PATHS AT CONNECTOR CHURN AND TRACK TRANSITIONS
//
// Every one of these was green while broken, and all four sit at the two places
// ads actually leak: a track boundary, and a connector being replaced.
//
// N1  A skip suppressed by the over-skip guard produced NO mute either. Mute
//     lived only in the successful-skip branch, and L1 never sets ad_active, so
//     the watchdog had already restored sound ~2s after the previous skip. A
//     second ad at t+2.1s therefore got nothing at all - audible in full.
// N2  The tripwire was armed by a global boolean, not per connector. After
//     Spotify replaced connector A with B, B's deliveries were uncounted,
//     unmuted and uncleared while health still said armed.
// N3  A SYNCHRONOUS getAdState() throw cleared the private flag but not the
//     public gate record - which is the one readiness reads.
// N4  Losing clearSlot from the connector returned early, preserving the last
//     successful acknowledgement forever.
// ===========================================================================
async function testN() {
  const baseFetch = async () => { throw new Error("unexpected fetch in TEST N"); };

  // ---- N1: the multi-ad track-boundary sequence -----------------------
  {
    const clock = makeClock();
    const fixture = makeFixture();
    const env = loadAdblock({ fixture, clock, baseFetch });
    assert("N.load: adblock.js loaded without throwing", env.loadError === null,
      env.loadError ? String(env.loadError && env.loadError.stack || env.loadError) : "");
    const wired = wireInStreamProvider(env, fixture);
    assert("N1.wire: in-stream provider hook installed", !!(wired && wired.api));
    if (wired && wired.api) {
      const muteBtn = env.nodes.muteNode;
      fixture.present.delete('[data-testid="ad-controls"]');
      env.sandbox.document.title = "Spotify";

      // 1. first audio ad: skips and mutes.
      wired.api.inStreamAd = { adId: "break-ad-1", slot: "stream",
                               metadata: { product_name: "audio_ad", format: "audio/ogg" } };
      const afterFirst = fixture.counts.skipToNext;
      assert("N1a: the first ad of the break is skipped and muted",
        afterFirst >= 1 && muteBtn._muted === true,
        `skips=${afterFirst} muted=${muteBtn._muted}`);

      // 2. the watchdog restores sound, because L1 never sets ad_active. This
      //    is correct on its own - a real song is playing by now.
      const watchdog = env.intervals.filter((i) => i.ms === 2000).map((i) => i.fn);
      clock.advance(2000);
      for (const fn of watchdog) { try { fn(); } catch {} }
      assert("N1b: ...and 2s later the watchdog has restored audio",
        muteBtn._muted === false, `muted=${muteBtn._muted}`);

      // 3. a SECOND, distinct audio ad arrives inside the recent-advance guard.
      //    The skip is deliberately suppressed. Containment must not be.
      clock.advance(100);                       // t+2.1s, inside the guard window
      const before2 = fixture.counts.skipToNext;
      wired.api.inStreamAd = { adId: "break-ad-2", slot: "stream",
                               metadata: { product_name: "audio_ad", format: "audio/ogg" } };
      assert("N1c: the second ad's skip is still suppressed (the guard is right)",
        fixture.counts.skipToNext === before2,
        `skips went ${before2} -> ${fixture.counts.skipToNext}`);
      assert("N1d (THE LEAK): ...but it IS muted, instead of getting nothing at all",
        muteBtn._muted === true,
        `muted=${muteBtn._muted} - zero skip AND zero mute is an audible ad`);
    }
  }

  // ---- N2: connector replacement --------------------------------------
  {
    const env = loadAdblock({ fixture: makeFixture(), clock: makeClock(), baseFetch });
    const W = env.sandbox.window;
    const maint = env.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
    const connA = makeConnectorStub({ initialState: { ad_enabled: "true" } });
    W.__interceptify_ads_connector = connA;
    W.__interceptify_instream_api = { adsCoreConnector: connA, skipToNext() {} };
    W.__interceptify_l1_provider_wrapped = true;
    for (let i = 0; i < 4; i++) { for (const fn of maint) { try { fn(); } catch {} } await flush(); }
    assert("N2.setup: covering connector A, and ready",
      W.__interceptify.health().tripwireCoversLive === true
        && W.__interceptify.health().protectionReady === true,
      JSON.stringify(W.__interceptify.health().notReady));

    // Spotify swaps the connector underneath us.
    const connB = makeConnectorStub({ initialState: { ad_enabled: "true" } });
    W.__interceptify_ads_connector = connB;
    W.__interceptify_instream_api = { adsCoreConnector: connB, skipToNext() {} };
    const h = W.__interceptify.health();
    assert("N2a (THE BUG): a replaced connector is NOT reported as covered",
      h.tripwireCoversLive === false && h.protectionReady === false,
      `covers=${h.tripwireCoversLive} ready=${h.protectionReady} notReady=${JSON.stringify(h.notReady)}`);

    // ...and the maintenance loop re-subscribes to the live one.
    for (let i = 0; i < 4; i++) { for (const fn of maint) { try { fn(); } catch {} } await flush(); }
    const before = W.__interceptify_ads_delivered || 0;
    connB.deliver({ adId: "on-connector-b", slot: "stream",
                    metadata: { product_name: "audio_ad", format: "audio/ogg" } });
    await flush();
    assert("N2b: after re-subscribing, connector B's deliveries ARE observed",
      (W.__interceptify_ads_delivered || 0) === before + 1,
      `delivered ${before} -> ${W.__interceptify_ads_delivered}`);
    assert("N2c: ...and contained, not merely counted",
      env.nodes.muteNode._muted === true, `muted=${env.nodes.muteNode._muted}`);
  }

  // ---- N3: a SYNCHRONOUS gate failure ---------------------------------
  {
    const env = loadAdblock({ fixture: makeFixture(), clock: makeClock(), baseFetch });
    const W = env.sandbox.window;
    const maint = env.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
    const conn = makeConnectorStub({ initialState: { ad_enabled: "true" } });
    W.__interceptify_ads_connector = conn;
    W.__interceptify_instream_api = { adsCoreConnector: conn, skipToNext() {} };
    W.__interceptify_l1_provider_wrapped = true;
    for (let i = 0; i < 4; i++) { for (const fn of maint) { try { fn(); } catch {} } await flush(); }
    assert("N3.setup: ready before the gate breaks",
      W.__interceptify.health().protectionReady === true);

    conn.getAdState = () => { throw new Error("core gone"); };   // synchronous throw
    for (const fn of maint) { try { fn(); } catch {} }
    await flush();
    const h = W.__interceptify.health();
    assert("N3 (THE BUG): a synchronous getAdState throw is not left reporting green",
      h.protectionReady === false && h.notReady.includes("gateClosed"),
      `ready=${h.protectionReady} notReady=${JSON.stringify(h.notReady)} err=${h.gateError}`);

    // A non-Promise RETURN is the same class of failure.
    const env2 = loadAdblock({ fixture: makeFixture(), clock: makeClock(), baseFetch });
    const W2 = env2.sandbox.window;
    const maint2 = env2.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
    const conn2 = makeConnectorStub({ initialState: { ad_enabled: "true" } });
    W2.__interceptify_ads_connector = conn2;
    W2.__interceptify_instream_api = { adsCoreConnector: conn2, skipToNext() {} };
    W2.__interceptify_l1_provider_wrapped = true;
    for (let i = 0; i < 4; i++) { for (const fn of maint2) { try { fn(); } catch {} } await flush(); }
    conn2.getAdState = () => ({ state: { ad_enabled: { value: "false" } } });   // not a promise
    for (const fn of maint2) { try { fn(); } catch {} }
    await flush();
    assert("N3b: ...and so is a getAdState that returns no promise",
      W2.__interceptify.health().protectionReady === false,
      JSON.stringify(W2.__interceptify.health().notReady));
  }

  // ---- N4: clearSlot disappears ---------------------------------------
  {
    const env = loadAdblock({ fixture: makeFixture(), clock: makeClock(), baseFetch });
    const W = env.sandbox.window;
    const maint = env.intervals.filter((i) => i.ms !== 500).map((i) => i.fn);
    const conn = makeConnectorStub({ initialState: { ad_enabled: "true" } });
    W.__interceptify_ads_connector = conn;
    W.__interceptify_instream_api = { adsCoreConnector: conn, skipToNext() {} };
    W.__interceptify_l1_provider_wrapped = true;
    for (let i = 0; i < 4; i++) { for (const fn of maint) { try { fn(); } catch {} } await flush(); }
    assert("N4.setup: the stream clear was acknowledged",
      W.__interceptify.health().slotClearConfirmed === true,
      JSON.stringify(W.__interceptify.health().slotClear));

    delete conn.clearSlot;                       // the method goes away
    for (const fn of maint) { try { fn(); } catch {} }
    await flush();
    const h = W.__interceptify.health();
    assert("N4 (THE BUG): losing clearSlot invalidates the old acknowledgement",
      h.slotClearConfirmed === false && h.protectionReady === false
        && h.notReady.includes("slotCleared"),
      `confirmed=${h.slotClearConfirmed} notReady=${JSON.stringify(h.notReady)}`);
  }
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
  try { testE(); } catch (e) {
    assert("TEST E crashed", false, String(e && e.stack || e));
  }
  try { testF(); } catch (e) {
    assert("TEST F crashed", false, String(e && e.stack || e));
  }
  try { testG(); } catch (e) {
    assert("TEST G crashed", false, String(e && e.stack || e));
  }
  try { testH(); } catch (e) {
    assert("TEST H crashed", false, String(e && e.stack || e));
  }
  try { testI(); } catch (e) {
    assert("TEST I crashed", false, String(e && e.stack || e));
  }
  try { await testJ(); } catch (e) {
    assert("TEST J crashed", false, String(e && e.stack || e));
  }
  try { testK(); } catch (e) {
    assert("TEST K crashed", false, String(e && e.stack || e));
  }
  try { await testL(); } catch (e) {
    assert("TEST L crashed", false, String(e && e.stack || e));
  }
  try { await testM(); } catch (e) {
    assert("TEST M crashed", false, String(e && e.stack || e));
  }
  try { await testN(); } catch (e) {
    assert("TEST N crashed", false, String(e && e.stack || e));
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
