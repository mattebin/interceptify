# Interceptify v2 — adblock.js regression tests

Dependency-free, Node-only regression test for `extensions/adblock.js` (the IIFE
injected into Spotify's renderer). No npm install, no test framework — just Node
24+ and the standard library (`node:vm`, `node:fs`).

## Run

From the `interceptify v2` directory:

```bash
node tests/test_adblock.mjs
```

Add `VERBOSE=1` to print the numeric detail behind every assertion:

```bash
VERBOSE=1 node tests/test_adblock.mjs     # PowerShell: $env:VERBOSE=1; node tests/test_adblock.mjs
```

Exit code is `0` when every assertion passes and `1` if any fail, so it drops
straight into CI.

## What it guards

The test loads the **real, unmodified** `extensions/adblock.js` inside a
`node:vm` sandbox with a minimal browser-like global stub (a `window`,
a `document` with `querySelector`/`querySelectorAll` driven by a mutable
fixture, captured timers, a controllable virtual clock, a stub `Response`, and
prototype-bearing globals like `HTMLElement`/`AudioNode` for the load-time
hooks). It then captures the FSM `check()` tick (`setInterval(fn, 500)`) and the
installed `window.fetch`, and drives them by hand.

### TEST A — the no-over-skip invariant (critical)

This is the regression that matters: the v1 blocker over-skipped real songs when
ad UI lingered one render past the ad audio. The test:

1. Paints an audio ad (`[data-testid="ad-controls"]` present, skip-forward
   present+enabled to model Premium, now-playing = `"Advertisement"`), drives
   several ticks, and asserts **at least one** skip/advance fires.
2. Simulates the ad -> song transition: strong selectors gone, now-playing =
   `"Real Song Name"`, **including** the nasty case where a lingering weak ad
   text node (`context-item-info-ad-subtitle`) is still present for one tick.
   Asserts **zero** additional skip-forward / seek-15 / `skipToNext()` actions
   fire on the real song, and that the FSM settles to `IDLE`/`COOLDOWN`.
3. Drives a weak-only "SUSPECTED" signal (`__interceptify_instream_ad_until` in
   the future, no strong selector) and asserts **zero** advances (mute-only),
   staying in `SUSPECTED`.

A throwaway negative control (run during development, not committed) confirmed
the keystone assertion has teeth: when the ad genuinely persists, the advance
counter keeps climbing — so the only reason TEST A passes is that adblock.js
correctly stops advancing once now-playing moves off the ad.

### TEST B — the manifest classifier

Exercises the `/manifests/v9/json/sources/<hex>/options/...` interception in the
single `window.fetch` hook. A fake base `fetch` is installed *before* adblock.js
loads, so the wrapper chains to it.

| Case | Config | Manifest body | Expected |
|------|--------|---------------|----------|
| B1 | `manifestDurationBlock` OFF (default) | short (`end_time_millis: 30000`) | passthrough (original body) |
| B2 | `manifestDurationBlock: true` + strong ad marker painted | short (`30000`) | blocked -> `{"contents":[]}` |
| B3 | `manifestDurationBlock: true` | music length (`240000`) | passthrough |

## Scope

The test **never** modifies `extensions/adblock.js` or any other project file —
it only reads `extensions/adblock.js`. All behavior is driven through the
captured `check()` tick and `window.fetch`. If a real adblock.js bug ever made
these invariants impossible to satisfy, the harness would fail loudly rather
than be patched around.
