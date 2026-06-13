# Interceptify v2

A small Windows tray app that **blocks ads in the Spotify desktop client** by patching its UI bundle (`xpui.spa`). v2 is a stability- and robustness-focused rework: it blocks Spotify's in-stream ad payloads before they reach the player, classifies short ad manifests pre-playback, and runs an explicit ad-state machine whose **single guarantee is that it never skips your real music** — even on the ad→song transition where v1 sometimes did.

> 🛑 **You need the desktop installer Spotify**, not the Microsoft Store version.
> Download from **[spotify.com/download](https://www.spotify.com/download)**. The Store version is sandboxed and the patcher can't touch it.

> ⚠️ **Honest limitations.**
> - Spotify auto-updates wipe the patch. Re-patch with one click after each update (or enable auto re-patch).
> - The in-stream block keys on Spotify's `inStreamApi`. v2 finds it by scanning module *source text* (not a hard-coded module id), so it survives most rebuilds — but a deep rename can still need a config tweak.
> - When the in-stream layer can't skip an ad (e.g. the hardest audio preroll where Spotify disables every skip control), v2 **mutes it and lets it play out** rather than risk skipping your next song. That's the deliberate trade — stability over aggression.
> - This is a hobby tool. For a maintained, full-ecosystem option, [Spicetify](https://spicetify.app/) is the bigger project.

## Install

### Easy — prebuilt .exe
1. Grab **Interceptify.exe** from the [Releases page](https://github.com/mattebin/interceptify/releases).
2. Double-click. Accept the UAC prompt (needed to write to `%APPDATA%\Spotify\Apps\xpui.spa`).
3. Right-click the tray shield → **Patch Spotify (start blocking ads)**.

### From source
```bat
pip install -r requirements.txt
python main.py
```
The app auto-elevates via UAC.

## Tray menu

| Item | What it does |
|---|---|
| **Patch Spotify** / **Unpatch Spotify** | Injects (or removes) the ad-block JS in `xpui.spa`. Closes & relaunches Spotify. |
| **Install update vX.Y.Z** | Appears when a newer release is on GitHub. Downloads, **verifies its SHA-256**, then restarts. |
| **Show status dot in Spotify** | Toggles the small dot in Spotify's top-right (green = idle, orange = suspected/muting, red = ad confirmed). |
| **Debug capture mode** | Off by default. Turns on the in-page sniffer **and** opens Spotify's DevTools endpoint on loopback for diagnosing new ad paths. Leave off for normal use. |
| **Run at Windows startup** | Adds Interceptify to `HKCU\…\Run` so it's there to re-patch after Spotify updates. |
| **Exit** | Quits the tray (the patch stays applied). |

## How it works

The patcher unzips `xpui.spa`, inlines `extensions/adblock.js` into `index.html` (preceded by the tunables from `extensions/adblock.config.json` as `window.__INTERCEPTIFY_CONFIG`), and re-zips. The original is preserved at `xpui.spa.interceptify-backup`. Our script runs **before** Spotify's deferred `xpui-snapshot.js`, so it hooks fetch, the webpack module graph, MediaSource, etc. before the player boots.

### Layer 1 — In-stream payload block (pre-paint)
Hooks Spotify's renderer-side in-stream ad provider and neutralises ad payloads before the visible player commits to them: wraps `onAdMessageCallbacks`, clears `inStreamAd`, returns `null` from `getInStreamAd()`, and calls `skipToNext()` once per ad. **v2 finds the provider module by scanning module source for `getInStreamAd` / `inStreamApi` / `onAdMessageCallbacks`** instead of a hard-coded webpack id, so a minifier renumbering no longer silently disables it. If no module matches, it logs once and leans on L2/L3.

### Layer 2 — Manifest pre-player block
Fetch interceptors stop known short ad manifests and their audio segments from loading:

| Endpoint | What we do |
|---|---|
| `/sponsoredplaylist/v1/sponsored` | Return `{"sponsorships":[]}`. |
| `/manifests/v9/json/sources/<srcId>/options/...` | If the manifest is short (`end_time_millis` between `manifestAdMinMs` and `manifestAdMaxMs`) **and corroborated** by an ad marker in the body or a concurrent ad signal, rewrite the response to `{"contents":[]}` and remember the `srcId`. |
| `/sources/<srcId>/...` segments | If `srcId` is a remembered ad source, return **404**. |

**Music is 200,000–500,000 ms; ads are <60,000 ms.** v2 adds a **corroboration guard**: a short manifest alone is no longer enough to block — so a <60 s *real* track (interlude, skit, punk song) is never silently 404'd. Classified sources are kept in a capped LRU set.

### Layer 3 — Ad-state machine + gated skip (the no-over-skip core)
A single state machine — `IDLE → SUSPECTED → CONFIRMED → SKIPPING → COOLDOWN` — drives detection and action from a 500 ms tick.

- **Strong signals** (a *currently-painted* audio/video-ad test-id like `ad-controls`, `ads-video-player-npv`, `canvas-ad-player`, plus a fuzzy fallback) are the **only** thing that can authorise advancing the queue.
- **Weak signals** (Spotify's `adplaying` event, lingering `leavebehind`/companion banners, the `<title>`+short-audio heuristic, `class*=Advertisement`) only **mute** — they can never skip.
- Every advancing action (in-stream `skipToNext`, native skip-forward click, `seek-forward-15` burst, ad-video-scoped `ended`) goes through **one gated choke point** that requires: state `CONFIRMED`, a strong marker *this tick*, not in post-ad cooldown, not spinning, and a per-ad retry budget. After a skip, a **cooldown + now-playing verification** confirm the track actually changed.
- The blind v1 mechanisms that caused over-skips — setting the progress bar to the end, synthetic seek clicks, `Shift+ArrowRight`, blanket `<video>` `ended` — **are removed** (a DOM-spray last resort exists but is off by default).
- Mute uses Spotify's volume button + a per-context WebAudio gain, armed only while an ad is confirmed, state-tracked so it never fights your manual mute, and a watchdog guarantees gain/mute always restore (no stuck-silent next song, even if Spotify was minimised).

## Configuration — surviving Spotify updates

Every value Spotify can break on an update — selectors, module-discovery signatures, URL regexes, the duration threshold, ad-object fields — lives in **`extensions/adblock.config.json`**. The patcher injects it as `window.__INTERCEPTIFY_CONFIG`, shallow-merged over the in-file defaults. **After a Spotify update breaks blocking, edit the JSON and re-patch — no code change or rebuild.** See the `_comment` field in that file.

## Detective / debug

Turn on **Debug capture mode** in the tray (off by default). Spotify then launches with a DevTools endpoint bound to **loopback only, with an exact allowed origin** (not the old `--remote-allow-origins=*`), so you can attach DevTools from a local browser:

```
http://127.0.0.1:9222
```

In the console:
```js
__interceptify.status()         // FSM state + detection counters + discovered module ids
__interceptify.state()          // current ad-state (IDLE/SUSPECTED/CONFIRMED/SKIPPING/COOLDOWN)
__interceptify.instreamModuleIds()  // which webpack modules the source-scan hooked
__interceptify.scanAds()        // ad-shaped elements right now
__interceptify.testIds()        // every data-testid in the DOM
```
With debug capture on, an in-page sniffer also records fetch / XHR / WebSocket / MediaSource events (`window.__interceptify_sniffer`, `window.__interceptify_meta_log`, `window.__interceptify_known_ad_sources`).

## Building yourself

```bat
pip install -r requirements.txt pyinstaller
pyinstaller --noconfirm --onefile --windowed ^
  --name "Interceptify" ^
  --manifest interceptify.manifest ^
  --uac-admin ^
  --add-data "extensions;extensions" ^
  main.py
```

Output: `dist\Interceptify.exe`. The `--add-data "extensions;extensions"` bundles both `adblock.js` and `adblock.config.json`. CI (`.github/workflows/release.yml`) also publishes an `Interceptify.exe.sha256` asset that the in-app updater verifies before installing.

## Security notes

- The self-updater only downloads from GitHub hosts, checks the asset size, and **verifies the SHA-256** before swapping the (admin-level) exe — it fails closed on a mismatch.
- Remote debugging is **opt-in** (Debug capture mode) and bound to loopback with an exact origin. The dev-mode prefs flag is only set in debug mode and is removed on unpatch.

## License

MIT — see [LICENSE](LICENSE).

## Notes / changelog

Earlier releases (≤ v1.4.0) shipped a mitmproxy + Windows-proxy pipeline; Spotify 1.2.88+ stopped using the Windows proxy, so it was removed in v1.5.0. The xpui patch is the only working layer on modern Spotify.

- **v1.5.2** — manifest-based pre-player block (`end_time_millis` discriminator).
- **v1.5.3** — in-stream payload block wrapping Spotify's renderer ad provider.
- **v2.0.0** — over-skip rework: explicit ad-state machine with a single gated skip choke point that **never skips a real song**; ID-agnostic in-stream module discovery; manifest corroboration guard (no more false-blocking short real tracks); all build-volatile knobs externalized to `adblock.config.json`; mute/gain watchdog so playback never stays stuck silent; integrity-verified self-update; remote debugging made opt-in and loopback-bound. The phone (ntfy) test notification was removed.
