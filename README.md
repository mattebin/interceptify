# Interceptify v2

A small Windows tray app that **blocks ads in the Spotify desktop client** by patching its UI bundle (`xpui.spa`). v2 is a stability- and robustness-focused rework: it blocks Spotify's in-stream ad payloads before they reach the player, classifies short ad manifests pre-playback, and runs an explicit ad-state machine whose **single guarantee is that it never skips your real music**, even on the ad→song transition where v1 sometimes did.

> 🛑 **You need the desktop installer Spotify**, not the Microsoft Store version.
> Download from **[spotify.com/download](https://www.spotify.com/download)**. The Store version is sandboxed and the patcher can't touch it.

> ⚠️ **Honest limitations.**
> - Spotify auto-updates wipe the patch. Re-patch with one click after each update, or tick the repair options under **Autostart** and it is put back for you.
> - The in-stream block keys on Spotify's `inStreamApi`. v2 finds it by scanning module *source text* (not a hard-coded module id), so it survives most rebuilds, but a deep rename can still need a config tweak.
> - When the in-stream layer can't skip an ad (e.g. the hardest audio preroll where Spotify disables every skip control), v2 **mutes it and lets it play out** rather than risk skipping your next song. That's the deliberate trade: stability over aggression.
> - This is a hobby tool. For a maintained, full-ecosystem option, [Spicetify](https://spicetify.app/) is the bigger project.

## Install

### Easy: prebuilt .exe
1. Grab **Interceptify.exe** from the [Releases page](https://github.com/mattebin/interceptify/releases).
2. Double-click. No UAC prompt: it runs as you. Everything it writes
   (`%APPDATA%\Spotify\Apps\xpui.spa`, Spotify's prefs, its own config) is
   already owned by your account.
3. Right-click the tray shield → **Patch Spotify (start blocking ads)**.

### From source
```bat
pip install -r requirements.txt
python main.py
```
Runs unelevated. Earlier versions demanded Administrator, which bought no
extra capability and meant a high-integrity process launched out of a
user-writable directory.

## Tray menu

| Item | What it does |
|---|---|
| *(first line, greyed out)* | The last thing the app did or found. Interceptify never shows pop-up notifications. This line and the log are where it reports. |
| **Patch Spotify** / **Unpatch Spotify** | Injects (or removes) the ad-block JS in `xpui.spa`. Closes & relaunches Spotify. After Unpatch, the automatic repair leaves Spotify alone until you patch again. |
| **Install update vX.Y.Z** | Appears when a newer release is on GitHub and is not installed yet. Downloads, **verifies its SHA-256**, then restarts. |
| **Check for updates (now X.Y.Z)** | Checks GitHub right away. |
| **Update automatically** | On by default. New releases are installed without asking, and the patch in Spotify is refreshed afterwards. |
| **Show status dot in Spotify** | Toggles the small dot in Spotify's top-right (green = idle, orange = suspected/muting, red = ad confirmed). |
| **Debug capture mode** | Off by default. Turns on the in-page sniffer **and** opens Spotify's DevTools endpoint on loopback for diagnosing new ad paths. Leave off for normal use. |
| **Autostart** → **Start Interceptify when I log in** | Adds the tray to your Windows startup programs. |
| **Autostart** → **Check and repair the patch when I log in** | A check at logon. If a Spotify update wiped the patch, it is put back. Spotify is restarted once, and only if it was open. |
| **Autostart** → **Check and repair the patch daily (08:00 and 21:00)** | The same check twice a day. |
| **Exit** | Quits the tray (the patch stays applied). |

## How it works

The patcher unzips `xpui.spa`, inlines `extensions/adblock.js` into `index.html` (preceded by the tunables from `extensions/adblock.config.json` as `window.__INTERCEPTIFY_CONFIG`), and re-zips. The original is preserved at `xpui.spa.interceptify-backup`. Our script runs **before** Spotify's deferred `xpui-snapshot.js`, so it hooks fetch, the webpack module graph, MediaSource, etc. before the player boots.

### The main block: Spotify's own ad switch
Spotify's client asks its core whether ads are enabled. The payload finds the ads connector at runtime, sets `ad_enabled` to `false` and clears the ad slots that were already queued, so ad breaks are never scheduled. If Spotify turns the switch back on, the payload turns it off again. The connector is found by what it can do (its `putState` and `getAdState` methods), not by its name or module id, so a rebuild that renames things does not lose it. The layers below are the fallback for an ad that gets through anyway.

### Layer 1: In-stream payload block (pre-paint)
Hooks Spotify's renderer-side in-stream ad provider and neutralises ad payloads before the visible player commits to them: wraps `onAdMessageCallbacks`, clears `inStreamAd`, returns `null` from `getInStreamAd()`, and calls `skipToNext()` once per ad. **v2 finds the provider module by scanning module source for `getInStreamAd` / `inStreamApi` / `onAdMessageCallbacks`** instead of a hard-coded webpack id, so a minifier renumbering no longer silently disables it. If no module matches, it logs once and leans on L2/L3.

### Layer 2: Manifest pre-player block
Fetch interceptors stop known short ad manifests and their audio segments from loading:

| Endpoint | What we do |
|---|---|
| `/sponsoredplaylist/v1/sponsored` | Return `{"sponsorships":[]}`. |
| `/manifests/v9/json/sources/<srcId>/options/...` | If the manifest is short (`end_time_millis` between `manifestAdMinMs` and `manifestAdMaxMs`) **and corroborated** by an ad marker in the body or a concurrent ad signal, rewrite the response to `{"contents":[]}` and remember the `srcId`. |
| `/sources/<srcId>/...` segments | If `srcId` is a remembered ad source, return **404**. |

**Music is 200,000–500,000 ms; ads are <60,000 ms.** v2 adds a **corroboration guard**: a short manifest alone is no longer enough to block, so a <60 s *real* track (interlude, skit, punk song) is never silently 404'd. Classified sources are kept in a capped LRU set.

> **Off by default.** `manifestDurationBlock` is `false` in `adblock.config.json`, so duration-based manifest blocking does not run unless you turn it on. The risk it guards against is real - misclassifying a short real track means silently 404'ing music you wanted - and L1 plus the ad-scheduler gate already handle ads without it. What stays active by default is segment blocking for sources already *confirmed* to be ads.

### Layer 3: Ad-state machine + gated skip (the no-over-skip core)
A single state machine (`IDLE → SUSPECTED → CONFIRMED → SKIPPING → COOLDOWN`) drives detection and action from a 500 ms tick.

- **Strong signals** (a *currently-painted* audio/video-ad test-id like `ad-controls`, `ads-video-player-npv`, `canvas-ad-player`, plus a fuzzy fallback) are the **only** thing that can authorise advancing the queue.
- **Weak signals** (Spotify's `adplaying` event, lingering `leavebehind`/companion banners, the `<title>`+short-audio heuristic, `class*=Advertisement`) only **mute**. They can never skip.
- Every advancing action (in-stream `skipToNext`, native skip-forward click, `seek-forward-15` burst, ad-video-scoped `ended`) goes through **one gated choke point** that requires: state `CONFIRMED`, a strong marker *this tick*, not in post-ad cooldown, not spinning, and a per-ad retry budget. After a skip, a **cooldown + now-playing verification** confirm the track actually changed.
- The blind v1 mechanisms that caused over-skips (setting the progress bar to the end, synthetic seek clicks, `Shift+ArrowRight`, blanket `<video>` `ended`) **are removed** (a DOM-spray last resort exists but is off by default).
- Mute uses Spotify's volume button + a per-context WebAudio gain, armed only while an ad is confirmed, state-tracked so it never fights your manual mute, and a watchdog guarantees gain/mute always restore (no stuck-silent next song, even if Spotify was minimised).

## Configuration: surviving Spotify updates

Every value Spotify can break on an update (selectors, module-discovery signatures, URL regexes, the duration threshold, ad-object fields) lives in **`extensions/adblock.config.json`**. The patcher injects it as `window.__INTERCEPTIFY_CONFIG`, shallow-merged over the in-file defaults. **After a Spotify update breaks blocking, edit the JSON and re-patch. No code change or rebuild.**

Two files, not one:

| File | Owner | On update |
|---|---|---|
| `extensions/adblock.config.json` | the release | **replaced** |
| `extensions/adblock.config.local.json` | you (and the self-heal) | never touched, and merged **on top** |

Put your own changes in the `.local.json` file. The shipped file holds exactly the values a release exists to correct, so it has to be replaceable: when both lived in one file, a release that fixed a module id or a selector could never reach anyone who already had the file. A customised shipped config is **not** migrated for you. If the new build finds `adblock.config.json` modified, it installs the new defaults (so the fix lands) and sets your previous file aside intact as `adblock.config.superseded-<timestamp>.json`. Copy anything you meant to keep into `.local.json`, which is never overwritten.

The reason it does not migrate automatically: file content cannot distinguish "the user edited this" from "this is simply the previous release's copy", and guessing is wrong in both directions - keep the old values and the fix never lands; drop them and your work disappears silently.

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
pip install -r requirements.txt "pyinstaller==6.11.1"
pyinstaller --noconfirm Interceptify-v2.spec
```

The pinned PyInstaller version matches CI. An unpinned local build is a different toolchain producing a different binary, which is how the local and released artifacts drifted apart the first time.

Output: `dist\Interceptify.exe`. Build from the spec, not a hand-written command line - CI uses the same file. The two used to differ (`uac_admin=True` in the spec, no `--uac-admin` in CI), so a local build produced an **elevated** binary that looked exactly like the release. `tests/test_bundled_payload.py` now fails the build if the .exe carries a different payload than the commit, requests anything but `asInvoker`, or is missing the modules it needs to run its own self-heal.

CI (`.github/workflows/release.yml`) also publishes an `Interceptify.exe.sha256` asset that the in-app updater verifies before installing.

## One install, one payload

The .exe is the whole application: `Interceptify.exe --selfheal --once` and `Interceptify.exe --install-tasks` are the same code paths as the scripts. That matters because the updater replaces `Interceptify.exe` and nothing else. If autostart pointed at a source checkout while the .exe updated itself, the old checkout would keep re-patching Spotify with its own older payload at every logon - the version string moves, the code that runs does not.

So autostart is always registered for whichever install did the registering, and a mismatch is reported rather than silently resolved: the tray shows it on its status line, `--verify` reports it, self-heal refuses to claim a pass, and the updater refuses to install.

The tray itself starts from your Windows startup programs (the `Run` entry), not from a scheduled task. Only the repair checks are scheduled tasks.

```bat
python install_tasks.py --status    :: what is registered, and for which install
python install_tasks.py             :: install / repair
python install_tasks.py --remove    :: take it all back out
```

## Checking on it

```bat
python selfheal.py --verify      :: READ-ONLY. Reports status, changes nothing.
python selfheal.py --selftest    :: DISRUPTIVE causal proof. Interrupts playback.
```

`--verify` reads the fingerprint on disk and, if a debug session is already open, the payload's own health. `--selftest` is the one that proves the block: it toggles Spotify's own ad gate both ways, requires the core to echo it, reopens the gate and requires the block to re-close it unaided, and starts playback if nothing is streaming, because a window with no audio cannot exercise what it is testing. Expect it to stop your music.

The scheduled repair (`--once`) only puts the patch back when Spotify's file needs it. It does not open Spotify with a debug port. To also have it prove the block inside the running client after each repair (two Spotify restarts), add `"live_verify": true` to `config.json` next to the app.

`python recon_ids.py` writes down every Spotify-side name the block depends on (module ids, export names, slot ids) as one JSON file per Spotify build, so the next update can be compared with the last. It restarts Spotify once.

## Security notes

- The app runs **as the invoking user**, never elevated.
- The self-updater only downloads from GitHub hosts, checks the asset size, and **verifies the SHA-256** before swapping the exe - it fails closed on a mismatch. The generated update script re-checks that hash immediately before the swap, because verifying at download time says nothing about the bytes installed seconds later.
- The .exe is **not code-signed**, and the published `.sha256` comes from the same release as the binary. It proves the download was not corrupted; it is not independent proof of who built it.
- Remote debugging is **opt-in** (Debug capture mode) and bound to loopback with an exact origin. The dev-mode prefs flag is only set in debug mode, and is only removed again if *we* were the ones who set it - a tool that cleans up after itself is right, one that also undoes your own settings is not.
- Diagnostic files from earlier versions (`capture_*.json`, `netlog_*.jsonl`) can hold request data. `python selfheal.py --redact-captures` masks tokens in them. Delete them when you are done.
- Scheduled tasks run at `LIMITED` run level, as you.

## License

MIT, see [LICENSE](LICENSE).

## Notes / changelog

Earlier releases (≤ v1.4.0) shipped a mitmproxy + Windows-proxy pipeline; Spotify 1.2.88+ stopped using the Windows proxy, so it was removed in v1.5.0. The xpui patch is the only working layer on modern Spotify.

- **v1.5.2**: manifest-based pre-player block (`end_time_millis` discriminator).
- **v1.5.3**: in-stream payload block wrapping Spotify's renderer ad provider.
- **v2.0.0**: over-skip rework: explicit ad-state machine with a single gated skip choke point that **never skips a real song**; ID-agnostic in-stream module discovery; manifest corroboration guard (no more false-blocking short real tracks); all build-volatile knobs externalized to `adblock.config.json`; mute/gain watchdog so playback never stays stuck silent; integrity-verified self-update; remote debugging made opt-in and loopback-bound. The phone (ntfy) test notification was removed.
- **v2.0.1**: near-instant silent ad skipping, plus inspect and debug tooling.
- **v2.0.2**: first total-block layer (ad state and stream time).
- **v2.0.3**: total block restored on Spotify 1.2.93, the first V8-snapshot build.
- **v2.0.4**: self-healing ad gate and a block that can be verified, for Spotify 1.2.94.
- **v2.0.5**: the ad connector is found by its state methods instead of the skip method. Scheduled tasks no longer open ghost Terminal windows.
- **v2.0.6**: Spotify 1.3.0 support. The 1.3.0 build renamed its chunk-loading global to plain `rspackChunk`, changed the module runtime's `d()` to a three-argument form, and moved the ad modules to new ids. The ad connector and its `ad_enabled` switch were unchanged, but the payload could no longer reach them, so only the mute fallback ran. Fixed: the new global is hooked, the real module loader is always preferred over the reconstructed fallback (which can no longer be mistaken for it), the fallback understands the three-argument `d()`, and provider discovery reads the original factory source and ignores implementation-sized matches. Also removed a dead recon tool (`frida_recon.py`) and stale ignore rules.
- **v2.0.7**: Spotify 1.3.9 support. That build renamed the exports of its in-stream ad module, and the old hook replaced them by name, which left Spotify stuck on its loading screen. The hook now wraps whatever the module exports and recognises things by what they do. The connector, the module table and the chunk loader are found the same way when their names move. The tray is now silent (no pop-up notifications, a status line in the menu instead), installs updates by itself and refreshes the patch afterwards, starts from the Windows startup programs instead of a scheduled task, and has separate Autostart options. The scheduled repair respects Unpatch, restarts Spotify once and only when the patch is actually missing.
