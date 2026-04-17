# Interceptify

A Windows tray app that runs an **embedded mitmproxy** to block ad & telemetry requests made by desktop apps — starting with **Spotify**. Extensible to any other app by dropping a filter file.

> ⚠️ **Honest disclaimer.** This is a learning / hobby tool.
> - **Spotify audio ads stream from the same CDN as music**, so they cannot be reliably blocked by URL filtering. Expect to still hear some audio ads.
> - Spotify ships updates that rename endpoints — filters will need occasional tuning.
> - Any future move to **certificate pinning** would break this entirely, with no workaround.
> - If you want serious, maintained blocking: use [AdGuard](https://adguard.com/) or a Pi-hole.

## How it works

```
  Spotify ──► Windows system proxy (127.0.0.1:8080) ──► mitmproxy (in-process)
                                                              │
                                      filters/spotify.txt  ◄──┤  match?
                                                              ▼
                                                  yes → 403 Blocked
                                                   no → forward upstream
```

Toggling ON:
1. Starts an in-process `mitmproxy.DumpMaster` with our `BlockerAddon` on `127.0.0.1:8080`.
2. Snapshots and then overwrites the per-user WinINET proxy settings in the registry.
3. Installs mitmproxy's auto-generated CA into the **Windows Trusted Root** store so HTTPS interception works (only on first run).

Toggling OFF reverses all three.

## Install

### Easy way — download the prebuilt exe
1. Grab **Interceptify.exe** from the [Releases page](https://github.com/mattebin/interceptify/releases).
2. Double-click it. Accept the UAC prompt.
3. Shield icon appears in your tray.

### From source (Python 3.10+)
```bat
pip install -r requirements.txt
python main.py
```
The app auto-elevates via UAC if launched without admin rights.

## Tray controls

| Action          | Result                                                          |
|-----------------|-----------------------------------------------------------------|
| Left-click      | Toggle blocking ON (green ✓) / OFF (grey ✕)                    |
| **Toggle**      | Same as left-click                                              |
| **🎵 Ad is playing — capture now** | Learn mode. Click this the moment an ad plays — see below |
| **Reload filters** | Re-reads all files in `filters/` without restarting          |
| **Install certificate** | Re-install mitmproxy CA (if you cleared it manually)    |
| **Open filter rules**   | Opens `filters/` in Explorer so you can edit rules      |
| **View blocked requests** | Toast with per-app counts + opens `blocked.log`       |
| **Exit**        | Stops proxy, restores system proxy, quits                       |

## Learn mode — teach it what an ad looks like

The proxy keeps a **rolling 60-second buffer** of every request Spotify makes that wasn't already blocked. When you hear an ad:

1. **Pause Spotify** the moment you notice the ad.
2. Right-click the tray icon → **🎵 Ad is playing — capture now**.
3. Interceptify scans the last 30 s of traffic and keeps entries that are:
   - on a known ad-network host, **or**
   - under an ad-shaped path (`/ads/`, `/promo/`, `/tracking/`, `/pixel`, …), **or**
   - an audio/video response (the actual ad stream).
4. New rules are appended to **`filters/spotify-learned.txt`** (deduped against existing rules), the engine reloads, and a toast shows what was added.
5. `apps.json` is updated automatically so the learned file is always loaded.

**This is the file you commit to git** — share your captures by pushing:

```bat
git add filters/spotify-learned.txt apps.json
git commit -m "Add learned Spotify ad endpoints"
git push
```

Review the file before committing — the heuristics are conservative but not perfect. Remove anything that looks like legit music/auth traffic.

## Filter syntax

One rule per line in `filters/<appname>.txt`. Lines starting with `#` are comments.

| Rule form                    | Matches                                    |
|------------------------------|--------------------------------------------|
| `example.com`                | That host, exactly, or any subdomain of it |
| `example.com/ads/`           | That host AND a URL path starting with `/ads/` |
| `*/tracking/*`               | Any request whose path contains `/tracking/` |
| `re:^https://.*/pixel\?id=`  | Python regex against the full URL          |

## Adding a new app

1. Create `filters/<appname>.txt` and add rules.
2. Add an entry to `apps.json`:

   ```json
   {
     "apps": {
       "spotify": { "filter_file": "filters/spotify.txt", "enabled": true },
       "discord":  { "filter_file": "filters/discord.txt",  "enabled": true }
     }
   }
   ```

3. Restart the app. New rules are loaded automatically.

For per-app logic more complex than URL blocking (e.g. rewriting JSON response bodies to strip inline ads), see the commented `response()` hook in `proxy_addon.py`.

## Test plan — verify the proxy is live

1. Toggle Interceptify **ON**.
2. In any browser using the system proxy (Edge, Chrome), go to **http://mitm.it** — the mitmproxy landing page should load, proving traffic is being intercepted.
3. Visit **https://example.com** — it should load cleanly (cert chain will show "mitmproxy" as the issuer — that's expected).
4. Play Spotify for a bit. Right-click the tray icon → **View blocked requests** — you should see a count for `spotify` and entries in `blocked.log` like:

   ```
   2026-04-17T16:24:11 [spotify] GET https://spclient.wg.spotify.com/ads/v1/... <- spclient.wg.spotify.com/ads/
   ```

5. Toggle OFF. Visit mitm.it again — it should fail, proving the proxy was removed cleanly.

## Troubleshooting (Spotify specifically)

| Symptom                                  | Likely cause / fix                                                        |
|------------------------------------------|---------------------------------------------------------------------------|
| Ads still play (audio)                   | Audio ads share the music CDN — URL filtering can't distinguish them.     |
| "Spotify can't connect" / login fails    | Spotify may be doing cert pinning on its auth endpoints. Add those hosts to a `bypass` list by commenting out rules and restarting. |
| Nothing appears in `blocked.log`         | Confirm system proxy is set: `netsh winhttp show proxy`. Visit mitm.it.   |
| Browser shows cert warnings              | The CA install didn't succeed. Run **Install certificate** from the menu. |
| After uninstall, system can't reach the internet | Toggle OFF first! If you closed it mid-ON: open Settings → Network → Proxy → turn off Manual proxy. |

## Build a single `.exe`

```bat
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed ^
  --name "Interceptify" ^
  --manifest interceptify.manifest ^
  --uac-admin ^
  --add-data "filters;filters" ^
  --add-data "apps.json;." ^
  main.py
```

The `.exe` lands in `dist\Interceptify.exe`.

## Security note

Installing a local root CA is a **genuine security tradeoff**: any software running as your user on this machine could (in theory) read the mitmproxy private key from `%USERPROFILE%\.mitmproxy\` and MITM your traffic. Only run tools you trust.

To cleanly remove the CA later: `certutil -delstore ROOT mitmproxy` from an elevated prompt.

## License

[MIT](LICENSE)
