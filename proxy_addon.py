"""
mitmproxy addon + filter engine for HostsBlock Pro.

Filter rules live in ``filters/<appname>.txt``. The ``FilterEngine`` loads and
compiles them at startup; ``BlockerAddon`` hooks every HTTP request and returns
a synthetic 403 when a rule matches — the request never leaves the proxy.

To extend for another app:
    1. Drop a ``filters/<appname>.txt`` next to the existing ones.
    2. Add an entry for it in ``apps.json``.
    3. (Optional) Add a ``response()`` hook below for response-body rewriting,
       e.g. to strip inline ad JSON from a specific host's API responses.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from mitmproxy import http

log = logging.getLogger("hostsblock")


# ---------------------------------------------------------------------------
# Rule types
# ---------------------------------------------------------------------------

class Rule:
    """One compiled filter rule tagged with the app it came from."""

    __slots__ = ("app", "raw", "match")

    def __init__(self, app: str, raw: str, match):
        self.app = app
        self.raw = raw
        self.match = match  # callable(host: str, path_and_query: str, full_url: str) -> bool

    def __repr__(self) -> str:
        return f"<Rule {self.app}:{self.raw}>"


def _compile_rule(raw: str):
    """
    Turn one line of filter text into a match callable.

    Rule grammar:
      - "re:<pattern>"         full-URL regex match
      - "host.com/path/prefix" host match + path prefix match
      - "*/substring/*"        path substring (host-agnostic)
      - "host.com"             exact host match
    """
    s = raw.strip()

    # Full URL regex
    if s.startswith("re:"):
        pattern = re.compile(s[3:])
        return lambda host, path, url: bool(pattern.search(url))

    # Path-substring rule, host-agnostic: "*/foo/*"
    if s.startswith("*/") and s.endswith("/*"):
        needle = s[1:-1]  # keep surrounding slashes
        return lambda host, path, url: needle in path

    # host + path (e.g. "example.com/ads/")
    if "/" in s:
        host_part, path_part = s.split("/", 1)
        path_part = "/" + path_part
        host_part = host_part.lower()
        return lambda host, path, url: host == host_part and path.startswith(path_part)

    # Bare hostname (exact or wildcard subdomain match)
    host_part = s.lower()
    return lambda host, path, url: host == host_part or host.endswith("." + host_part)


# ---------------------------------------------------------------------------
# Filter engine
# ---------------------------------------------------------------------------

class FilterEngine:
    """Loads ``apps.json`` and the matching filter files, then matches requests."""

    def __init__(self, root: Path):
        self.root = root
        self.rules: list[Rule] = []
        self.apps_config: dict = {}
        self.reload()

    def reload(self) -> None:
        self.rules.clear()
        cfg_path = self.root / "apps.json"
        if not cfg_path.exists():
            log.warning("apps.json not found — no filters loaded")
            return
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        self.apps_config = cfg.get("apps", {})

        for app_name, app_cfg in self.apps_config.items():
            if not app_cfg.get("enabled", True):
                continue
            f = self.root / app_cfg["filter_file"]
            if not f.exists():
                log.warning("Filter file missing for %s: %s", app_name, f)
                continue
            for line in f.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                try:
                    self.rules.append(Rule(app_name, s, _compile_rule(s)))
                except re.error as e:
                    log.error("Bad regex in %s: %s (%s)", f, s, e)

        log.info("Loaded %d rules from %d apps", len(self.rules), len(self.apps_config))

    def match(self, host: str, path: str, url: str) -> Optional[Rule]:
        for r in self.rules:
            if r.match(host, path, url):
                return r
        return None


# ---------------------------------------------------------------------------
# mitmproxy addon
# ---------------------------------------------------------------------------

class BlockerAddon:
    """
    mitmproxy addon that blocks requests matching any loaded filter rule.

    Blocked requests are short-circuited with a 403 so the upstream server is
    never contacted. Each block is appended to ``blocked.log`` and tallied in
    an in-memory per-app counter.

    Also maintains a rolling buffer of *unblocked* requests (the last
    ``RECENT_WINDOW_SEC`` seconds) so the tray can ask "what just played?" —
    used by the learn-mode capture feature. See ``capture_candidates()``.
    """

    RECENT_WINDOW_SEC = 60  # how much history the rolling buffer keeps

    def __init__(self, root: Path):
        self.root = root
        self.engine = FilterEngine(root)
        self.log_path = root / "blocked.log"
        self.counts: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        # rolling buffer of (timestamp, method, host, path, url, content_type)
        self._recent: deque = deque(maxlen=2000)

    # mitmproxy hooks ------------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        host = (req.pretty_host or "").lower()
        path = req.path or "/"
        url = req.pretty_url

        rule = self.engine.match(host, path, url)
        if rule is None:
            # Track it for learn-mode capture
            self._remember(req.method, host, path, url, content_type=None)
            return

        flow.response = http.Response.make(
            403,
            b"Blocked by HostsBlock Pro\n",
            {"Content-Type": "text/plain"},
        )
        self._record(req.method, url, rule)

    def response(self, flow: http.HTTPFlow) -> None:
        """Attach response content-type to the rolling-buffer entry (if any)."""
        if flow.response is None:
            return
        ct = flow.response.headers.get("content-type", "")
        if not ct:
            return
        url = flow.request.pretty_url
        with self._lock:
            # Walk from newest backward — cheap since the window is bounded
            for i in range(len(self._recent) - 1, -1, -1):
                entry = self._recent[i]
                if entry[4] == url and entry[5] is None:
                    self._recent[i] = (*entry[:5], ct.lower())
                    break

    # Extension point: uncomment to rewrite response bodies for specific hosts.
    # def response(self, flow: http.HTTPFlow) -> None:
    #     if flow.request.pretty_host.endswith("some-app.com"):
    #         flow.response.text = flow.response.text.replace('"ad":', '"_blocked_ad":')

    # Helpers --------------------------------------------------------------

    def _record(self, method: str, url: str, rule: Rule) -> None:
        with self._lock:
            self.counts[rule.app] += 1
            try:
                with self.log_path.open("a", encoding="utf-8") as f:
                    f.write(
                        f"{datetime.now().isoformat(timespec='seconds')} "
                        f"[{rule.app}] {method} {url}  <-  {rule.raw}\n"
                    )
            except Exception as e:
                log.warning("Failed to write blocked.log: %s", e)

    def summary(self) -> str:
        if not self.counts:
            return "No requests blocked yet."
        return "\n".join(f"{app}: {n}" for app, n in sorted(self.counts.items()))

    # ---- Learn-mode: capture recent candidates ---------------------------

    def _remember(self, method: str, host: str, path: str, url: str, content_type: Optional[str]) -> None:
        with self._lock:
            self._recent.append((time.time(), method, host, path, url, content_type))

    def _recent_within(self, window_sec: int) -> list[tuple]:
        cutoff = time.time() - window_sec
        with self._lock:
            return [e for e in self._recent if e[0] >= cutoff]

    def capture_candidates(
        self,
        app: str = "spotify",
        window_sec: int = 30,
        suspect_hosts_extra: Optional[list[str]] = None,
    ) -> tuple[int, list[str], Path]:
        """
        Promote recent requests likely tied to an ad into a learned-filter file.

        Call this *right after* pausing an ad that just played. We look at the
        last ``window_sec`` seconds of non-blocked traffic and keep rules that:
          - have an audio/video/ad-ish content-type, OR
          - are on known ad-network hosts, OR
          - live under path segments that smell like ads (ads/, ad-logic/,
            promo/, sponsor/, tracking/, pixel, beacon, telemetry).

        The promoted rules are appended (deduped) to
        ``filters/<app>-learned.txt`` and the filter engine is reloaded so they
        take effect immediately. The file is the thing you commit to git.

        Returns (count_added, rules_added, path_to_file).
        """
        suspect_hosts = {
            "doubleclick.net", "googlesyndication.com", "googleadservices.com",
            "adnxs.com", "adsrvr.org", "adform.net", "moatads.com",
            "scorecardresearch.com", "adeventtracker.spotify.com",
            "pubads.g.doubleclick.net",
        }
        if suspect_hosts_extra:
            suspect_hosts.update(h.lower() for h in suspect_hosts_extra)

        path_needles = (
            "/ads/", "/ad-logic/", "/ad/", "/adserver",
            "/promo", "/sponsor", "/tracking/", "/telemetry",
            "/pixel", "/beacon", "/gabo-receiver",
        )
        ad_ct_needles = ("audio/", "video/", "application/x-mpegurl", "application/vnd.apple.mpegurl")

        candidates: list[str] = []
        seen_urls = set()

        for _, _method, host, path, url, ct in self._recent_within(window_sec):
            if url in seen_urls:
                continue
            seen_urls.add(url)

            host_match = any(host == h or host.endswith("." + h) for h in suspect_hosts)
            path_match = any(n in path for n in path_needles)
            ct_match = bool(ct) and any(n in ct for n in ad_ct_needles)

            if not (host_match or path_match or ct_match):
                continue

            # Build a rule: prefer host+path-prefix when a segment looks ad-ish,
            # otherwise fall back to the bare host.
            rule = self._derive_rule(host, path, path_needles, prefer_path=(path_match or ct_match))
            candidates.append(rule)

        # Dedup + drop anything already matched by the existing engine
        unique: list[str] = []
        for r in candidates:
            if r in unique:
                continue
            # Skip rules the engine already covers (avoid file bloat)
            test_host, test_path, test_url = self._rule_probe(r)
            if self.engine.match(test_host, test_path, test_url):
                continue
            unique.append(r)

        learned_path = self.root / "filters" / f"{app}-learned.txt"
        learned_path.parent.mkdir(parents=True, exist_ok=True)

        existing = set()
        if learned_path.exists():
            for ln in learned_path.read_text(encoding="utf-8").splitlines():
                s = ln.strip()
                if s and not s.startswith("#"):
                    existing.add(s)

        new_rules = [r for r in unique if r not in existing]
        if new_rules:
            header_needed = not learned_path.exists()
            with learned_path.open("a", encoding="utf-8") as f:
                if header_needed:
                    f.write(
                        f"# HostsBlock Pro — learned rules for {app}\n"
                        f"# Auto-captured from recent traffic. Review before committing.\n"
                    )
                f.write(f"\n# --- Captured {datetime.now().isoformat(timespec='seconds')} ---\n")
                for r in new_rules:
                    f.write(r + "\n")

            # Register the learned file in apps.json so the engine loads it next reload
            self._ensure_apps_json_entry(f"{app}-learned", f"filters/{app}-learned.txt")
            self.engine.reload()

        return len(new_rules), new_rules, learned_path

    @staticmethod
    def _derive_rule(host: str, path: str, path_needles, prefer_path: bool) -> str:
        if prefer_path:
            for n in path_needles:
                idx = path.find(n)
                if idx != -1:
                    prefix = path[: idx + len(n)]
                    return f"{host}{prefix}"
        return host

    @staticmethod
    def _rule_probe(rule: str) -> tuple[str, str, str]:
        """Synthesize a (host, path, url) from a rule so we can test it against the engine."""
        if rule.startswith("re:"):
            return ("example.invalid", "/", rule[3:])
        if rule.startswith("*/") and rule.endswith("/*"):
            return ("example.invalid", rule[1:-1], "https://example.invalid" + rule[1:-1])
        if "/" in rule:
            h, p = rule.split("/", 1)
            return (h.lower(), "/" + p, f"https://{h}/{p}")
        return (rule.lower(), "/", f"https://{rule}/")

    def _ensure_apps_json_entry(self, app_key: str, filter_rel_path: str) -> None:
        cfg_path = self.root / "apps.json"
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {"apps": {}}
        except Exception:
            cfg = {"apps": {}}
        cfg.setdefault("apps", {})
        if app_key not in cfg["apps"]:
            cfg["apps"][app_key] = {
                "filter_file": filter_rel_path,
                "enabled": True,
                "description": f"Learned rules captured via tray (learn mode).",
            }
            cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
