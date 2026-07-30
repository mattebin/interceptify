"""
Strip identifying material out of anything a diagnostic tool writes to disk.

The CDP capture tools exist to answer "what did Spotify request during an ad
break". They were logging full URLs verbatim, and Spotify's URLs carry access
tokens, client ids, device ids and user ids in the query string. That turns a
debugging aid into a credential file sitting in the project directory, kept
forever, with no indication that it should be handled carefully.

What is kept is the part that answers the question - scheme, host, path shape -
and nothing that identifies the account or authorises anything.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

# Query parameters worth removing by name even in contexts where the rest of the
# query is kept. Matched case-insensitively, as substrings, because Spotify's
# naming is not consistent (access_token, accessToken, auth-token, ...).
# Distinctive enough to match as substrings without eating diagnostics. Bare
# "key", "auth" and "sig" USED to be in here and were actively harmful: "key"
# redacted `gateKeys` and `adGateFallbackKeys`, and "sig" redacted
# `adUrlSignals` and `instreamSourceSignatures` - the exact fields a capture is
# taken to inspect. Over-redaction is not free; it makes the diagnostic useless
# and pushes people towards capturing without it.
SENSITIVE_PARAMS = (
    "token", "secret", "password", "passwd", "credential", "signature",
    "api_key", "apikey", "access_key", "accesskey", "private_key", "privatekey",
    "client_id", "clientid", "device_id", "deviceid", "user_id", "userid",
    "session_id", "sessionid", "username", "email", "cookie",
    # Spotify's own session cookies. `sp_dc` is a long-lived credential that can
    # be exchanged for access tokens, so it is worth more than the access token
    # this file was originally written to catch, and it matched nothing.
    "sp_dc", "sp_key", "csrf",
)

# Long hex / base64-ish runs inside a path: source ids, track ids, device ids.
_OPAQUE = re.compile(r"\b[A-Za-z0-9_-]{22,}\b")
_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*")

_NAME_ALT = "|".join(re.escape(s) for s in SENSITIVE_PARAMS)

# A sensitive value inside an embedded JSON body: {"access_token": "abc"}.
# Length-independent on purpose. Redaction used to rest entirely on _OPAQUE,
# which only fires at 22+ characters, so a short token, a 6-digit code or a
# numeric user id passed straight through a function named "redact". The NAME is
# the evidence that a value is sensitive; its length is not.
_JSON_PAIR = re.compile(
    r'(?i)("(?:[A-Za-z0-9_.\-]*(?:%s)[A-Za-z0-9_.\-]*)"\s*:\s*)("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false)'
    % _NAME_ALT
)

# The same thing unquoted, as it appears in form bodies and stray query
# fragments that are not part of a parseable URL: access_token=abc&...
_KV_PAIR = re.compile(
    r"(?i)\b([A-Za-z0-9_.\-]*(?:%s)[A-Za-z0-9_.\-]*)=([^&\s\"']+)" % _NAME_ALT
)


_PLACEHOLDER = ("<redacted>", '"<redacted>"')

# An Authorization / Cookie header as it appears in a captured JSON body. The
# in-memory redactor has always handled these (redact_any consults _AUTH_NAME on
# the KEY), but the raw-text path did not - "authorization" is not a substring of
# anything in SENSITIVE_PARAMS. So a capture written before the redactor existed
# kept `"Authorization": "Bearer ..."` intact while the cleanup reported it
# clean: the narrower of two redactors was the one doing the remediation.
_AUTH_PAIR = re.compile(
    r'(?i)("(?:x-)?(?:proxy-|www-)?'
    r'(?:authorization|authenticate|cookie|set-cookie|api[-_]?key|auth[-_]?token)"\s*:\s*)'
    r'("(?:[^"\\]|\\.)*")'
)

# The same headers as RAW TEXT, which is how they appear in a netlog line or any
# capture that is not JSON. The file path only ever looked for the quoted JSON
# form, so `Authorization: Basic ...` sat in a diagnostic file untouched while
# credentials_in() reported zero - the cleanup declaring success over a header it
# could not see. Basic auth is a base64 username:password, so this is not a
# lesser leak than the bearer token this module was written to catch.
_AUTH_LINE = re.compile(
    r'(?im)^([ \t]*(?:x-)?(?:proxy-)?'
    r'(?:authorization|api[-_]?key|auth[-_]?token|cookie|set-cookie)[ \t]*:[ \t]*)'
    r'(?!<redacted>)(\S.*)$'
)

# A URL that still carries a query string. redact_url() drops queries wholesale
# for live capture, but retrospective cleanup left historical ones untouched, so
# the two paths disagreed about the same data.
_URL_QUERY = re.compile(r'(https?://[^\s"\'<>\\]*?)\?[^\s"\'<>\\]*')


def _scrub(s: str) -> tuple[str, int]:
    """Redact `s`, and report how many real credentials were removed.

    ONE pass produces both answers. They used to be computed separately -
    redact_structured() did the work, credentials_in() counted with a different
    and narrower set of patterns - so the checker could report a file clean while
    the cleaner had left credentials in it. A verifier that does not run the same
    logic as the thing it verifies is not checking that thing.
    """
    n = 0

    def bump(repl):
        def f(m):
            nonlocal n
            if m.lastindex and m.group(m.lastindex) in _PLACEHOLDER:
                return m.group(0)                    # already done, not a finding
            n += 1
            return repl(m)
        return f

    # URL queries FIRST, and the order matters. Running the pair passes first
    # rewrites `access_token=X` to `access_token=<redacted>` inside the URL, and
    # the query-stripper's character class then stops at the `<` - leaving a
    # `.../me<redacted>` stub behind. Same credentials removed either way, but
    # one of the two produces a file a human can still read.
    def strip_query(m):
        nonlocal n
        n += 1
        return m.group(1)
    s = _URL_QUERY.sub(strip_query, s)

    s = _AUTH_PAIR.sub(bump(lambda m: m.group(1) + '"<redacted>"'), s)
    s = _AUTH_LINE.sub(bump(lambda m: m.group(1) + "<redacted>"), s)
    s = _JSON_PAIR.sub(bump(lambda m: m.group(1) + '"<redacted>"'), s)
    s = _KV_PAIR.sub(bump(lambda m: m.group(1) + "=<redacted>"), s)

    def bearer(m):
        nonlocal n
        n += 1
        return "Bearer <redacted>"
    s = _BEARER.sub(bearer, s)
    return s, n


def redact_structured(s: str) -> str:
    """Mask sensitive values in JSON or key=value text, whatever their length."""
    return _scrub(s)[0]


def credentials_in(s: str) -> int:
    """How many credentials `s` still exposes an ACTUAL VALUE for.

    Used to decide whether a file needs cleaning and, more importantly, to check
    afterwards that cleaning it worked. "we ran the redactor" is not the same
    claim as "there is nothing left", and only the second one is worth acting on.

    Counting raw matches is not that check either: a redacted pair still matches
    its pattern, so `access_token=<redacted>` once counted as a live credential
    and a fully-cleaned file reported exactly as dirty as it started.
    """
    return _scrub(s)[1]


def redact_file(path) -> tuple[int, int]:
    """Redact a capture in place. Returns (found_before, found_after).

    These artifacts predate the redactor: three captures from 2026-06-13 on this
    machine each carry a full 482-character Spotify access_token in a URL query.
    They were never publishable (the capture globs are gitignored), but a
    credential sitting in a diagnostic file is a credential, and the file is only
    ever more likely to be shared than deleted.

    Rewrite through a temp file so an interrupted run cannot leave a truncated
    capture where a redacted one was meant to be.
    """
    import os
    import pathlib
    p = pathlib.Path(path)
    raw = p.read_text(encoding="utf-8", errors="replace")
    before = credentials_in(raw)
    if not before:
        return 0, 0
    cleaned = redact_structured(raw)
    tmp = p.with_suffix(p.suffix + ".redacting")
    tmp.write_text(cleaned, encoding="utf-8")
    os.replace(tmp, p)
    return before, credentials_in(cleaned)


def redact_url(url: str, keep_query: bool = False) -> str:
    """A URL safe to write to a log file.

    The query string is dropped entirely by default. It is where the credentials
    live, and no diagnostic here has ever needed its contents - only whether a
    request happened, to which host, against which endpoint.
    """
    if not url:
        return ""
    if url.startswith("data:"):
        return "data:[...]"
    if url.startswith("blob:"):
        return "blob:[...]"
    try:
        parts = urlsplit(url)
    except ValueError:
        return "[unparseable url]"

    path = _OPAQUE.sub("<id>", parts.path)
    query = ""
    if keep_query and parts.query:
        kept = []
        for pair in parts.query.split("&"):
            name = pair.split("=", 1)[0]
            low = name.lower()
            if any(s in low for s in SENSITIVE_PARAMS):
                kept.append(f"{name}=<redacted>")
            else:
                kept.append(_OPAQUE.sub("<id>", pair))
        query = "&".join(kept)
    # netloc keeps the host but never userinfo (user:pass@host).
    netloc = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, netloc, path, query, ""))


def redact_text(s: str, limit: int = 400) -> str:
    """A body/preview string safe to write, truncated to `limit`.

    Order matters: the name-driven pass runs BEFORE the length-driven one, so a
    short `"access_token": "abc"` is caught by its key rather than slipping past
    a 22-character threshold it was never going to meet.
    """
    if not s:
        return ""
    s = _BEARER.sub("Bearer <redacted>", s)
    s = redact_structured(s)
    s = _OPAQUE.sub("<id>", s)
    return s[:limit]


_SENSITIVE_NAME = re.compile(r"(?i)%s" % _NAME_ALT)
# Authorization carries a credential whatever the scheme says - Basic, Bearer,
# Digest, or something bespoke. Keying off "Bearer" alone left `Basic <base64>`
# in the clear.
_AUTH_NAME = re.compile(r"(?i)^(authorization|proxy-authorization|www-authenticate|cookie|set-cookie)$")


# Field names WE emit that happen to contain a sensitive-looking substring. They
# are configuration and diagnostics, never credentials, and they are the fields a
# capture is usually taken to inspect - so name them once here rather than
# loosening the rule for everything.
NEVER_REDACT = frozenset({
    "instreamsourcesignatures",   # module source-scan needles
    "playerstatesignatures",
})


def is_sensitive_key(name: str) -> bool:
    if not name:
        return False
    if name.strip().lower() in NEVER_REDACT:
        return False
    return bool(_AUTH_NAME.match(name) or _SENSITIVE_NAME.search(name))


def redact_any(value, limit: int = 4000, key: str | None = None):
    """Redact every string in a nested structure, whatever shape it is.

    The KEY a value sits under travels with it. Without that, redaction could
    only ever see what a value looks like, so `{"headers": {"Authorization":
    "Basic c2hvcnQ="}}` and a short nested `access_token` came out untouched:
    the JSON-pair pattern matches text, and by the time recursion reached the
    leaf the name that made it sensitive had been left behind in the parent.

    URL-shaped strings still go through redact_url; everything else through
    redact_text.
    """
    if isinstance(value, dict):
        return {k: redact_any(v, limit, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_any(v, limit, key=key) for v in value]
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        if key and is_sensitive_key(key):
            return "<redacted>"
    if isinstance(value, str):
        if "://" in value or value.startswith(("blob:", "data:")):
            return redact_url(value)
        return redact_text(value, limit)
    return value
