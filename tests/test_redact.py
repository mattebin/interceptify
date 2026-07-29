"""
The redactor must remove credentials AND leave diagnostics readable.

Both halves matter. Over-redaction is not the safe direction: a capture whose
`instreamSourceSignatures` and `adGateFallbackKeys` have been blanked is useless
for the job it was taken for, so people stop redacting rather than stop
capturing. Bare "key", "auth" and "sig" were in the sensitive list once and did
exactly that.

The reason this file exists at all: three captures from 2026-06-13 on this
machine each carried a full 482-character Spotify access_token in a URL query.
Not because the redactor could not handle that shape - it can, and case 1 proves
it - but because the files predated it being applied, and a comment in
selfheal.py described them as "redacted" anyway. A claim nothing checks is a
claim that drifts.

Run:  python tests/test_redact.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import redact  # noqa: E402

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"   :: {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


# The real token shape, truncated: Spotify's are ~482 chars of base64url.
TOKEN = "BQC9tF9aAgNvyk" + "x" * 400


def main() -> int:
    # ---- 1. the shape that actually leaked ------------------------------
    url = f"https://spclient.wg.spotify.com/ad-logic/v1/ads?access_token={TOKEN}&market=SE"
    out = redact.redact_structured(url)
    check("1. an access_token in a query string is removed", TOKEN not in out, out[:80])
    check("1b. ...and the endpoint is still identifiable",
          "spclient.wg.spotify.com" in out and "ad-logic" in out, out[:80])

    body = json.dumps({"access_token": TOKEN, "expires_in": 3600})
    out = redact.redact_structured(body)
    check("2. a token in a JSON body is removed", TOKEN not in out, out[:80])
    check("2b. ...and non-secret siblings survive", '"expires_in"' in out and "3600" in out, out)

    # ---- 3. short secrets are secrets too -------------------------------
    # Redaction used to rest on a 22-char opaque-run rule, so a 6-digit code or
    # a numeric user id passed straight through a function named "redact".
    out = redact.redact_structured(json.dumps({"session_id": "42", "device_id": "ab"}))
    check("3. a SHORT sensitive value is still redacted",
          '"42"' not in out and '"ab"' not in out, out)

    # ---- 4. the fields a capture is TAKEN for must survive ---------------
    diag = json.dumps({
        "instreamSourceSignatures": ["getInStreamAd", "inStreamApi"],
        "playerStateSignatures": ["is_paused"],
        "adGateFallbackKeys": ["ad_enabled"],
        "gateKeys": ["ad_enabled"],
        "adUrlSignals": ["/ad-logic/"],
    })
    out = redact.redact_structured(diag)
    check("4. diagnostic fields are NOT redacted (over-redaction kills the tool)",
          "getInStreamAd" in out and "ad_enabled" in out and "/ad-logic/" in out, out[:200])

    # ---- 5. credentials_in must discriminate BOTH ways -------------------
    check("5. credentials_in sees a live credential",
          redact.credentials_in(f"access_token={TOKEN}") == 1)
    check("5b. ...and does NOT count an already-redacted one",
          redact.credentials_in("access_token=<redacted>") == 0,
          "a redacted pair still matches the pattern; counting it made a clean "
          "file report as dirty forever")

    # ---- 6. redact_file: in place, verified, and still parseable ---------
    tmp = Path(tempfile.mkdtemp(prefix="interceptify-redact-"))
    cap = tmp / "capture_test.json"
    original = {"requests": [{"url": url, "method": "GET"},
                             {"url": "https://open.spotify.com/track/abc", "method": "GET"}],
                "note": "kept"}
    cap.write_text(json.dumps(original, indent=2), encoding="utf-8")
    before, after = redact.redact_file(cap)
    text = cap.read_text(encoding="utf-8")
    check("6. redact_file reports what it found and what remains",
          before >= 1 and after == 0, f"before={before} after={after}")
    check("6b. the token is gone from disk", TOKEN not in text)
    check("6c. the file is still valid JSON", json.loads(text)["note"] == "kept")

    before2, after2 = redact.redact_file(cap)
    check("6d. re-running is a no-op, not a second pass over placeholders",
          (before2, after2) == (0, 0), f"{before2},{after2}")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print("redaction: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
