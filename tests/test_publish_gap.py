"""The fix being merged and the fix being downloadable are different facts.

Between 2026-07-29 and 2026-08-05 an expression in the release workflow's
`permissions:` block made the file unparseable. Every tag push failed at startup
with no jobs and no log, so no release was built. APP_VERSION said 2.0.5 while
GitHub's latest release said 2.0.4 for a week, and nothing anywhere noticed:

  * test_version_consistency compares the tag being built against APP_VERSION,
    but it runs INSIDE ci - a workflow that never starts never runs it;
  * the tray's update poll asks `is_newer(published, APP_VERSION)`, which is
    False when the source is AHEAD. Source-ahead-of-published and up-to-date
    return the same answer and take the same silent branch.

`published_version_gap()` is the check that closes that. This is its test.

No network: every case stubs the release lookup, so a CI runner without egress
(or a rate limit) cannot make this flaky.

Run:  python tests/test_publish_gap.py
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import selfheal          # noqa: E402
import self_updater      # noqa: E402

results: list[tuple[str, bool, str]] = []


def check(label: str, passed: bool, detail: str = "") -> None:
    results.append((label, passed, detail))


def with_release(tag: str | None):
    """A lookup that returns a release with this tag (or None)."""
    if tag is None:
        return lambda: None
    return lambda: types.SimpleNamespace(
        tag=tag, exe_asset_url="https://example/x.exe",
        exe_asset_size=1, exe_asset_sha256="0" * 64)


def raises(exc: Exception):
    def _boom():
        raise exc
    return _boom


def run_case(stub, app_version: str = "2.0.5") -> dict:
    real_lookup = self_updater.get_latest_release
    real_app = sys.modules.get("main")
    self_updater.get_latest_release = stub
    # published_version_gap imports APP_VERSION from main; stub the module so
    # the test does not depend on whatever the tree currently says.
    fake_main = types.ModuleType("main")
    fake_main.APP_VERSION = app_version
    sys.modules["main"] = fake_main
    try:
        return selfheal.published_version_gap()
    finally:
        self_updater.get_latest_release = real_lookup
        if real_app is not None:
            sys.modules["main"] = real_app
        else:
            sys.modules.pop("main", None)


def main() -> int:
    # THE BUG. This is the exact state the repo was in for a week.
    got = run_case(with_release("v2.0.4"), app_version="2.0.5")
    check("the real 2026-08-05 gap (app 2.0.5, published v2.0.4) is reported",
          got["status"] == "unpublished", str(got))
    check("...and it names both versions so the message is actionable",
          got["app"] == "2.0.5" and got["published"] == "v2.0.4", str(got))

    # Shipped: no alarm.
    check("a published version is ok",
          run_case(with_release("v2.0.5"))["status"] == "ok")

    # A user running behind the latest release is the updater's job, not this
    # check's. It must stay quiet rather than double-report.
    check("running behind the latest release is ok, not a gap",
          run_case(with_release("v2.0.6"))["status"] == "ok")

    # Advisory means advisory. Offline, rate-limited, or a repo with no releases
    # must read as UNKNOWN - never as a gap (false alarm) and never as ok (the
    # silent branch that hid this in the first place).
    for label, stub in (
        ("network failure", raises(OSError("no route to host"))),
        ("rate limited", raises(RuntimeError("403 rate limit exceeded"))),
        ("no releases published yet", with_release(None)),
    ):
        st = run_case(stub)["status"]
        check(f"{label} reads as unknown, not a gap and not ok", st == "unknown", st)

    # A malformed tag must not crash a self-heal run.
    st = run_case(with_release("not-a-version"))["status"]
    check("an unparseable tag degrades safely", st in ("ok", "unknown", "unpublished"), st)

    width = max(len(r[0]) for r in results)
    failed = 0
    print("\n=== publish-gap check ===\n")
    for label, passed, detail in results:
        if not passed:
            failed += 1
        line = f"[{'PASS' if passed else 'FAIL'}] {label.ljust(width)}"
        print(f"{line}   :: {detail}" if detail and not passed else line)
    print(f"\n{len(results) - failed}/{len(results)} assertions passed.")
    if failed:
        print(f"{failed} FAILED.")
        return 1
    print("publish-gap: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
