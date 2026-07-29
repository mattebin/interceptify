"""
The git tag, APP_VERSION and the manifest must agree.

A release is identified by three numbers written in three places by hand. When
they disagree, the self-updater is the thing that suffers: it compares the tag
from the GitHub release against the running APP_VERSION to decide whether an
update exists. Tag ahead of APP_VERSION and every user updates forever; tag
behind and nobody is ever offered the fix.

Run:  python tests/test_version_consistency.py v2.0.5
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def app_version() -> str | None:
    # Parsed, not imported: importing main.py pulls in the tray's GUI
    # dependencies, which a version check has no business requiring.
    m = re.search(r'^APP_VERSION\s*=\s*"([^"]+)"', (ROOT / "main.py").read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else None


def manifest_version() -> str | None:
    m = re.search(r'<assemblyIdentity[^>]*\bversion="([^"]+)"',
                  (ROOT / "interceptify.manifest").read_text(encoding="utf-8"))
    return m.group(1) if m else None


def version_resource() -> str | None:
    """FileVersion from the Windows version resource the build embeds."""
    p = ROOT / "version_info.txt"
    if not p.is_file():
        return None
    m = re.search(r'StringStruct\("FileVersion",\s*"([^"]+)"', p.read_text(encoding="utf-8"))
    return m.group(1) if m else None


def main(argv: list[str]) -> int:
    tag = (argv[1] if len(argv) > 1 else "").strip()
    app = app_version()
    man = manifest_version()
    res = version_resource()
    failures = []

    if app is None:
        failures.append("APP_VERSION not found in main.py")
    if man is None:
        failures.append("assemblyIdentity version not found in interceptify.manifest")
    if res is None:
        failures.append("FileVersion not found in version_info.txt")

    if tag:
        want = tag[1:] if tag.startswith("v") else tag
        if app and want != app:
            failures.append(f"tag {tag!r} implies version {want!r} but APP_VERSION is {app!r}")
        # The manifest carries a 4-part Windows version; compare the leading
        # parts it shares with APP_VERSION rather than demanding an exact match.
        for label, value in (("manifest", man), ("version_info.txt", res)):
            if value and app:
                head = ".".join(value.split(".")[:len(app.split("."))])
                if head != app:
                    failures.append(f"{label} version {value!r} does not start with "
                                    f"APP_VERSION {app!r}")

    for f in failures:
        print(f"[FAIL] {f}")
    if failures:
        return 1
    print(f"[PASS] tag={tag or '(none)'} APP_VERSION={app} manifest={man} resource={res}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
