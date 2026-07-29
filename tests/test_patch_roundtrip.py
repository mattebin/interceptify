"""
Patch and unpatch a synthetic xpui.spa, and prove both directions exactly.

The patcher is the one component whose failure is silent by nature: it rewrites
a ZIP that some other program opens later, so a bad patch shows up as "Spotify
won't start" or, worse, "Spotify starts and blocks nothing". Neither surfaces
here. This drives the real functions against a throwaway Spotify tree.

What it asserts, and why each one has been wrong at some point:

  1. patch() reports success                  - it once returned True after
                                                writing a payload it could not
                                                read back
  2. the marker lands in index.html           - the marker is what is_patched()
                                                reads
  3. the INLINE payload hashes to our file    - the integrity check used to hash
                                                a spare copy in the archive that
                                                Spotify never loads
  4. no stray members are added               - that spare copy is gone
  5. every other archive member is untouched  - a rewrite must not perturb the
                                                rest of Spotify's UI
  6. unpatch() restores byte-for-byte         - the backup is the user's undo
  7. unpatch() refuses to roll a NEWER Spotify
     back onto an older backup                - restoring blindly downgrades the
                                                UI after a Spotify update
  8. a backup taken from an already-patched
     client is reconstructed clean            - the 2026-07-16 shape, baked into
                                                the one file that is supposed to
                                                be the way back
  9. a patch that fails verification leaves
     xpui.spa untouched                       - verification ran AFTER the live
                                                archive had been replaced, so a
                                                bad rewrite was installed first
                                                and reported second
 10. shipped defaults and local overrides
     merge with local winning                 - one combined file meant a release
                                                could never correct a
                                                build-volatile key on an install
                                                that already had it

Run:  python tests/test_patch_roundtrip.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    print(f"[{'PASS' if cond else 'FAIL'}] {label}" + (f"   :: {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


def build_fake_xpui(path: Path, marker_text: str = "ORIGINAL") -> dict[str, bytes]:
    """A minimal stand-in for Spotify's UI bundle."""
    members = {
        "index.html": f"<html><body><div>{marker_text}</div></body></html>".encode(),
        "xpui.js": b"console.log('spotify ui');",
        "vendor~xpui.css": b".a{color:red}",
        "images/logo.svg": b"<svg/>",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return members


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="interceptify-roundtrip-"))
    # spotify_xpui_path() derives from APPDATA, so pointing APPDATA at a temp
    # tree is enough to exercise the real code against a disposable Spotify.
    os.environ["APPDATA"] = str(tmp)

    import spotify_patcher  # imported AFTER APPDATA is set

    xpui = spotify_patcher.spotify_xpui_path()
    original = build_fake_xpui(xpui)
    pristine_bytes = xpui.read_bytes()

    ok, msg = spotify_patcher.patch(show_badge=True, debug_capture=False)
    check("1. patch() succeeded", ok, msg)
    if not ok:
        return 1

    with zipfile.ZipFile(xpui) as z:
        names = set(z.namelist())
        html = z.read("index.html").decode("utf-8")

    check("2. marker present in index.html", spotify_patcher.MARKER in html)
    check("2b. is_patched() agrees", spotify_patcher.is_patched())

    live = spotify_patcher.inline_payload_sha()
    ours = spotify_patcher.our_payload_sha()
    check("3. the INLINE payload is exactly the payload we ship", live == ours,
          f"live={live} ours={ours}")

    check("4. no extra archive members were added", names == set(original),
          f"unexpected: {sorted(names - set(original))}")

    with zipfile.ZipFile(xpui) as z:
        untouched = all(z.read(n) == original[n] for n in original if n != "index.html")
    check("5. every non-index member is byte-identical", untouched)

    ok, msg = spotify_patcher.unpatch()
    check("6. unpatch() succeeded", ok, msg)
    check("6b. xpui.spa restored byte-for-byte", xpui.read_bytes() == pristine_bytes,
          f"{hashlib.sha256(xpui.read_bytes()).hexdigest()[:16]} vs "
          f"{hashlib.sha256(pristine_bytes).hexdigest()[:16]}")
    check("6c. is_patched() is False again", not spotify_patcher.is_patched())

    # A Spotify update replaces xpui.spa with a NEW pristine archive while our
    # backup still holds the OLD one. Restoring then is a downgrade.
    spotify_patcher.patch(show_badge=True, debug_capture=False)
    build_fake_xpui(xpui, marker_text="NEWER SPOTIFY")     # update wipes the patch
    newer = xpui.read_bytes()
    ok, msg = spotify_patcher.unpatch()
    check("7. unpatch() does NOT roll a newer Spotify back to the old backup",
          xpui.read_bytes() == newer, f"ok={ok} msg={msg}")

    # 8. Patching an ALREADY-patched client must not enshrine that patch as the
    # pristine backup. This is the 2026-07-16 shape: an older build had patched,
    # a newer one backed up what it found, and "restore original" then restored
    # the old payload forever.
    tmp2 = Path(tempfile.mkdtemp(prefix="interceptify-poison-"))
    os.environ["APPDATA"] = str(tmp2)
    import importlib
    importlib.reload(spotify_patcher)
    xpui2 = spotify_patcher.spotify_xpui_path()
    build_fake_xpui(xpui2)
    spotify_patcher.patch(show_badge=True, debug_capture=False)   # first build patches
    backup2 = xpui2.with_suffix(xpui2.suffix + spotify_patcher.BACKUP_SUFFIX)
    backup2.unlink()                                              # ...and its backup is lost
    spotify_patcher.patch(show_badge=True, debug_capture=False)   # second build patches
    with zipfile.ZipFile(backup2) as z:
        backup_html = z.read("index.html").decode("utf-8")
    check("8. a backup taken from an already-patched client is reconstructed clean",
          spotify_patcher.MARKER not in backup_html)
    ok, msg = spotify_patcher.unpatch()
    check("8b. unpatch then really removes the patch", ok and not spotify_patcher.is_patched(), msg)

    # 9. A patch that fails verification must leave Spotify EXACTLY as it was.
    # It used to replace xpui.spa first and check afterwards, so a bad rewrite
    # was installed and then reported as a failure - the caller saw False while
    # the user was left running the broken archive, with no rollback.
    build_fake_xpui(xpui2)
    for stale in (xpui2.with_suffix(xpui2.suffix + spotify_patcher.BACKUP_SUFFIX),):
        if stale.exists():
            stale.unlink()
    before = xpui2.read_bytes()
    real_sha = spotify_patcher.our_payload_sha
    spotify_patcher.our_payload_sha = lambda: "0" * 64      # nothing can ever match this
    try:
        ok, msg = spotify_patcher.patch(show_badge=True, debug_capture=False)
    finally:
        spotify_patcher.our_payload_sha = real_sha
    check("9. a patch that fails verification reports failure", not ok, msg)
    check("9b. ...and Spotify's archive is byte-for-byte untouched",
          xpui2.read_bytes() == before,
          f"{hashlib.sha256(xpui2.read_bytes()).hexdigest()[:16]} vs "
          f"{hashlib.sha256(before).hexdigest()[:16]}")
    check("9c. ...and it is not left marked as patched", not spotify_patcher.is_patched())

    # 10. Shipped defaults and local overrides are separate files, merged with
    # local winning. Before the split, the sync preserved every existing config
    # value forever, so a release that fixed a build-volatile key could never
    # reach anyone who already had the file.
    ext = ROOT / "extensions"
    shipped = json.loads((ext / "adblock.config.json").read_text(encoding="utf-8"))
    some_key = "instreamModuleFallbackId"
    local_path = ext / "adblock.config.local.json"
    saved_local = local_path.read_text(encoding="utf-8") if local_path.exists() else None
    try:
        local_path.write_text(json.dumps({some_key: 999999, "_note": "test"}), encoding="utf-8")
        merged = spotify_patcher.load_adblock_config()
        check("10. a local override beats the shipped default",
              merged.get(some_key) == 999999, f"got {merged.get(some_key)!r}")
        check("10b. shipped keys the local file does not mention still come through",
              merged.get("tickMs") == shipped.get("tickMs"))
        check("10c. underscore notes never reach the page",
              not any(k.startswith("_") for k in merged), f"{sorted(merged)[:3]}")
    finally:
        if saved_local is None:
            local_path.unlink(missing_ok=True)
        else:
            local_path.write_text(saved_local, encoding="utf-8")

    # 11. Two stacked injections must be refused. A marker test cannot see this:
    # the page would run two payloads, both installing hooks, and every presence
    # check would still say yes. It is what a re-patch of an already-patched
    # client produces the moment the strip step regresses.
    os.environ["APPDATA"] = str(tmp2)
    importlib.reload(spotify_patcher)
    xpui3 = spotify_patcher.spotify_xpui_path()
    build_fake_xpui(xpui3)
    for stale in (xpui3.with_suffix(xpui3.suffix + spotify_patcher.BACKUP_SUFFIX),):
        stale.unlink(missing_ok=True)
    spotify_patcher.patch(show_badge=True, debug_capture=False)
    with zipfile.ZipFile(xpui3) as z:
        once = z.read("index.html").decode("utf-8")
    doubled = once.replace("</body>", "", 1) + once[once.find(spotify_patcher.MARKER):]
    dbl = Path(tempfile.mkdtemp(prefix="interceptify-double-")) / "xpui.spa"
    with zipfile.ZipFile(xpui3) as zin, zipfile.ZipFile(dbl, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            zout.writestr(info, doubled.encode("utf-8") if info.filename == "index.html"
                          else zin.read(info.filename))
    why = spotify_patcher.verify_patched_archive(dbl)
    check("11. a doubly-injected archive is refused", why is not None and "exactly one" in why,
          f"why={why!r}")

    # 12. A backup that changed since we wrote it must not be restored blindly.
    backup3 = xpui3.with_suffix(xpui3.suffix + spotify_patcher.BACKUP_SUFFIX)
    check("12. a freshly written backup verifies",
          spotify_patcher.backup_problem(xpui3, backup3) is None,
          str(spotify_patcher.backup_problem(xpui3, backup3)))
    backup3.write_bytes(backup3.read_bytes() + b"tampered")
    check("12b. ...a tampered backup is detected",
          "changed" in (spotify_patcher.backup_problem(xpui3, backup3) or ""))
    ok, msg = spotify_patcher.unpatch()
    check("12c. ...and unpatch refuses to restore it", not ok and "Refusing to restore" in msg, msg)

    # ---------------------------------------------------------------------
    # 13. THE INJECTED CONFIG IS THE ONE THAT COUNTS.
    #
    # The config reaches Spotify only at patch time, so editing a config FILE
    # changes nothing about the running client until a re-patch. Nothing
    # measured that: the fingerprint compared payload hashes only. Patch with
    # config A, edit the sidecar to config B, and every check still reported
    # healthy while Spotify kept running A - indefinitely.
    #
    # That matters because a config edit is the DOCUMENTED way to fix a Spotify
    # rebuild without cutting a release. A fix that silently never applies is
    # worse than no fix: it reads as tried-and-didn't-work.
    # ---------------------------------------------------------------------
    tmp4 = Path(tempfile.mkdtemp(prefix="interceptify-cfgident-"))
    os.environ["APPDATA"] = str(tmp4)
    importlib.reload(spotify_patcher)
    xpui4 = spotify_patcher.spotify_xpui_path()
    build_fake_xpui(xpui4)
    saved_local = local_path.read_text(encoding="utf-8") if local_path.exists() else None
    try:
        ok, msg = spotify_patcher.patch(show_badge=True, debug_capture=False)
        check("13. patch with config A succeeded", ok, msg)
        injected = spotify_patcher.inline_config_sha_of(xpui4)
        check("13b. the injected config parses back out of the archive",
              injected is not None)
        check("13c. ...and it is exactly the config we meant to inject",
              injected == spotify_patcher.effective_config_sha(),
              f"injected={injected} effective={spotify_patcher.effective_config_sha()}")

        # Now change ONLY the sidecar - the exact silent-failure Codex reproduced.
        local_path.write_text(json.dumps({"primaryAdSlot": "audio-stream"}), encoding="utf-8")
        importlib.reload(spotify_patcher)
        still = spotify_patcher.inline_config_sha_of(xpui4)
        check("13d. a sidecar edit does NOT change what Spotify is running",
              still == injected, "the fixture is wrong if these differ")
        check("13e. (THE BUG) and that difference is now DETECTED, not silent",
              still != spotify_patcher.effective_config_sha(),
              "live config still compares equal to the effective config")

        # A re-patch is what actually applies it.
        ok, msg = spotify_patcher.patch(show_badge=True, debug_capture=False)
        check("13f. a re-patch carries the change into the archive", ok, msg)
        check("13g. ...and the live config now matches again",
              spotify_patcher.inline_config_sha_of(xpui4)
              == spotify_patcher.effective_config_sha())
    finally:
        if saved_local is None:
            local_path.unlink(missing_ok=True)
        else:
            local_path.write_text(saved_local, encoding="utf-8")
        importlib.reload(spotify_patcher)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED: " + "; ".join(FAILURES))
        return 1
    print("patch/unpatch round-trip: ALL PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
