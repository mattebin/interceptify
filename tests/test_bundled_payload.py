"""
The built .exe must carry THIS commit's payload.

The .exe and the JavaScript it injects are two different artifacts that ship as
one release. The version string lives in the .exe; the ad blocking lives in the
payload. Nothing previously connected them, and the updater replaced only the
.exe - so "updated to 2.0.5" could mean "running 2.0.5 with 2.0.3's payload",
which is indistinguishable from a working install until an ad plays.

This opens the PyInstaller archive inside the built exe and compares the bundled
extensions/adblock.js against the one in the working tree.

It also checks the embedded manifest asks for `asInvoker`. A local build once
sat in dist/ requesting `requireAdministrator` because the .spec said
uac_admin=True while CI passed no --uac-admin: two build paths, one of which
produced an elevated binary that looked exactly like the release. The manifest
is inside the .exe, so it is the only place that answers the question about the
artifact itself rather than about the build command someone believes was used.

Run:  python tests/test_bundled_payload.py dist/Interceptify.exe
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Both halves of what gets injected. The config is not decoration: it carries
# every Spotify-build-specific selector, module id, gate-key pattern and URL
# regex, so a build whose bundled config is not this commit's ships a payload
# aimed at a different Spotify.
BUNDLED = {
    "extensions/adblock.js": ROOT / "extensions" / "adblock.js",
    "extensions/adblock.config.json": ROOT / "extensions" / "adblock.config.json",
}
PAYLOAD = BUNDLED["extensions/adblock.js"]


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def bundled_file(exe: Path, rel: str) -> bytes | None:
    """Pull a bundled data file out of the onefile archive.

    Raises rather than returning None on an unusable reader: a check that
    quietly opts out is the failure mode this whole exercise is about.
    """
    from PyInstaller.archive.readers import CArchiveReader

    reader = CArchiveReader(str(exe))
    wanted = [n for n in reader.toc if n.replace("\\", "/").endswith(rel)]
    if not wanted:
        return None
    return reader.extract(wanted[0])


# The .exe is the WHOLE application, not just the tray. It runs its own
# self-heal and registers its own scheduled tasks (`Interceptify.exe --selfheal`,
# `--install-tasks`). When it carried neither, a packaged install could only get
# autostart by pointing scheduled tasks at a source checkout - two deployments,
# two payloads, and an updater that moves only one of them forward. That is how
# stale code keeps re-patching Spotify after a successful update.
REQUIRED_MODULES = ("selfheal", "install_tasks", "spotify_patcher", "patch_lock", "websocket")


def bundled_modules(exe: Path) -> set[str]:
    """Top-level module names inside the onefile archive's PYZ."""
    import tempfile
    from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader

    reader = CArchiveReader(str(exe))
    pyz_name = next((n for n in reader.toc if n.lower().endswith(".pyz")), None)
    if pyz_name is None:
        raise RuntimeError("no PYZ archive inside the exe")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "bundle.pyz"
        p.write_bytes(reader.extract(pyz_name))
        return {n.split(".", 1)[0] for n in ZlibArchiveReader(str(p)).toc}


def embedded_manifest(exe: Path) -> str | None:
    """The RT_MANIFEST resource, read as a resource rather than guessed at.

    The first version of this scanned the whole binary for a
    requestedExecutionLevel string. That answers a different question: any copy
    of the text anywhere in 29 MB of bundled data would satisfy it, and a real
    manifest resource whose text it failed to anticipate would not. What decides
    whether Windows shows a UAC prompt is the RT_MANIFEST resource, so read that.

    Loaded with LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE: the
    file is mapped for its resources and no code in it is ever executed.
    """
    import ctypes
    from ctypes import wintypes

    LOAD_LIBRARY_AS_DATAFILE = 0x00000002
    LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020
    RT_MANIFEST = 24

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    k32.LoadLibraryExW.restype = wintypes.HMODULE
    k32.FindResourceW.argtypes = [wintypes.HMODULE, wintypes.LPCWSTR, wintypes.LPCWSTR]
    k32.FindResourceW.restype = wintypes.HANDLE
    k32.LoadResource.argtypes = [wintypes.HMODULE, wintypes.HANDLE]
    k32.LoadResource.restype = wintypes.HANDLE
    k32.LockResource.argtypes = [wintypes.HANDLE]
    k32.LockResource.restype = wintypes.LPVOID
    k32.SizeofResource.argtypes = [wintypes.HMODULE, wintypes.HANDLE]
    k32.SizeofResource.restype = wintypes.DWORD
    k32.FreeLibrary.argtypes = [wintypes.HMODULE]

    mod = k32.LoadLibraryExW(str(exe.resolve()), None,
                             LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)
    if not mod:
        raise OSError(f"could not map {exe} for resources (err {ctypes.get_last_error()})")
    try:
        for res_id in (1, 2, 3):          # 1 = exe, 2 = dll, 3 = other
            info = k32.FindResourceW(mod, wintypes.LPCWSTR(res_id), wintypes.LPCWSTR(RT_MANIFEST))
            if not info:
                continue
            size = k32.SizeofResource(mod, info)
            handle = k32.LoadResource(mod, info)
            ptr = k32.LockResource(handle)
            if not ptr or not size:
                continue
            return ctypes.string_at(ptr, size).decode("utf-8", "replace")
        return None
    finally:
        k32.FreeLibrary(mod)


def execution_level(exe: Path) -> str | None:
    """The requestedExecutionLevel Windows will actually honour."""
    import re
    xml = embedded_manifest(exe)
    if not xml:
        return None
    m = re.search(r"requestedExecutionLevel[^>]*\blevel\s*=\s*[\"']([A-Za-z]+)[\"']", xml)
    return m.group(1) if m else None


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("[FAIL] usage: test_bundled_payload.py <path to Interceptify.exe>")
        return 1
    exe = Path(argv[1])
    if not exe.is_file():
        print(f"[FAIL] {exe} does not exist")
        return 1

    level = execution_level(exe)
    if level is None:
        print("[FAIL] no requestedExecutionLevel found in the embedded manifest; "
              "the build must pass --manifest interceptify.manifest")
        return 1
    if level.lower() != "asinvoker":
        print(f"[FAIL] the exe requests {level!r}. Interceptify runs as the invoking user; "
              f"an elevated build is a privilege-escalation shape, not a capability.")
        return 1

    try:
        mods = bundled_modules(exe)
    except Exception as e:
        print(f"[FAIL] could not read the bundled modules: {e!r}")
        return 1
    missing = [m for m in REQUIRED_MODULES if m not in mods]
    if missing:
        print(f"[FAIL] the exe does not bundle {', '.join(missing)}. It cannot run its own "
              f"self-heal or own its own autostart, so a packaged install would have to "
              f"schedule a source checkout - and the updater never moves that forward.")
        return 1

    for rel, path in BUNDLED.items():
        ours = path.read_bytes()
        try:
            got = bundled_file(exe, rel)
        except Exception as e:
            print(f"[FAIL] could not read the PyInstaller archive: {e!r}")
            return 1
        if got is None:
            print(f"[FAIL] the built exe contains no {rel} (check --add-data / the spec)")
            return 1
        if sha(got) != sha(ours):
            print(f"[FAIL] bundled {rel} {sha(got)[:16]} != working tree {sha(ours)[:16]}")
            return 1
        print(f"[PASS] bundled {rel} matches the working tree "
              f"({sha(ours)[:16]}, {len(ours)} bytes)")
    print(f"[PASS] the exe requests {level} and bundles {', '.join(REQUIRED_MODULES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
