"""
One writer at a time for Spotify's xpui.spa.

Four things patch that file: the tray app and three scheduled self-heal runs.
They all kill Spotify, rebuild the archive through the same fixed temp path
(``xpui.spa.tmp``) and rename it into place. Two of them overlapping does not
merely race on the result - one process can rename the temp file out from under
the other's ZIP writer, so the loser produces a truncated or half-written
archive and Spotify refuses to start.

A Windows named mutex is the right primitive here rather than a lock file: the
kernel releases it when the owning process dies, so a crashed or force-killed
patcher cannot leave a stale lock that blocks every future run. A lock file
needs staleness heuristics, and a heuristic that guesses wrong either deadlocks
the app forever or defeats the lock.

The lock fails CLOSED: if the mutex cannot be created at all, ``exclusive()``
yields False and the caller must not patch. Proceeding unserialised would give
back exactly the corruption the lock exists to prevent, while still reading like
the lock was held.

Usage:
    with patch_lock.exclusive(timeout=30) as got:
        if not got:
            return False, "Another Interceptify process is patching right now."
        ...
"""

from __future__ import annotations

import ctypes
import logging
from contextlib import contextmanager
from ctypes import wintypes

log = logging.getLogger("interceptify")

# "Local\" scopes the mutex to the current login session, which is the correct
# boundary: the thing being protected is this user's Spotify install. "Global\"
# would need privileges we deliberately no longer request.
MUTEX_NAME = r"Local\InterceptifyXpuiPatch"

# A SECOND, coarser lock covering an entire self-heal run. The patch mutex only
# spans the archive rewrite, which left everything around it - killing and
# relaunching Spotify, harvesting incidents, writing state, verifying - free to
# interleave between the logon, 08:00 and 21:00 tasks. Two overlapping runs can
# each kill the other's Spotify, and both write the state file.
RUN_MUTEX_NAME = r"Local\InterceptifySelfHealRun"

WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
_k32.CreateMutexW.restype = wintypes.HANDLE
_k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_k32.WaitForSingleObject.restype = wintypes.DWORD
_k32.ReleaseMutex.argtypes = [wintypes.HANDLE]
_k32.ReleaseMutex.restype = wintypes.BOOL
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CloseHandle.restype = wintypes.BOOL


@contextmanager
def _named(name: str, timeout: float, what: str):
    """Hold a named mutex for the block. Yields True if acquired.

    Yields False rather than raising on timeout, so callers report a useful
    message instead of a traceback; a contended lock is a normal condition here,
    not an error.
    """
    handle = _k32.CreateMutexW(None, False, name)
    if not handle:
        # Fail CLOSED. This used to proceed unserialised with a warning, which
        # inverts the point of the lock: the case it exists to prevent is two
        # patchers rewriting xpui.spa at once, and that is a corrupt Spotify, not
        # a missed opportunity. A warning in a log nobody reads is not a
        # substitute for the guarantee the caller thinks it has.
        log.error("%s lock unavailable (err %s); refusing to proceed unserialised",
                  what, ctypes.get_last_error())
        yield False
        return

    ms = 0xFFFFFFFF if timeout is None else int(max(0.0, timeout) * 1000)
    rc = _k32.WaitForSingleObject(handle, ms)
    # WAIT_ABANDONED means the previous owner died holding it. The lock is ours
    # and the file may be mid-rewrite, which is exactly when re-patching from the
    # pristine backup is the right move - so treat it as acquired, but say so.
    acquired = rc in (WAIT_OBJECT_0, WAIT_ABANDONED)
    if rc == WAIT_ABANDONED:
        log.warning("%s lock was abandoned by a dead process", what)
    try:
        yield acquired
    finally:
        if acquired:
            _k32.ReleaseMutex(handle)
        _k32.CloseHandle(handle)


@contextmanager
def exclusive(timeout: float = 30.0):
    """Serialise the xpui.spa rewrite itself."""
    with _named(MUTEX_NAME, timeout, "patch") as ok:
        yield ok


@contextmanager
def run_exclusive(timeout: float = 5.0):
    """Serialise an ENTIRE self-heal run.

    The patch mutex only spans the archive rewrite. Killing and relaunching
    Spotify, harvesting incidents, writing state and verifying all sat outside
    it, so the logon, 08:00 and 21:00 tasks could interleave: two runs each
    killing the other's Spotify and both writing the state file.

    Short timeout on purpose. An overlapping scheduled run should step aside and
    let the one already working finish, not queue behind it and repeat
    everything.
    """
    with _named(RUN_MUTEX_NAME, timeout, "self-heal run") as ok:
        yield ok
