"""
Utility helpers to write JSON config files atomically and safely.
Provides write_atomic_json(path, data) which writes to a temporary file and
atomically replaces the target file. Also exposes a simple file lock helper
using an advisory lock when portalocker is available, otherwise falls back to
open+rename atomic write (best-effort).

This is intentionally small and dependency-free by default.
"""
from pathlib import Path
import json
import os
import tempfile
import time

try:
    import portalocker
    _HAS_PORTALOCKER = True
except Exception:
    _HAS_PORTALOCKER = False


def write_atomic_json(path, data, indent=2):
    """Write JSON to `path` atomically.

    - Writes to a temporary file in the same directory, fsyncs, then os.replace.
    - If portalocker is available, obtains an exclusive lock on the target file
      while writing to avoid concurrent writers.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Serialize JSON to bytes first
    json_bytes = json.dumps(data, indent=indent, ensure_ascii=False).encode('utf-8')

    # If portalocker available, use it to lock the path during write
    if _HAS_PORTALOCKER:
        # Create file if not exists so we can lock it
        with open(path, 'a+', encoding='utf-8') as lockf:
            try:
                portalocker.lock(lockf, portalocker.LockFlags.EXCLUSIVE)
                # Write to temp file in same dir
                with tempfile.NamedTemporaryFile(mode='wb', delete=False, dir=str(path.parent)) as tmpf:
                    tmpf.write(json_bytes)
                    tmpf.flush()
                    os.fsync(tmpf.fileno())
                    tmp_name = tmpf.name
                # Atomic replace
                os.replace(tmp_name, str(path))
            finally:
                try:
                    portalocker.unlock(lockf)
                except Exception:
                    pass
        return

    # Fallback: best-effort atomic write without advisory lock
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, dir=str(path.parent)) as tmpf:
        tmpf.write(json_bytes)
        tmpf.flush()
        os.fsync(tmpf.fileno())
        tmp_name = tmpf.name
    os.replace(tmp_name, str(path))


def read_json(path):
    """Read JSON file safely; returns parsed object or None if not found/parse error."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None
