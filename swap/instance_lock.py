"""Owner-only process lock for the single-writer swap ledger."""

import fcntl
import os
import stat


def acquire_instance_lock(store_path):
    """Return a held lock fd; the caller must retain it until process exit."""
    if not isinstance(store_path, str) or not store_path:
        raise RuntimeError("store must be a non-empty path before instance lock")
    parent = os.path.dirname(os.path.abspath(store_path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("platform lacks O_NOFOLLOW required for swapd lock")
    flags = os.O_RDWR | os.O_CREAT | nofollow | getattr(os, "O_CLOEXEC", 0)
    path = os.path.abspath(store_path) + ".lock"
    fd = os.open(path, flags, 0o600)
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) & 0o077
        ):
            raise RuntimeError("swapd instance lock is not an owner-only regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another swapd process already owns this ledger") from exc
        os.ftruncate(fd, 0)
        os.write(fd, ("%d\n" % os.getpid()).encode("ascii"))
        os.fsync(fd)
        return fd
    except Exception:
        os.close(fd)
        raise
