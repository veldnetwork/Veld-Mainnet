"""Bounded, no-follow reads for private Linux service configuration.

The owner/group may grant read access to another service role, but public reads
and group/other writes must not make credentials replaceable by the gateway.
Windows worker credentials use the native secure-channel DACL implementation.
"""
import os
import stat
from .protocol import require


def read_private(path, maximum):
    require(type(maximum) is int and 0 < maximum <= 4*1024*1024, 'private file bound')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), 'private file must be regular')
        if os.name != 'nt':
            require(metadata.st_mode & 0o027 == 0, 'unsafe private file permissions')
        require(metadata.st_size <= maximum, 'private file too large')
        chunks=[]; size=0
        while size <= maximum:
            value=os.read(descriptor, maximum + 1 - size)
            if not value:break
            chunks.append(value);size+=len(value)
        require(size <= maximum, 'private file too large')
        return b''.join(chunks)
    finally:
        os.close(descriptor)
