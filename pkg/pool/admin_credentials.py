#!/usr/bin/env python3
"""Set/rotate the panel-only password interactively as the admin service user.
Never accepts a wallet passphrase, password argv, environment secret or default.
"""

import argparse
import getpass
import os
from pathlib import Path
import stat
import sys

from pool.admin import password_record
from pool.journal import atomic
from pool.protocol import encode, require


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', required=True)
    args = parser.parse_args()
    path = Path(args.file)
    require(path.is_absolute() and '..' not in path.parts, 'absolute credential path required')
    for parent in (*path.parents, path):
        require(not parent.is_symlink(), 'linked credential path refused')
    metadata = path.parent.stat()
    require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and metadata.st_mode & 0o077 == 0,
        'run as the owner of the private admin directory',
    )
    require(sys.stdin.isatty(), 'interactive local terminal required')
    first = getpass.getpass('New operator-only passphrase (16+ characters): ')
    require(first == getpass.getpass('Repeat operator passphrase: '), 'passphrases differ')
    atomic(path, encode(password_record(first)) + b'\n')
    print(
        'Operator credential saved. Existing sessions are invalidated. No pool policy or wallet key changed.'
    )


if __name__ == '__main__':
    main()
