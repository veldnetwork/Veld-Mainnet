#!/usr/bin/env python3
"""Verify a source-only Python payload without generating unpinned bytecode."""
import argparse
from pathlib import Path


def verify(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Python package must be a real directory')
    count = 0
    for path in root.rglob('*'):
        if path.is_symlink() or path.name == '__pycache__' or path.suffix == '.pyc':
            raise ValueError('Python package contains an unpinned execution path')
        if path.suffix == '.py':
            if not path.is_file():
                raise ValueError('Python source must be a regular file')
            compile(path.read_bytes(), str(path), 'exec')
            count += 1
    if not count:
        raise ValueError('Python package has no source')
    return count


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(f'PASS {verify(args.directory)} source-only Python modules')
