"""Run against the real native helper; no mocked PoW or alternate hash path."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

from pool.native import Native
from pool.protocol import Busy

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',required=True)
    args=parser.parse_args()
    fixture=Path(__file__).resolve().parents[1]/'tests/fixtures/veldhash-3.0.9-vectors.txt'
    height,header,expected=fixture.read_text().splitlines()[0].split()
    raw=bytes.fromhex(header)
    identity=hashlib.sha256(hashlib.sha256(raw[:80]+bytes(8)).digest()).hexdigest()
    with tempfile.TemporaryFile(mode='w+') as log:
        native=Native(args.binary,log)
        try:
            for restart in range(3):
                assert native.hash(raw,int(height))==(expected,identity)
                native.process.kill();native.process.wait(timeout=5)
            try:native.hash(raw,int(height))
            except Busy:pass
            else:raise AssertionError('unbounded restart loop')
        finally:native.close()
    result=subprocess.run([args.binary],input='x'*10000+'\n',text=True,capture_output=True,timeout=10)
    assert result.returncode==2 and len(result.stdout)<1024
    result=subprocess.run([args.binary],input='scan 0 '+header+' '+'f'*64+' ffffffffffffffff 2\n',text=True,capture_output=True,timeout=10)
    assert result.stdout=='ERROR nonce range\n'
    print('PASS real VeldHash before/after two verifier crashes, bounded restarts, oversized framing, nonce overflow')

if __name__=='__main__':main()
