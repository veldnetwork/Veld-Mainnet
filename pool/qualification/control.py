"""Bounded, acknowledged commands for the test-only native backend.

The backend executes stdin commands serially. A slow valid command must not
cause the driver to enqueue more mining commands behind it: those commands
would later mine beyond the intended boundary. This helper changes only the
test orchestration, not work admission, hashing, validation or clocks.
"""
import os
from pathlib import Path
import secrets
import stat
import time


def acknowledgement(path, request_id):
    """Read only an exact command receipt, never a possibly interleaved log."""
    try:
        descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor,'rb') as stream:
        metadata=os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink>1 or metadata.st_size>256:
            raise RuntimeError('invalid native mining acknowledgement file')
        if metadata.st_nlink==0:
            # The writer can atomically replace this pathname after open() but
            # before fstat(). The open old inode is then unlinked, not corrupt.
            # Do not accept it or queue more work; poll the same command's
            # current receipt within mine_block's existing bounded deadline.
            return None
        raw=stream.read(257)
    if len(raw)>256 or not raw.endswith(b'\n'):
        raise RuntimeError('invalid native mining acknowledgement framing')
    parts=raw.decode('ascii').split()
    if len(parts)<3 or parts[0]!='V1':
        raise RuntimeError('invalid native mining acknowledgement version')
    if parts[1]!=request_id:
        return None  # An earlier command's durable receipt is not this command.
    if parts[2]=='DEFERRED' and len(parts)==3:
        return ('DEFERRED',None,None)
    if (parts[2]=='MINED' and len(parts)==5 and parts[3].isascii() and parts[3].isdigit() and
            str(int(parts[3]))==parts[3] and 0<int(parts[3])<2**64 and
            len(parts[4])==64 and all(c in '0123456789abcdef' for c in parts[4])):
        return ('MINED',int(parts[3]),parts[4])
    raise RuntimeError('invalid native mining acknowledgement schema')


def mine_block(process, rpc, address, log_path, timeout=180):
    before = rpc.call('getblockcount')
    deadline = time.monotonic() + timeout
    if not isinstance(process.args,(list,tuple)) or len(process.args)<2:
        raise RuntimeError('native fixture process identity required')
    directory=Path(process.args[1]).resolve()
    if not directory.is_dir():raise RuntimeError('native fixture directory missing')
    ack_path=directory/'lab-mining-ack.txt'
    pending=False;request_id='';last_refusal=''
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('native backend exited during mining')
        if not pending:
            current = rpc.call('getblockcount')
            if current > before:
                return current
            request_id=secrets.token_hex(16)
            process.stdin.write('clock ' + str(1767225600 + (before + 1) * 180) + '\n')
            process.stdin.write('mine ' + address + ' ' + request_id + '\n')
            process.stdin.flush()
            pending=True
        receipt=acknowledgement(ack_path,request_id)
        if receipt is not None:
            result,height,block=receipt
            if result=='MINED':
                if height<=before or rpc.call('getblockhash',str(height))!=block:
                    raise RuntimeError('native mining acknowledgement is not the expected canonical block')
                return height
            last_refusal='native command deferred';pending=False
        time.sleep(.1 if pending else .5)
    # Do not enqueue another command or interpret a timeout as invalid work.
    raise RuntimeError('native mining acknowledgement deadline: ' +
                       (last_refusal or 'command still running'))
