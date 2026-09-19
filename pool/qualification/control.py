"""Bounded, acknowledged commands for the test-only native backend.

The backend executes stdin commands serially. A slow valid command must not
cause the driver to enqueue more mining commands behind it: those commands
would later mine beyond the intended boundary. This helper changes only the
test orchestration, not work admission, hashing, validation or clocks.
"""
import time


def mine_block(process, rpc, address, log_path, timeout=180):
    before = rpc.call('getblockcount')
    deadline = time.monotonic() + timeout
    with log_path.open('rb') as log:
        log.seek(0, 2)
        pending = False
        buffered = b''
        last_refusal = ''
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('native backend exited during mining')
            if not pending:
                current = rpc.call('getblockcount')
                if current > before:
                    return current
                process.stdin.write('clock ' + str(1767225600 + (before + 1) * 180) + '\n')
                process.stdin.write('mine ' + address + '\n')
                process.stdin.flush()
                pending = True
            buffered += log.read()
            while b'\n' in buffered:
                line, buffered = buffered.split(b'\n', 1)
                if line.startswith(b'MINED '):
                    height = int(line.split()[1])
                    if height <= before:
                        raise RuntimeError('native mining acknowledged an unexpected height')
                    return height
                if line.startswith(b'MINE_DEFERRED '):
                    last_refusal = line.decode('utf8', errors='replace')[:512]
                    pending = False
            time.sleep(.1 if pending else .5)
    # Do not enqueue another command or interpret a timeout as invalid work.
    raise RuntimeError('native mining acknowledgement deadline: ' +
                       (last_refusal or 'command still running'))
