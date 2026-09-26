import queue
import subprocess
import threading
import time
from .protocol import Busy, require, hex64


class Native:
    """One bounded, separately scheduled native verifier process."""

    def __init__(self, binary, log):
        self.binary, self.log = str(binary), log
        self.lock = threading.Lock()
        self.closed = False
        self.starts = []
        self.process = self.reader = None
        self._start()

    def _start(self):
        now = time.monotonic()
        self.starts = [started for started in self.starts if now - started < 60]
        if len(self.starts) >= 3:
            raise Busy('native restart limit; retry later')
        self.starts.append(now)
        process = subprocess.Popen(
            [self.binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log,
            text=True,
            bufsize=1,
        )
        lines = queue.Queue(maxsize=4)
        self.process, self.lines = process, lines

        def read():
            try:
                while True:
                    line = process.stdout.readline(513)
                    if not line:
                        break
                    if len(line) > 512 or not line.endswith('\n'):
                        break
                    lines.put(line.rstrip('\n'), timeout=1)
            except (OSError, ValueError, queue.Full):
                pass
            finally:
                try:
                    lines.put(None, timeout=1)
                except queue.Full:
                    pass

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()

    def _stop(self):
        process, reader = self.process, self.reader
        self.process = self.reader = None
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if reader is not None:
            reader.join(timeout=2)
        process.stdin.close()
        process.stdout.close()

    def request(self, line, timeout=10):
        require(
            isinstance(line, str) and len(line) <= 512 and '\n' not in line and '\r' not in line,
            'native request frame',
        )
        if not self.lock.acquire(blocking=False):
            raise Busy('native verifier occupied')
        try:
            if self.closed:
                raise Busy('native verifier stopped')
            if self.process is None or self.process.poll() is not None:
                self._stop()
                self._start()
            try:
                self.process.stdin.write(line + '\n')
                self.process.stdin.flush()
            except OSError as error:
                self._stop()
                raise Busy('native verifier disconnected; retry same proof') from error
            try:
                result = self.lines.get(timeout=timeout)
            except queue.Empty:
                self._stop()
                raise Busy('native verifier timed out')
            if result is None or not result.startswith('OK '):
                self._stop()
                raise Busy('native verifier resource failure')
            return result.split()
        finally:
            self.lock.release()

    def hash(self, header, height):
        result = self.request(f'hash {height} {header.hex()}')
        require(len(result) == 3, 'native response schema')
        return hex64(result[1]), hex64(result[2])

    def inspect(self, header, height):
        result = self.request(f'inspect {height} {header.hex()}')
        require(
            len(result) == 4 and result[3] in ('block', 'near_miss', 'none'), 'native proof schema'
        )
        return hex64(result[1]), hex64(result[2]), result[3]

    def close(self):
        with self.lock:
            self.closed = True
            self._stop()
