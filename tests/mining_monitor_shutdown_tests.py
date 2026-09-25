"""Exercise the production mining monitor's shutdown cancellation with native threads."""

from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile

prefix = r'''
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

struct Node {
    std::atomic<bool> running_{true}, mining_{true}, mining_hashing_active_{true};
    struct Chain { int GetHeight() const { return 0; } } chain_;
    struct { int prev_hash{0}; } tmpl;
    struct HashingPause {
        explicit HashingPause(std::atomic<bool>& state): state(state) { state.store(false); }
        ~HashingPause() { state.store(true); }
        std::atomic<bool>& state;
    };
    std::atomic<bool> first_safety{false}, safety_in_progress{false};
    bool MiningWorkStillSafe(int, std::string&) {
        if (!first_safety.exchange(true)) return true;
        safety_in_progress.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        return true;
    }
    bool Run(unsigned count) {
        std::atomic<bool> stop_now{false}, network_recheck_requested{false};
        std::atomic<bool> rebuild_for_pending_transactions{false};
        std::atomic<uint64_t> mining_template_revision_{0};
        const uint64_t template_revision=0;
        std::vector<std::thread> workers;
        for (unsigned i=0;i<count;++i) workers.emplace_back([&] { while(!stop_now.load()) std::this_thread::yield(); });
'''
suffix = r'''
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        while (!safety_in_progress.load() && std::chrono::steady_clock::now()<deadline) std::this_thread::yield();
        running_.store(false);
        mirror.join();
        bool forwarded=stop_now.load();
        stop_now.store(true);
        for (auto& worker:workers) worker.join();
        std::cout << "workers=" << count << " cancellation_forwarded=" << forwarded << "\n";
        return forwarded;
    }
};
int main() {
    for(unsigned n: {1u,7u,8u,15u}) { Node node; if(!node.Run(n)) return 1; }
}
'''


def extract_monitor(text):
    """Select the single monitor declaration and its following target boundary."""
    text = text.replace('\r\n', '\n')
    starts = list(re.finditer(r'(?m)^[ \t]*std::thread\s+mirror\s*\(', text))
    ends = list(re.finditer(r'(?m)^[ \t]*uint32_t\s+effective_bits\s*=', text))
    if len(starts) != 1 or len(ends) != 1 or ends[0].start() <= starts[0].end():
        raise ValueError('expected one mining monitor and its following target declaration')
    body = text[starts[0].start() : ends[0].start()].rstrip()
    if not re.search(r'\}\s*\)\s*;\s*$', body):
        raise ValueError('mining monitor declaration is not terminated before the target')
    return body


def check_extraction():
    fixture = (
        'std::thread mirror([]() {\n    stop_now.store(true);\n});\nuint32_t effective_bits = 1;\n'
    )
    expected = re.sub(r'\s+', '', extract_monitor(fixture))
    layouts = (
        fixture,
        fixture.replace('mirror(', 'mirror(\n'),
        fixture.replace('\n', '\r\n'),
        '\n'.join('    ' + line for line in fixture.splitlines()),
    )
    for layout in layouts:
        if re.sub(r'\s+', '', extract_monitor(layout)) != expected:
            raise AssertionError('monitor extraction depends on source layout')
    invalid = (
        fixture.replace('mirror(', 'other('),
        fixture.replace('effective_bits', 'other_bits'),
        fixture + fixture,
        fixture.replace('});', '}'),
        'uint32_t effective_bits = 1;\nstd::thread mirror([]() {});\n',
    )
    for source in invalid:
        try:
            extract_monitor(source)
        except ValueError:
            continue
        raise AssertionError('ambiguous or incomplete monitor extraction was accepted')
    return len(layouts) + len(invalid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cxx', default='clang++')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    header = (args.source_root / 'include/node/node.h').read_bytes()
    extraction_controls = check_extraction()
    body = extract_monitor(header.decode())
    with tempfile.TemporaryDirectory(prefix='veld-mining-monitor-') as temporary:
        folder = Path(temporary)
        harness = folder / 'monitor.cpp'
        harness.write_text(prefix + body + suffix, encoding='utf-8')
        binary = folder / ('monitor.exe' if os.name == 'nt' else 'monitor')
        env = dict(os.environ)
        if os.name == 'nt' and Path(args.cxx).is_absolute():
            env['PATH'] = str(Path(args.cxx).parent) + os.pathsep + env.get('PATH', '')
        subprocess.run(
            [args.cxx, '-std=c++20', '-O1', '-pthread', str(harness), '-o', str(binary)],
            check=True,
            timeout=90,
            env=env,
        )
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15, env=env)
        result = dict(
            result='PASS' if run.returncode == 0 else 'FAIL',
            run_exit=run.returncode,
            extraction_controls=extraction_controls,
            source_header_sha256=hashlib.sha256(header).hexdigest(),
            monitor_body_sha256=hashlib.sha256(body.encode()).hexdigest(),
            output=run.stdout + run.stderr,
        )
        if args.output:
            args.output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
        return run.returncode


if __name__ == '__main__':
    raise SystemExit(main())
