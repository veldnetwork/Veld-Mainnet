"""Execute the shipping watchdog branch with an inert node in a local C++ harness."""
from pathlib import Path
import argparse
import os
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--compiler", required=True)
parser.add_argument("--output-dir", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
source = (root / "src/veld-node.cpp").read_text(encoding="utf-8")
start = source.index("if (stuck_secs >= STUCK_GRACE_SECS)")
brace = source.index("{", start)
depth = 1
end = brace + 1
while depth:
    depth += (source[end] == "{") - (source[end] == "}")
    end += 1
branch = source[start:end]
assert "::_exit(" not in branch
assert "RequestSnapshotRecoveryOnRestart" not in branch
prefix = r"""#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <iostream>
struct InertNode {
  unsigned calls = 0;
  void SetIBDComplete(bool complete) { assert(!complete); ++calls; }
  void SyncTCPIBDFlag() { ++calls; }
  void ClearRejectCache() { ++calls; }
  void ClearOrphanPool() { ++calls; }
  void TriggerTipReconcile() { ++calls; }
};
void run(uint64_t hint, int elapsed, bool suppressed) {
#ifdef _WIN32
  _putenv_s("VELD_DISABLE_STUCK_RESTART", suppressed ? "1" : "");
#else
  setenv("VELD_DISABLE_STUCK_RESTART", suppressed ? "1" : "", 1);
#endif
  InertNode node;
  constexpr int STUCK_GRACE_SECS = 300;
  int stuck_secs = elapsed, stable_ticks = 4;
  uint64_t cur_height = 10, peer_best = hint, stuck_anchor_height = 9;
"""
suffix = r"""
  if (elapsed < STUCK_GRACE_SECS) {
    assert(node.calls == 0 && stuck_secs == elapsed);
  } else if (suppressed) {
    assert(node.calls == 0 && stuck_secs == -STUCK_GRACE_SECS);
  } else {
    assert(node.calls == 5 && stable_ticks == 0 && stuck_anchor_height == cur_height && stuck_secs == 0);
  }
}
int main() {
  run(11, 299, false);
  run(11, 300, false);
  run(1000, 300, false);
  run(1000, 300, true);
  std::cout << "PASS: actual watchdog branch uses bounded recovery for small/large hints and preserves suppression/grace controls\n";
}
"""
args.output_dir.mkdir(parents=True, exist_ok=True)
unit = args.output_dir / "watchdog-branch.cpp"
exe = args.output_dir / ("watchdog-branch.exe" if os.name == "nt" else "watchdog-branch")
unit.write_text(prefix + branch + suffix, encoding="utf-8", newline="\n")
subprocess.run([args.compiler, "-std=c++20", "-O0", "-g0", str(unit), "-o", str(exe)], check=True)
subprocess.run([str(exe)], check=True, timeout=10)
