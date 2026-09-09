"""Compile the supply-cap fixture boundary in private and public profiles."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = output / "coinbase-fixture-profile.cpp"
    source.write_text('''#include "node/node.h"
#include "core/version.h"
#include <concepts>
#include <string_view>
template<class T> concept HasAccountingParent = requires(T& node) {
    { node.TestSetCoinbaseAccountingParent(uint64_t{0}) } -> std::same_as<bool>;
};
static_assert(HasAccountingParent<veld::VeldNode> == EXPECT_FIXTURE);
static_assert(std::string_view(veld::CLIENT_VERSION) == "3.1.3");
static_assert(veld::CONSENSUS_SECURITY_UPGRADE_HEIGHT == 2880);
#ifdef VELD_PUBLIC_RELEASE
#ifdef VELD_PUBLIC_MAINNET
static_assert(veld::PROTOCOL_UPGRADE_HEIGHT == 3840);
static_assert(veld::ASERT_ACTIVATION_HEIGHT == 3840);
static_assert(veld::SECURITY_STATE_MIGRATION_HEIGHT == 3840);
#else
static_assert(veld::PROTOCOL_UPGRADE_HEIGHT == 0);
static_assert(veld::ASERT_ACTIVATION_HEIGHT == 0);
static_assert(veld::SECURITY_STATE_MIGRATION_HEIGHT == 0);
#endif
#endif
''', encoding="utf-8")
    private = ["VELD_TEST_CHAIN_BUILD", "VELD_TEST_HOOKS",
               "VELD_DSTATE_QUALIFICATION", "VELD_ASERT_TESTCHAIN",
               "VELD_TEST_BRANCH_CONTEXT", "VELD_TEST_STAKE_OUTPOINT_BACKING",
               "VELD_PROTOCOL_UPGRADE_TEST_HEIGHT=3360"]
    cases = [("private-fixture", private, True, True)]
    for profile in ("VELD_PUBLIC_MAINNET", "VELD_PUBLIC_TESTNET"):
        flags = ["VELD_PUBLIC_RELEASE", profile]
        cases.append((profile.lower(), flags, False, True))
        cases.append((profile.lower() + "-reject-fixture", flags + private, True, False))
    results = []
    for name, flags, visible, allowed in cases:
        command = [args.compiler, "-std=c++20", "-fsyntax-only", "-DVELD_MAINNET_POW",
                   "-DVELD_USE_LEVELDB", "-DEXPECT_FIXTURE=" + str(int(visible)),
                   "-I" + str(root / "include"), "-I" + str(root / "vendor/pqc"),
                   *("-D" + flag for flag in flags), str(source)]
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=180)
        (output / (name + ".log")).write_text(result.stdout + result.stderr, encoding="utf-8")
        passed = (result.returncode == 0) == allowed
        if not allowed:
            passed = passed and "cannot be combined with consensus test or bypass macros" in result.stderr
        results.append(dict(case=name, command=command, exit_code=result.returncode,
                            expected_compile=allowed, passed=passed))
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        if not passed:
            raise AssertionError(name + ": " + result.stderr[-2000:])
    print("PASS coinbase fixture profile contracts=" + str(len(results)))


if __name__ == "__main__":
    main()
