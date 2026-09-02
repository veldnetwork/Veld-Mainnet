#!/usr/bin/env python3
"""Focused source-order assertions for private-seed lifetime minimization."""

from pathlib import Path
import sys


checks = 0


def require(condition: bool, message: str) -> None:
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


def ordered(text: str, *needles: str) -> bool:
    position = 0
    for needle in needles:
        found = text.find(needle, position)
        if found < 0:
            return False
        position = found + len(needle)
    return True


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: daybreak_seed_lifetime_source_tests.py SRC")
    source = Path(sys.argv[1]).read_text(encoding="utf-8")

    require("void Clear() noexcept" in source,
            "sensitive wrappers must expose explicit no-throw clearing")
    require("~SensitiveString() { Clear(); }" in source,
            "sensitive strings must remain RAII-wiped")
    require("~LockedSeed() {\n        Clear();" in source,
            "locked seeds must remain RAII-wiped")

    main_start = source.index('if (cmd == "new" || cmd == "from-seed")')
    main_end = source.index('if (cmd == "show")', main_start)
    import_flow = source[main_start:main_end]
    require(ordered(import_flow,
                    "ValidateNewOutputPath(out_path)",
                    'ReadPassphrase("encrypting new key")',
                    'if (cmd == "from-seed")',
                    "ReadSeedFromProtectedHandle"),
            "destination and passphrase must be validated before seed import")
    require("LockedSeed seed;" in import_flow,
            "imported decoded seed must live only in locked RAII storage")
    require("std::array<uint8_t, 32> seed{}" not in import_flow,
            "import flow must not retain an unlocked decoded seed copy")
    require(ordered(import_flow,
                    "ParseHex32(seed_hex.value, seed.bytes)",
                    "seed_hex.Clear();",
                    "CmdNew(out_path, testnet, &seed, pass)"),
            "raw seed hex must be wiped immediately after parsing")

    command_start = source.index("static int CmdNew(")
    command_end = source.index("static int CmdShow(", command_start)
    command = source[command_start:command_end]
    require("LockedSeed* seed_opt" in command,
            "CmdNew must consume locked storage without another seed copy")
    require("ReadPassphrase(" not in command,
            "CmdNew must not wait for a passphrase while holding a seed")
    require("HexOf(seed" not in command,
            "secret hex must not be created in an unmanaged temporary string")
    require(ordered(command,
                    "AppendHex(plaintext.value, seed->bytes.data()",
                    "seed->Clear();",
                    "EncryptWallet(plaintext.value"),
            "seed bytes must be wiped after plaintext construction and before encryption")
    require(command.count("plaintext.Clear();") >= 2,
            "plaintext must be cleared on encryption failure and success")
    require(command.count("pass.Clear();") >= 2,
            "passphrase must be cleared on encryption failure and success")
    require(ordered(command,
                    "EncryptWallet(plaintext.value",
                    "}\n    plaintext.Clear();\n    pass.Clear();",
                    "AtomicWriteNew("),
            "plaintext and passphrase must be wiped before ciphertext output")
    require("plaintext.value.reserve(" in command,
            "plaintext must reserve before appending secret hex")

    print(f"PASS daybreak_seed_lifetime_source_tests checks={checks}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
