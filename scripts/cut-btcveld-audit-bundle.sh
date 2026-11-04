#!/bin/bash
# cut-btcveld-audit-bundle.sh — build the btcVELD peg + AMM external-audit
# source bundle.
#
# Superset of the mainnet-RC cut, focused on the btcVELD additive surface:
# full node source (so the ledger / AMM / guard / reorg overlay are reviewable
# in context) + the btcVELD design docs + dry-run proofs + operational services.
# ALLOWLIST cut, explicit secret removals, and a HARD secret-scan gate.
# The cover letter (mainnet-launch/BTCVELD_AUDIT_PACKAGE.md) is moved to the
# bundle root as README_AUDIT.md; its own SHA is reported separately (not
# embedded) so the bundle is not self-referential. Run from repo root.
#   usage: bash scripts/cut-btcveld-audit-bundle.sh <YYYYMMDD> [OUTPUT_DIR]
set -euo pipefail
TS="${1:?usage: cut-btcveld-audit-bundle.sh <YYYYMMDD> [OUTPUT_DIR]}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${2:-$ROOT/dist}"
cd "$ROOT"
BD="$OUT/.stage-$TS"
RC="veld-btcveld-audit-$TS"
TARBALL="veld-btcveld-audit-source-$TS.tar.gz"
mkdir -p "$OUT"
rm -rf "$BD"; mkdir -p "$BD/$RC"

echo "  [stage] allowlist copy"
# --- ALLOWLIST: source tree + docs + dryrun proofs + fuzz harnesses + btcVELD
#     services + transform + vendored PQClean.
for d in include src docs mainnet-launch scripts fuzz vendor pkg swap; do
    [ -d "$d" ] && cp -r "$d" "$BD/$RC/"
done
for f in build_linux.sh build_all.sh build_all.bat README.md LICENSE CHANGES.txt pkg/CHANGES.txt; do
    [ -f "$f" ] && cp "$f" "$BD/$RC/" 2>/dev/null || true
done

echo "  [stage] BAN the prose cover letter / README (flagged stale by auditors 5x — removed for good)"
# --- The prose cover letter perpetually goes stale vs the live code (it described a
# --- DORMANT peg while the peg ships LIVE) and mis-scopes the audit. It is PERMANENTLY
# --- EXCLUDED — the source code + the current design docs are the audit surface, and
# --- they don't drift. Defensive removal so it can never recur even if a copy reappears.
rm -f "$BD/$RC/README_AUDIT.md" "$BD/$RC/mainnet-launch/BTCVELD_AUDIT_PACKAGE.md"
find "$BD/$RC" -type f \( -iname "README_AUDIT.md" -o -iname "BTCVELD_AUDIT_PACKAGE.md" \) -delete 2>/dev/null || true

echo "  [scrub] secret-bearing docs + operator scratch + binaries"
# --- EXPLICIT removals: docs that carry a real VELD_VAULT_PASSPHRASE / ops secrets
rm -f  "$BD/$RC/docs/AUDIT_2026-04-23_RUNNING_STATE.md"
rm -f  "$BD/$RC/docs/HANDOFF_2026-04-17_POST_AUDIT.md"
rm -f  "$BD/$RC/docs/PRE_LAUNCH_OPS_ACTION_NOTE.md"
# --- shipped binaries (source-only bundle)
rm -rf "$BD/$RC/pkg/bin"
# --- the packaging tools themselves (they self-match the secret scan) + scratch
# ALL cut-*.sh bundle tools embed the secret-scan patterns, so they self-match the
# gate; they are packaging tooling, not audit surface. Strip every one (a new
# cut-full-audit-bundle.sh tripped the gate once — glob so future ones can't recur).
rm -f  "$BD/$RC/scripts/cut-"*.sh
rm -f  "$BD/$RC/scripts/test-wd-gen.ps1"
rm -f  "$BD/$RC/scripts/remote-build-"*.sh 2>/dev/null || true
rm -f  "$BD/$RC/scripts/regress-v1v3.sh"

echo "  [scrub] btcVELD services (pyc / caches / operator configs)"
# --- Drop compiled caches and any real operator configuration or key material.
find "$BD/$RC/swap" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$BD/$RC/swap" -type f -name "*.pyc" -delete 2>/dev/null || true
# real (non-.example) operator configs, if any ever land next to the sources
find "$BD/$RC/swap" -type f -name "*.conf" ! -name "*.example" -delete 2>/dev/null || true
find "$BD/$RC/swap" -type f \( -iname "*.key" -o -iname "*.seed" -o -iname "*.env" -o -iname "*.pass" \) -delete 2>/dev/null || true

echo "  [scrub] fuzz corpora / crash inputs (generated test data)"
rm -rf "$BD/$RC/fuzz/corpus_"* 2>/dev/null || true
find "$BD/$RC/fuzz" -mindepth 1 -maxdepth 2 -type d \
     \( -iname "corpus*" -o -iname "crash*" -o -iname "finding*" -o -iname "seed*" \) \
     -exec rm -rf {} + 2>/dev/null || true

echo "  [scrub] defensive artifact sweep"
# --- DEFENSIVE sweep: drop any key/secret/artifact that slipped in by construction
# python bytecode caches ANYWHERE in the tree (source-only bundle; the swap-scoped
# sweep above missed scripts/__pycache__ etc.)
find "$BD/$RC" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$BD/$RC" -type f \( \
    -iname "*.key" -o -iname "*.pem" -o -iname "*.pass" -o -iname "*.token" -o \
    -iname "*secret*" -o -iname "*.p12" -o -iname "*.pfx" -o \
    -iname "*.exe" -o -iname "*.dll" -o -iname "*.o" -o -iname "*.a" -o -iname "*.so" -o \
    -iname "*.log" -o -iname "*.zip" -o -iname "*.tar.gz" -o \
    -iname "*.bak*" -o -iname "*.orig" -o -iname "*~" \) -delete 2>/dev/null || true

echo "  [gate] HARD secret-scan"
# Quote-aware, case-insensitive scanner covers the full staged tree and never
# echoes matched credential values.
python3 -B "$ROOT/scripts/scan-bundle-secrets.py" "$BD/$RC"
echo "  [gate] CLEAN — no passphrases / private keys / tokens / maker WIFs"

echo "  [pack] tarball + manifest + sha256"
cd "$BD"
tar -czf "$OUT/$TARBALL" "$RC"
cd "$OUT"
SHA="$(sha256sum "$TARBALL" | awk '{print $1}')"
NFILES="$(find "$BD/$RC" -type f | wc -l | tr -d ' ')"
SIZE="$(du -h "$TARBALL" | awk '{print $1}')"
# manifest: sorted file list for the audit team to diff against
( cd "$BD" && find "$RC" -type f | sort ) > "$OUT/veld-btcveld-audit-manifest-$TS.txt"
rm -rf "$BD"

echo
echo "=== btcVELD audit bundle cut ==="
echo "  tarball : $OUT/$TARBALL"
echo "  size    : $SIZE   files: $NFILES"
echo "  sha256  : $SHA"
echo "  manifest: $OUT/veld-btcveld-audit-manifest-$TS.txt"
