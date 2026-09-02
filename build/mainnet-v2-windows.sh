#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 ROLE OUTPUT_DIR" >&2
  echo "Run from MSYS2 CLANG64. ROLE: node | desktop | keygen | validator | gui | fleet" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
role=$1
output=$(realpath -m "$2")
src=$(realpath "$(dirname "$0")/..")
case "$output/" in
  "$src/"*)
    echo "output directory must be outside the source tree" >&2
    exit 2
    ;;
esac
if [[ -e $output ]]; then
  [[ -d $output && -z $(find "$output" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
    echo "output directory must be absent or empty: $output" >&2
    exit 2
  }
fi

case "$role" in
  node)    source_file=src/veld-node.cpp;    binary=veld-node.exe ;;
  desktop) source_file=src/veld-desktop.cpp; binary=veld-wallet.exe ;;
  keygen)  source_file=src/veld-keygen.cpp;  binary=veld-keygen.exe ;;
  validator) source_file=src/veld-validator.cpp; binary=veld-validator.exe ;;
  gui)     source_file=src/veld-node-gui.cpp; binary=veld-node-gui.exe ;;
  fleet)   source_file=src/veld-node.cpp;    binary=veld-node-fleet-no-mine.exe ;;
  *) usage ;;
esac
[[ ${MSYSTEM:-} == CLANG64 ]] || {
  echo "Windows production builds require the MSYS2 CLANG64 environment" >&2
  exit 2
}

git_root=$(git -C "$src" rev-parse --show-toplevel 2>/dev/null || true)
if [[ -n $git_root && $(realpath "$git_root") == "$src" ]]; then
  source_is_git=1
  source_identity_basis=verified-git-worktree
  source_commit=$(git -C "$src" rev-parse HEAD)
  source_tree=$(git -C "$src" rev-parse 'HEAD^{tree}')
  controller_rel=$(realpath --relative-to="$src" "${BASH_SOURCE[0]}")
  git -C "$src" ls-files --error-unmatch "$controller_rel" "$source_file" \
    >/dev/null
  [[ -z $(git -C "$src" status --short) ]] || {
    echo "refusing a dirty source worktree" >&2
    exit 2
  }
else
  source_is_git=0
  source_identity_basis=caller-declared-source-archive
  : "${VELD_SOURCE_COMMIT:?source archive requires VELD_SOURCE_COMMIT}"
  : "${VELD_SOURCE_TREE:?source archive requires VELD_SOURCE_TREE}"
  source_commit=$VELD_SOURCE_COMMIT
  source_tree=$VELD_SOURCE_TREE
fi
[[ $source_commit =~ ^[0-9a-f]{40}$ && $source_tree =~ ^[0-9a-f]{40}$ ]] || {
  echo "source commit/tree must be lowercase 40-character Git object IDs" >&2
  exit 2
}

if command -v python3 >/dev/null; then
  pqc_python=python3
elif command -v python >/dev/null; then
  pqc_python=python
else
  echo "Python 3 is required for the PQC raw-byte provenance gate" >&2
  exit 2
fi
"$pqc_python" "$src/scripts/verify-pqc-provenance.py" \
  --root "$src" --release-role "$role"

base_definitions=(
  -DVELD_MAINNET_POW
  -DVELD_PUBLIC_RELEASE
  -DVELD_PUBLIC_MAINNET
)
definitions=("${base_definitions[@]}")
case "$role" in
  node|desktop) definitions+=(-DVELD_USE_LEVELDB) ;;
  fleet) definitions+=(-DVELD_USE_LEVELDB -DVELD_FLEET_NO_MINE) ;;
esac
if [[ $role == gui ]]; then
  : "${VELD_TRUSTED_NODE_BUILD:?gui role requires VELD_TRUSTED_NODE_BUILD}"
  : "${VELD_TRUSTED_WALLET_BUILD:?gui role requires VELD_TRUSTED_WALLET_BUILD}"
  trusted_node_build=$(realpath "$VELD_TRUSTED_NODE_BUILD")
  trusted_wallet_build=$(realpath "$VELD_TRUSTED_WALLET_BUILD")
  trusted_node_source="$trusted_node_build/bin/veld-node.exe"
  trusted_wallet_source="$trusted_wallet_build/bin/veld-wallet.exe"
  for path in \
      "$trusted_node_source" "$trusted_wallet_source" \
      "$trusted_node_build/build-identity.tsv" \
      "$trusted_wallet_build/build-identity.tsv" \
      "$trusted_node_build/deployment-info.txt" \
      "$trusted_wallet_build/deployment-info.txt" \
      "$trusted_node_build/binary-sha256.txt" \
      "$trusted_wallet_build/binary-sha256.txt"; do
    [[ -f $path ]] || {
      echo "missing trusted GUI build input: $path" >&2
      exit 2
    }
  done
  require_build_field() {
    local file=$1 key=$2 expected=$3 actual
    actual=$(awk -F '\t' -v key="$key" '$1 == key { print $2 }' "$file")
    [[ $actual == "$expected" ]] || {
      echo "trusted build $file has $key=$actual, expected $expected" >&2
      exit 2
    }
  }
  for build_dir in "$trusted_node_build" "$trusted_wallet_build"; do
    require_build_field "$build_dir/build-identity.tsv" source_commit "$source_commit"
    require_build_field "$build_dir/build-identity.tsv" source_tree "$source_tree"
  done
  require_build_field "$trusted_node_build/build-identity.tsv" role node
  require_build_field "$trusted_wallet_build/build-identity.tsv" role desktop
  trusted_node_hash=$(sha256sum "$trusted_node_source" | awk '{print $1}')
  trusted_wallet_hash=$(sha256sum "$trusted_wallet_source" | awk '{print $1}')
  awk -v hash="$trusted_node_hash" '$1 == hash { found=1 } END { exit !found }' \
    "$trusted_node_build/binary-sha256.txt"
  awk -v hash="$trusted_wallet_hash" '$1 == hash { found=1 } END { exit !found }' \
    "$trusted_wallet_build/binary-sha256.txt"
  node_info="$trusted_node_build/deployment-info.txt"
  wallet_info="$trusted_wallet_build/deployment-info.txt"
  grep -F '"profile_id":"veld-public-mainnet-v2"' "$node_info"
  grep -F '"binary_role":"node"' "$node_info"
  grep -F '"storage_backend":"leveldb"' "$node_info"
  grep -F '"fleet_no_mine":false' "$node_info"
  grep -F '"mining_compiled":true' "$node_info"
  grep -F '"mining_rpc_methods_compiled":true' "$node_info"
  grep -F '"profile_id":"veld-public-mainnet-v2"' "$wallet_info"
  grep -F '"binary_role":"desktop-client"' "$wallet_info"
  grep -F '"storage_backend":"leveldb"' "$wallet_info"
  grep -F '"remote_tls_backend":"winhttp"' "$wallet_info"
  node_client_version=$(sed -n 's/.*"client_version":"\([^"]*\)".*/\1/p' "$node_info")
  wallet_client_version=$(sed -n 's/.*"client_version":"\([^"]*\)".*/\1/p' "$wallet_info")
  [[ -n $node_client_version && $node_client_version == "$wallet_client_version" ]] || {
    echo "trusted node and wallet client versions do not match" >&2
    exit 2
  }
  definitions+=(
    "-DVELD_TRUSTED_NODE_SHA256=\"$trusted_node_hash\""
    "-DVELD_TRUSTED_WALLET_SHA256=\"$trusted_wallet_hash\""
  )
fi
for definition in "${definitions[@]}"; do
  if [[ $definition == *VELD_TEST* || $definition == *REGTEST* ||
        $definition == *QUALIFICATION* ]]; then
    echo "test/qualification macro refused: $definition" >&2
    exit 2
  fi
done

mkdir -p "$output/obj" "$output/bin" "$output/logs"
if [[ $role == gui ]]; then
  mkdir -p "$output/trusted-inputs"
  trusted_node="$output/trusted-inputs/veld-node.exe"
  trusted_wallet="$output/trusted-inputs/veld-wallet.exe"
  cp "$trusted_node_source" "$trusted_node"
  cp "$trusted_wallet_source" "$trusted_wallet"
  [[ $(sha256sum "$trusted_node" | awk '{print $1}') == "$trusted_node_hash" ]]
  [[ $(sha256sum "$trusted_wallet" | awk '{print $1}') == "$trusted_wallet_hash" ]]
fi
exec > >(tee "$output/logs/${role}-build.log") 2>&1

{
  printf 'source_commit\t%s\n' "$source_commit"
  printf 'source_tree\t%s\n' "$source_tree"
  printf 'source_identity_basis\t%s\n' "$source_identity_basis"
  printf 'platform\twindows-msys2-clang64\n'
  printf 'role\t%s\n' "$role"
  printf 'source\t%s\n' "$source_file"
  printf 'binary\t%s\n' "$binary"
  if [[ $role == gui ]]; then
    printf 'trusted_node_sha256\t%s\n' "$trusted_node_hash"
    printf 'trusted_wallet_sha256\t%s\n' "$trusted_wallet_hash"
  fi
} | tee "$output/build-identity.tsv"
printf '%s\n' "${definitions[@]}" | tee "$output/compile-definitions.txt"

command -v clang
clang --version
command -v clang++
clang++ --version
command -v ld
ld --version | sed -n '1,2p'
command -v openssl
openssl version -a
pacman -Q | grep -E \
  '^(mingw-w64-clang-x86_64-(clang|leveldb|openssl|gcc-libs|libwinpthread)|msys2-runtime) ' \
  | sort | tee "$output/dependencies.tsv"

if [[ $role == gui ]]; then
  "$trusted_node" --deployment-info |
    tee "$output/trusted-node-deployment-info.txt"
  "$trusted_wallet" --deployment-info |
    tee "$output/trusted-desktop-deployment-info.txt"
  for report in trusted-node-deployment-info trusted-desktop-deployment-info; do
    grep -F '"profile_id":"veld-public-mainnet-v2"' "$output/$report.txt"
    grep -F '"storage_backend":"leveldb"' "$output/$report.txt"
  done
  grep -F '"binary_role":"node"' "$output/trusted-node-deployment-info.txt"
  grep -F '"fleet_no_mine":false' "$output/trusted-node-deployment-info.txt"
  grep -F '"mining_compiled":true' "$output/trusted-node-deployment-info.txt"
  grep -F '"mining_rpc_methods_compiled":true' "$output/trusted-node-deployment-info.txt"
  grep -F '"binary_role":"desktop-client"' "$output/trusted-desktop-deployment-info.txt"
  grep -F '"remote_tls_backend":"winhttp"' "$output/trusted-desktop-deployment-info.txt"
  live_node_client_version=$(sed -n \
    's/.*"client_version":"\([^"]*\)".*/\1/p' \
    "$output/trusted-node-deployment-info.txt")
  live_wallet_client_version=$(sed -n \
    's/.*"client_version":"\([^"]*\)".*/\1/p' \
    "$output/trusted-desktop-deployment-info.txt")
  [[ $live_node_client_version == "$node_client_version" &&
     $live_wallet_client_version == "$wallet_client_version" ]] || {
    echo "staged GUI inputs do not match their recorded client versions" >&2
    exit 2
  }
fi

mapfile -t c_sources < <(grep -Ev '^[[:space:]]*(#|$)' \
  "$src/vendor/pqc/provenance/release-c-sources.txt")
objects=()
for index in "${!c_sources[@]}"; do
  rel=${c_sources[$index]}
  obj="$output/obj/${index}-$(basename "${rel%.c}").o"
  command=(clang -std=c11 -O2 -DNDEBUG -I"$src/vendor/pqc" \
    -I"$src/vendor/pqc/mldsa65" -c "$src/$rel" -o "$obj")
  printf 'COMMAND'; printf ' %q' "${command[@]}"; printf '\n'
  "${command[@]}"
  objects+=("$obj")
done

artifact="$output/bin/$binary"

# Public Windows packages must run on a stock supported Windows installation.
# Link the CLANG64 C++ runtime and LevelDB into each release-role executable so
# users never need loose MSYS2 DLLs beside the client or a developer toolchain
# on PATH. System DLLs remain ordinary Windows imports.
static_runtime_archives=(
  "$MINGW_PREFIX/lib/libc++.a"
  "$MINGW_PREFIX/lib/libc++abi.a"
  "$MINGW_PREFIX/lib/libunwind.a"
)
for archive in "${static_runtime_archives[@]}"; do
  [[ -f $archive ]] || {
    echo "missing required static runtime archive: $archive" >&2
    exit 2
  }
done
static_role_archives=()
if [[ $role != keygen && $role != validator && $role != gui ]]; then
  leveldb_archive="$MINGW_PREFIX/lib/libleveldb.a"
  [[ -f $leveldb_archive ]] || {
    echo "missing required static LevelDB archive: $leveldb_archive" >&2
    exit 2
  }
  static_role_archives+=("$leveldb_archive")
fi
libraries=(-lssl -lcrypto -lws2_32 -ladvapi32 -lbcrypt -liphlpapi \
  -lshell32 -lole32 -luuid -lgdi32)
[[ $role != desktop ]] || libraries+=(-lwinhttp -lcrypt32 -lcomctl32)
extra_objects=()
link_flags=()
if [[ $role == gui ]]; then
  command=(llvm-windres -I"$src" "$src/resources/veld-node.rc" -O coff \
    -o "$output/obj/veld-node-gui-resource.o")
  printf 'COMMAND'; printf ' %q' "${command[@]}"; printf '\n'
  "${command[@]}"
  extra_objects+=("$output/obj/veld-node-gui-resource.o")
  libraries+=(-lwinhttp -lcrypt32 -lcomctl32 -lcomdlg32 -ldwmapi -luser32)
  link_flags+=(-D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00 -mwindows -municode)
fi
command=(clang++ -std=c++20 -O2 -DNDEBUG -pthread -nostdlib++ \
  -I"$src/include" \
  -I"$src/vendor/pqc" -I"$src/vendor/pqc/mldsa65" \
  "${definitions[@]}" "${link_flags[@]}" "$src/$source_file" "${objects[@]}" \
  "${extra_objects[@]}" "${static_role_archives[@]}" \
  "${static_runtime_archives[@]}" "${libraries[@]}" -o "$artifact")
printf 'COMMAND'; printf ' %q' "${command[@]}"; printf '\n'
"${command[@]}"

third_party="$output/third-party"
mkdir -p "$third_party/licenses" "$third_party/provenance/pqc/vendor-patches" \
  "$third_party/provenance/tools"
cp "$src/THIRD_PARTY_NOTICES.md" "$third_party/THIRD_PARTY_NOTICES.md"
cp "$src/vendor/pqc/mldsa65/LICENSE" \
  "$third_party/licenses/PQClean-ML-DSA-65-LICENSE"
cp "$src/vendor/pqc/mlkem768/LICENSE" \
  "$third_party/licenses/PQClean-ML-KEM-768-LICENSE"
cp "$src/vendor/pqc/PQCLEAN_VERSION" "$third_party/provenance/PQCLEAN_VERSION"
cp "$src/vendor/pqc/provenance/"{PQC_PROVENANCE.tsv,README.md,release-c-sources.txt,TOOLCHAIN.lock,wasm-rebuild-attestation.tsv} \
  "$third_party/provenance/pqc/"
cp "$src/vendor/pqc/provenance/vendor-patches/"* \
  "$third_party/provenance/pqc/vendor-patches/"
cp "$src/scripts/generate-mldsa65-nist-kat.py" \
  "$src/scripts/rebuild-pqc-wasm.py" "$src/scripts/rebuild-pqc-wasm.sh" \
  "$src/scripts/verify-pqc-provenance.py" "$third_party/provenance/tools/"
if [[ $role == desktop || $role == gui ]]; then
  cp "$src/third_party_licenses/Emscripten-LICENSE.txt" \
    "$third_party/licenses/Emscripten-LICENSE.txt"
fi

# Recheck exact source bytes immediately before artifact inspection/package
# handoff, so a mid-build source mutation cannot inherit the precompile proof.
"$pqc_python" "$src/scripts/verify-pqc-provenance.py" \
  --root "$src" --release-role "$role" --package-dir "$third_party" \
  | tee "$output/pqc-provenance-prepackage.txt"

file "$artifact" | tee "$output/binary-file.txt"
objdump -p "$artifact" | tee "$output/binary-pe-metadata.txt"
if grep -Eiq 'DLL Name:[[:space:]]*(libc\+\+|libc\+\+abi|libunwind|libleveldb|libwinpthread[^[:space:]]*)\.dll' \
    "$output/binary-pe-metadata.txt"; then
  echo "release artifact retains a forbidden loose-runtime DLL import" >&2
  exit 2
fi
sha256sum "$artifact" | tee "$output/binary-sha256.txt"
if [[ $role == gui ]]; then
  cp "$trusted_node" "$output/bin/veld-node.exe"
  cp "$trusted_wallet" "$output/bin/veld-wallet.exe"
  [[ $(sha256sum "$output/bin/veld-node.exe" | awk '{print $1}') == "$trusted_node_hash" ]]
  [[ $(sha256sum "$output/bin/veld-wallet.exe" | awk '{print $1}') == "$trusted_wallet_hash" ]]
  cp "$artifact" "$output/Veld Node.exe"
  cmp "$artifact" "$output/Veld Node.exe"
  sha256sum "$output/bin/veld-node.exe" "$artifact" \
    "$output/bin/veld-wallet.exe" "$output/Veld Node.exe" \
    | tee "$output/binary-sha256.txt"
  printf 'GUI role is a windowed package launcher; runtime identity is bound by the signed package manifest.\n' \
    | tee "$output/runtime-version.txt" "$output/deployment-info.txt"
else
  "$artifact" --version | tee "$output/runtime-version.txt"
  "$artifact" --deployment-info | tee "$output/deployment-info.txt"
  grep -F 'veld-public-mainnet-v2' "$output/deployment-info.txt"
fi
case "$role" in
  node)
    grep -F '"binary_role":"node"' "$output/deployment-info.txt"
    grep -F '"fleet_no_mine":false' "$output/deployment-info.txt"
    grep -F '"mining_compiled":true' "$output/deployment-info.txt"
    grep -F '"legacy_direct_mint_formats_accepted":false' "$output/deployment-info.txt"
    grep -F '"reserve_proof_semantics":"RTP1/RVS1"' "$output/deployment-info.txt"
    grep -F '"reserve_service_capability_required":true' "$output/deployment-info.txt"
    grep -F '"state_digest_version":8' "$output/deployment-info.txt"
    grep -F '"storage_backend":"leveldb"' "$output/deployment-info.txt"
    ;;
  desktop)
    grep -F '"binary_role":"desktop-client"' "$output/deployment-info.txt"
    grep -F '"remote_tls_backend":"winhttp"' "$output/deployment-info.txt"
    grep -F '"storage_backend":"leveldb"' "$output/deployment-info.txt"
    ;;
  keygen)
    grep -F '"binary_role":"keygen"' "$output/deployment-info.txt"
    ;;
  validator)
    grep -F '"binary_role":"validator-finality-daemon"' "$output/deployment-info.txt"
    grep -F '"finality_bond_units":1000000000000' "$output/deployment-info.txt"
    grep -F '"finality_min_validators":7' "$output/deployment-info.txt"
    grep -F '"genesis_fingerprint":"880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b"' \
      "$output/deployment-info.txt"
    grep -F '"remote_rpc_transport":"loopback-bearer-via-node-helper"' \
      "$output/deployment-info.txt"
    ;;
  gui)
    # LLVM strings in the required CLANG64 environment does not implement
    # GNU strings' -e/--encoding option.  Inspect the UTF-16LE GUI identity
    # directly so this probe is portable across the supported controller.
    perl -0777 -ne '
      BEGIN { $needle = join("\0", split(//, "Veld Node")) . "\0"; }
      if (index($_, $needle) >= 0) { print "Veld Node\n"; $found = 1; }
      END { exit($found ? 0 : 1); }
    ' "$artifact" |
      tee "$output/gui-identity-strings.txt"
    ;;
  fleet)
    grep -F '"binary_role":"node"' "$output/deployment-info.txt"
    grep -F '"fleet_no_mine":true' "$output/deployment-info.txt"
    grep -F '"mining_compiled":false' "$output/deployment-info.txt"
    grep -F '"mining_rpc_methods_compiled":false' "$output/deployment-info.txt"
    grep -F '"legacy_direct_mint_formats_accepted":false' "$output/deployment-info.txt"
    grep -F '"reserve_proof_semantics":"RTP1/RVS1"' "$output/deployment-info.txt"
    grep -F '"reserve_service_capability_required":true' "$output/deployment-info.txt"
    grep -F '"state_digest_version":8' "$output/deployment-info.txt"
    grep -F '"storage_backend":"leveldb"' "$output/deployment-info.txt"
    ;;
esac

strings "$artifact" | grep -E \
  'veld-public-mainnet-v2|RTP1|RVS1|rolling-outpoint-v1|VELD_STATE_DIGEST_v8|Veld (Node|Desktop|Keygen|Validator)' \
  | sort -u | tee "$output/method-feature-inventory.txt" || true
if [[ $role != gui ]]; then
  case "$role" in
    node|fleet)
      required_features=(veld-public-mainnet-v2 RTP1 RVS1 rolling-outpoint-v1 VELD_STATE_DIGEST_v8)
      ;;
    desktop)
      required_features=(veld-public-mainnet-v2 RTP1 RVS1 rolling-outpoint-v1)
      ;;
    keygen)
      required_features=(veld-public-mainnet-v2 RTP1 RVS1)
      ;;
    validator)
      required_features=(veld-public-mainnet-v2)
      ;;
  esac
  for feature in "${required_features[@]}"; do
    grep -F "$feature" "$output/method-feature-inventory.txt"
  done
fi

if [[ $role == fleet ]]; then
  "$artifact" --help >"$output/runtime-help.txt" 2>&1
  if grep -Eq -- '--mine([[:space:]]|$)|--miner([[:space:]]|$)|--threads([[:space:]]|$)' \
      "$output/runtime-help.txt"; then
    echo "fleet help exposes a mining-only option" >&2
    exit 1
  fi
  for invocation in '--mine' '--miner Vbad' '--threads 1'; do
    read -r -a args <<<"$invocation"
    set +e
    "$artifact" "${args[@]}" >"$output/logs/fleet-refusal-${args[0]#--}.txt" 2>&1
    rc=$?
    set -e
    [[ $rc -eq 78 ]] || {
      echo "fleet flag was not deterministically refused: $invocation rc=$rc" >&2
      exit 1
    }
    grep -F 'VELD_FLEET_NO_MINE build' \
      "$output/logs/fleet-refusal-${args[0]#--}.txt"
  done
  set +e
  "$artifact" --help --mine >"$output/logs/fleet-refusal-help-order.txt" 2>&1
  rc=$?
  set -e
  [[ $rc -eq 78 ]] || {
    echo "fleet flag bypassed refusal behind --help: rc=$rc" >&2
    exit 1
  }
fi

if (( source_is_git )); then
  [[ $(git -C "$src" rev-parse HEAD) == "$source_commit" ]]
  [[ $(git -C "$src" rev-parse 'HEAD^{tree}') == "$source_tree" ]]
  [[ -z $(git -C "$src" status --short) ]] || {
    echo "source worktree changed while compiling; discarding attestation" >&2
    exit 1
  }
fi

printf 'PASS mainnet-v2-windows role=%s commit=%s tree=%s sha256=%s\n' \
  "$role" "$source_commit" "$source_tree" \
  "$(sha256sum "$artifact" | awk '{print $1}')"
