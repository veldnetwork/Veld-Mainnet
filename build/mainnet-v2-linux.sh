#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: $0 ROLE OUTPUT_DIR" >&2
  echo "ROLE: node | desktop | keygen | validator | operator | fleet" >&2
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
  node)    source_file=src/veld-node.cpp;    binary=veld-node ;;
  desktop) source_file=src/veld-desktop.cpp; binary=veld-desktop ;;
  keygen)  source_file=src/veld-keygen.cpp;  binary=veld-keygen ;;
  validator) source_file=src/veld-validator.cpp; binary=veld-validator ;;
  operator) source_file=src/veld-miner-portal.py; binary=veld-miner-portal ;;
  fleet)   source_file=src/veld-node.cpp;    binary=veld-node-fleet-no-mine ;;
  *) usage ;;
esac

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

command -v python3 >/dev/null || {
  echo "python3 is required for the PQC raw-byte provenance gate" >&2
  exit 2
}
python3 "$src/scripts/verify-pqc-provenance.py" \
  --root "$src" --release-role "$role"

base_definitions=(
  -DVELD_MAINNET_POW
  -DVELD_PUBLIC_RELEASE
  -DVELD_PUBLIC_MAINNET
)
definitions=("${base_definitions[@]}")
case "$role" in
  node)    definitions+=(-DVELD_USE_LEVELDB) ;;
  desktop) definitions+=(-DVELD_USE_LEVELDB -DVELD_DESKTOP_OPENSSL_TLS) ;;
  fleet)   definitions+=(-DVELD_USE_LEVELDB -DVELD_FLEET_NO_MINE) ;;
esac
if [[ $role == operator ]]; then
  definitions=()
fi
for definition in "${definitions[@]}"; do
  if [[ $definition == *VELD_TEST* || $definition == *REGTEST* ||
        $definition == *QUALIFICATION* ]]; then
    echo "test/qualification macro refused: $definition" >&2
    exit 2
  fi
done

mkdir -p "$output/obj" "$output/bin" "$output/logs"
log="$output/logs/${role}-build.log"
exec > >(tee "$log") 2>&1

{
  printf 'source_commit\t%s\n' "$source_commit"
  printf 'source_tree\t%s\n' "$source_tree"
  printf 'source_identity_basis\t%s\n' "$source_identity_basis"
  printf 'platform\tlinux\n'
  printf 'role\t%s\n' "$role"
  printf 'source\t%s\n' "$source_file"
  printf 'binary\t%s\n' "$binary"
} | tee "$output/build-identity.tsv"
printf '%s\n' "${definitions[@]}" | tee "$output/compile-definitions.txt"

artifact="$output/bin/$binary"
if [[ $role == operator ]]; then
  command -v python3
  python3 -VV | tee "$output/dependencies.tsv"
  python3 - <<'PY' | tee -a "$output/dependencies.tsv"
import cryptography
import sqlite3
print("cryptography\t" + cryptography.__version__)
print("sqlite\t" + sqlite3.sqlite_version)
PY
  install -m 0755 "$src/$source_file" "$artifact"
  mkdir -p "$output/config"
  install -m 0644 \
    "$src/pkg/reverse-proxy/veld-public-services.nginx.conf.template" \
    "$output/config/veld-public-services.nginx.conf.template"
  PYTHONPYCACHEPREFIX="$output/obj/pycache" \
    python3 -m py_compile "$artifact"
  sha256sum "$output/config/veld-public-services.nginx.conf.template" \
    | tee "$output/operator-config-sha256.txt"
else
  command -v gcc
  gcc --version
  command -v g++
  g++ --version
  command -v ld
  ld --version | sed -n '1,2p'
  command -v openssl
  openssl version -a
  openssl_version=$(pkg-config --modversion openssl)
  dpkg --compare-versions "$openssl_version" ge 3.0 || {
    echo "Linux desktop transport requires OpenSSL >= 3.0; found $openssl_version" >&2
    exit 2
  }
  dpkg-query -W -f='${Package}\t${Version}\n' \
    build-essential gcc g++ binutils libc6-dev libleveldb-dev libssl-dev openssl pkg-config 2>/dev/null \
    | sort | tee "$output/dependencies.tsv"

  mapfile -t c_sources < <(grep -Ev '^[[:space:]]*(#|$)' \
    "$src/vendor/pqc/provenance/release-c-sources.txt")
  objects=()
  for index in "${!c_sources[@]}"; do
    rel=${c_sources[$index]}
    obj="$output/obj/${index}-$(basename "${rel%.c}").o"
    command=(gcc -std=c11 -O2 -DNDEBUG -I"$src/vendor/pqc" \
      -I"$src/vendor/pqc/mldsa65" -c "$src/$rel" -o "$obj")
    printf 'COMMAND'; printf ' %q' "${command[@]}"; printf '\n'
    "${command[@]}"
    objects+=("$obj")
  done

  libraries=(-lssl -lcrypto)
  [[ $role == keygen || $role == validator ]] || libraries+=(-lleveldb)
  command=(g++ -std=c++20 -O2 -DNDEBUG -pthread -I"$src/include" \
    -I"$src/vendor/pqc" -I"$src/vendor/pqc/mldsa65" \
    "${definitions[@]}" "$src/$source_file" "${objects[@]}" \
    "${libraries[@]}" -o "$artifact")
  printf 'COMMAND'; printf ' %q' "${command[@]}"; printf '\n'
  "${command[@]}"
fi

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
if [[ $role == desktop ]]; then
  cp "$src/third_party_licenses/Emscripten-LICENSE.txt" \
    "$third_party/licenses/Emscripten-LICENSE.txt"
fi

# Recheck exact source bytes immediately before artifact inspection/package
# handoff, so a mid-build source mutation cannot inherit the precompile proof.
python3 "$src/scripts/verify-pqc-provenance.py" \
  --root "$src" --release-role "$role" --package-dir "$third_party" \
  | tee "$output/pqc-provenance-prepackage.txt"

file "$artifact" | tee "$output/binary-file.txt"
if [[ $role != operator ]]; then
  readelf -h -l -d "$artifact" | tee "$output/binary-elf-metadata.txt"
fi
sha256sum "$artifact" | tee "$output/binary-sha256.txt"
"$artifact" --version | tee "$output/runtime-version.txt"
"$artifact" --deployment-info | tee "$output/deployment-info.txt"
grep -F 'veld-public-mainnet-v2' "$output/deployment-info.txt"
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
    grep -F '"remote_tls_backend":"openssl"' "$output/deployment-info.txt"
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
  operator)
    grep -F '"binary_role":"operator-portal"' "$output/deployment-info.txt"
    grep -F '"client_version":"3.0.0"' "$output/deployment-info.txt"
    grep -F '"public_gettxhistory_compiled":false' "$output/deployment-info.txt"
    grep -F '"snapshot_bootstrap_compiled":false' "$output/deployment-info.txt"
    grep -F '"upnp_compiled":false' "$output/deployment-info.txt"
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
  'veld-public-mainnet-v2|RTP1|RVS1|rolling-outpoint-v1|VELD_STATE_DIGEST_v8|Veld (Node|Desktop|Keygen|Validator|Operator)' \
  | sort -u | tee "$output/method-feature-inventory.txt" || true
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
  validator|operator)
    required_features=(veld-public-mainnet-v2)
    ;;
esac
for feature in "${required_features[@]}"; do
  grep -F "$feature" "$output/method-feature-inventory.txt"
done

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

printf 'PASS mainnet-v2-linux role=%s commit=%s tree=%s sha256=%s\n' \
  "$role" "$source_commit" "$source_tree" \
  "$(sha256sum "$artifact" | awk '{print $1}')"
