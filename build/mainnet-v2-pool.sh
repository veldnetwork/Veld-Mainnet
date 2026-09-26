#!/usr/bin/env bash
# Unsigned production-role artifact construction only. This never installs,
# starts services, signs releases, enrolls identities, or connects to a chain.
set -Eeuo pipefail
[[ $# == 1 ]] || { echo "usage: $0 EMPTY_OUTPUT_DIRECTORY" >&2; exit 2; }
src=$(realpath "$(dirname "$0")/..")
output=$(realpath -m "$1")
case "$output/" in "$src/"*) echo 'output must be outside source' >&2; exit 2;; esac
[[ ! -e "$output" ]] || [[ -d "$output" && -z $(find "$output" -mindepth 1 -maxdepth 1 -print -quit) ]] || exit 2
[[ $(git -C "$src" rev-parse --show-toplevel) == "$src" ]] || { echo 'verified Git worktree required' >&2; exit 2; }
[[ -z $(git -C "$src" status --short) ]] || { echo 'refusing a dirty source worktree' >&2; exit 2; }
commit=$(git -C "$src" rev-parse HEAD); tree=$(git -C "$src" rev-parse 'HEAD^{tree}')
git -C "$src" ls-files --error-unmatch build/mainnet-v2-pool.sh src/veld-pool-work.cpp src/veld-pool-client.cpp src/veld-pool-identity.cpp src/veld-pool-payout.cpp >/dev/null
# The dedicated backend retains the ordinary node's mining capability. Fleet
# remains a separate no-mine role and is never substituted for this backend.
bash "$src/build/mainnet-v2-linux.sh" node "$output/backend"
mkdir -p "$output/bin" "$output/logs" "$output/lib/pool"
cp "$output/backend/bin/veld-node" "$output/bin/veld-node"
exec > >(tee "$output/logs/pool-build.log") 2>&1
python3 "$src/scripts/verify-pqc-provenance.py" --root "$src" --release-role node
objects=("$output/backend/obj/"*.o)
for name in work client identity payout; do
  command=(g++ -std=c++20 -O2 -DNDEBUG -pthread -DVELD_MAINNET_POW -DVELD_PUBLIC_RELEASE -DVELD_PUBLIC_MAINNET
    -I"$src/include" -I"$src/vendor/pqc" -I"$src/vendor/pqc/mldsa65"
    "$src/src/veld-pool-$name.cpp" "${objects[@]}" -lssl -lcrypto -o "$output/bin/veld-pool-$name")
  printf 'COMMAND'; printf ' %q' "${command[@]}"; printf '\n'; "${command[@]}"
  "$output/bin/veld-pool-$name" --version >"$output/logs/$name-version.txt"
  "$output/bin/veld-pool-$name" --deployment-info >"$output/logs/$name-deployment.txt"
  python3 "$src/scripts/verify-release-version.py" --root "$src" --deployment-info "$output/logs/$name-deployment.txt"
  grep -F 'veld-public-mainnet-v2' "$output/logs/$name-deployment.txt"
  readelf -h -l -d "$output/bin/veld-pool-$name" >"$output/logs/$name-elf.txt"
done
for module in __init__ accounting admin backend coordinator gateway identity journal native node_service operator overview payments private_file protocol public_status records rewards service; do
  cp "$src/pool/$module.py" "$output/lib/pool/"
done
cp -r "$src/pool/web" "$output/lib/pool/web"
cp -r "$src/pool/admin_web" "$output/lib/pool/admin_web"
cp -r "$src/pkg/pool" "$output/setup"
cp "$src/docs/operations/pool-candidate.md" "$output/README.md"
cp -r "$output/backend/third-party" "$output/third-party"
python3 "$src/scripts/verify-python-package.py" "$output/lib"
python3 "$src/scripts/verify-pqc-provenance.py" --root "$src" --release-role node --package-dir "$output/third-party"
[[ $(git -C "$src" rev-parse HEAD) == "$commit" && $(git -C "$src" rev-parse 'HEAD^{tree}') == "$tree" && -z $(git -C "$src" status --short) ]] || { echo 'source changed during pool build' >&2; exit 1; }
printf 'source_commit\t%s\nsource_tree\t%s\nprofile\tveld-public-mainnet-v2\n' "$commit" "$tree" >"$output/source-identity.tsv"
(cd "$output" && find bin lib setup third-party -type f ! -path '*/__pycache__/*' -print0 | sort -z | xargs -0 sha256sum) >"$output/pool-sha256.txt"
echo 'PASS unsigned public-profile pool artifacts; installation and public launch are separate gates'
