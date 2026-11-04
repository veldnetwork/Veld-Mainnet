#!/usr/bin/env bash
# Stage an unsigned Linux client candidate. Signing and publication are separate.
set -Eeuo pipefail
[[ $# == 1 ]] || { echo "usage: $0 EMPTY_OUTPUT_DIRECTORY" >&2; exit 2; }
src=$(realpath "$(dirname "$0")/..")
output=$(realpath -m "$1")
case "$output/" in "$src/"*) echo 'output must be outside source' >&2; exit 2;; esac
[[ ! -e "$output" ]] || [[ -d "$output" && -z $(find "$output" -mindepth 1 -maxdepth 1 -print -quit) ]] || exit 2
[[ $(git -C "$src" rev-parse --show-toplevel) == "$src" ]] || exit 2
[[ -z $(git -C "$src" status --short) ]] || { echo 'clean source worktree required' >&2; exit 2; }
commit=$(git -C "$src" rev-parse HEAD)
tree=$(git -C "$src" rev-parse 'HEAD^{tree}')

for role in node desktop pool-worker; do
  bash "$src/build/mainnet-v2-linux.sh" "$role" "$output/build/$role"
done

client="$output/client"
mkdir -p "$client/bin"
install -m 0755 "$output/build/node/bin/veld-node" "$client/bin/veld-node"
install -m 0755 "$output/build/desktop/bin/veld-desktop" "$client/bin/veld-desktop"
install -m 0755 "$output/build/pool-worker/bin/veld-pool-client" "$client/bin/veld-pool-client"
install -m 0755 "$src/pkg/linux/veld-wallet" "$client/bin/veld-wallet"
install -m 0755 "$src/pkg/linux/Install Wallet.sh" "$client/Install Wallet.sh"
install -m 0755 "$src/pkg/linux/Start Wallet.sh" "$client/Start Wallet.sh"
mkdir -p "$client/share/icons"
install -m 0644 "$src/resources/veld-wallet-icon.svg" "$client/share/icons/veld-wallet.svg"
install -m 0644 "$src/docs/operations/linux-wallet.md" "$client/LINUX-WALLET.md"
install -m 0644 "$src/docs/operations/address-only-mining.md" "$client/ADDRESS-ONLY-MINING.md"
cp -a "$output/build/desktop/third-party" "$client/third-party"
install -m 0644 "$src/LICENSE" "$client/LICENSE.txt"
install -m 0644 "$src/docs/operations/pool-mining.md" "$client/POOL-MINING.md"
printf 'source_commit\t%s\nsource_tree\t%s\nplatform\tlinux-x86_64\nstatus\tunsigned\n' \
  "$commit" "$tree" >"$client/BUILD-IDENTITY.tsv"
(cd "$client" && find . -type f ! -name 'UNSIGNED-SHA256SUMS.txt' -printf '%P\0' | sort -z | xargs -0 sha256sum) \
  >"$client/UNSIGNED-SHA256SUMS.txt"
python3 "$src/tests/linux_pool_client_cli_tests.py" "$client/bin/veld-pool-client"
[[ $(git -C "$src" rev-parse HEAD) == "$commit" && \
   $(git -C "$src" rev-parse 'HEAD^{tree}') == "$tree" && \
   -z $(git -C "$src" status --short) ]] || { echo 'source changed during build' >&2; exit 1; }
echo "PASS unsigned Linux client candidate with wallet launcher and pool mining: $client"
