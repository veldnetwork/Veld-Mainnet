#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
output=$(realpath -m -- "${1:?output directory required}")
mkdir -p -- "$output"
cd -- "$root"
python3 scripts/verify-pqc-provenance.py
objects=()
index=0
while IFS= read -r source; do
    [[ -n "$source" && "$source" != \#* ]] || continue
    object="$output/pqc-$index.o"
    cc -std=c11 -O2 -Ivendor/pqc -Ivendor/pqc/mldsa65 -c "$source" -o "$object"
    objects+=("$object")
    index=$((index+1))
done < vendor/pqc/provenance/release-c-sources.txt
c++ -std=c++20 -O2 -pthread -DVELD_MAINNET_POW -DVELD_PUBLIC_RELEASE -DVELD_PUBLIC_MAINNET \
    -Iinclude -Ivendor/pqc src/veld-checkpoint-tool.cpp "${objects[@]}" \
    -o "$output/veld-checkpoint-tool"
"$output/veld-checkpoint-tool" verify tests/fixtures/mainnet-checkpoint.json 1
