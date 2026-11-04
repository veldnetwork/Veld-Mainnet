#!/bin/sh
set -eu
package=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$package/bin/veld-wallet" open
