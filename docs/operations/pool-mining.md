# Pool mining with Veld Node

Use an official signed Veld client from [veld.network](https://veld.network/).
The public pool is available at [pool.veld.network](https://pool.veld.network/).

## Windows

1. Open Veld Node and select **Pool**.
2. Enter `https://pool.veld.network`, or another compatible HTTPS pool endpoint.
3. Enter **your own wallet's payout address**. Do not use the pool's operator address.
4. Choose a CPU worker count, leaving capacity for other applications.
5. Select **Start pool mining** and check that accepted work increases.

## Linux

Use a verified Linux client package containing `bin/veld-pool-client`. The
previous 3.2.8 Linux download does not contain this worker. From the extracted
package directory, run:

```sh
./bin/veld-pool-client --pool https://pool.veld.network \
  --payout YOUR_VELD_ADDRESS --threads 4 \
  --state-dir "$HOME/.local/share/veld/pool"
```

Replace the payout address with your own and adjust the worker count to leave
capacity for other applications. The pool worker connects over authenticated
HTTPS, retains its account in a private local directory, and needs no wallet
key, passphrase, running full node, or blockchain download. Press Ctrl+C to
stop. Inspect `pool-status.json` inside the private state directory for accepted
shares and balances. Keep `pool-account.json` private; it contains mining and
dashboard viewing credentials. A different endpoint or payout address needs a
different state directory.

For a source build, `build/mainnet-v2-linux.sh pool-worker OUTPUT_DIRECTORY`
produces the same worker from a clean worktree. A local build is unsigned;
verify an official signed package before using it with real earnings.

Members need no personal stake or deposit and must never provide a private key
or wallet passphrase to the pool. Multiple machines may use the same payout
address. Each device retains its own worker account and contribution history.

The configured worker count is the requested limit. The number currently hashing
can change while work is acquired, submitted, or retried. A temporary verification
delay is distinct from rejected work. Preserve the client profile when updating
so the device retains its account and viewing access.

## Balances and payment history

| Field | Meaning |
| --- | --- |
| Pending | Allocated income awaiting canonical maturity and spendability |
| Available | Matured entitlement available to a qualifying payout batch |
| In payment | Entitlement reserved in a durable payment intent |
| Paid | Payments confirmed on the canonical chain |

The published policy is a 0% service fee, a 1 VELD automatic payout
threshold by payout address, daily batches, and at least 120 canonical
confirmations plus actual spendability. Smaller balances remain recorded.
Daily processing does not guarantee daily earnings or a payment from each block.
Devices sharing a payout address may display different per-account balances.

Select **Copy view access** in the client's Pool tab and use it with the dashboard
to view private account details. A payout address alone grants no access. Treat
viewing access as a private credential; do not post it in support channels.

Block rewards, lottery winnings, and ordinary pool-stake yield are separate
income categories. Only actual pool receipts create shared rewards. Pool
co-mining requires the operator's separately funded 1,000 VELD stake and fee
funds. Members do not supply those funds.

## Stop, reconnect, and update

**Stop pool mining** clears automatic pool-resume intent. Disconnecting does not
erase earned balances. Solo mining remains available through the Mining tab;
confirm the active mode before starting workers.

Enable **Settings → Release and updates → Automatic updates** on each PC.
Keep Veld open for hourly signed-update checks. Normal Windows reboot behavior
is separate; see [automatic updates](automatic-updates.md).
