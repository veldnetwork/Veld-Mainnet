const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
const start = source.indexOf('    // APR estimate:');
const end = source.indexOf('    var stakers = d.stakers || [];', start);
assert(start > 0 && end > start);
const code = source.slice(start, end);
let checks = 0;
function render(data, active = true) {
  const label = { textContent: '' };
  vm.runInNewContext(code, {
    d: data, active, staked: 2000, vault: 21000,
    document: { getElementById: () => label },
    fmt: (value, digits) => value.toFixed(digits),
  });
  return label.textContent;
}
for (const [data, expected] of [
  [{ stakers: [{ payout_veld: 0 }] }, '0.0%'],
  [{ stakers: [{ payout_veld: '0.00000000' }] }, '0.0%'],
  [{ stakers: [{ payout_veld: 0.5 }, { payout_veld: 0.5 }] }, '18.3%'],
  // A 100 VELD budget is not a 100 VELD ordinary-staker payout when escrow
  // receives 80 VELD or concentration caps leave funds in the vault.
  [{ distributable_veld: 100, stakers: [{ payout_veld: 20 }] }, '365.0%'],
  [{ distributable_veld: 100, stakers: [{ payout_veld: 75 }] }, '1368.8%'],
  [{ stakers: [{ payout_veld: 1000 }] }, '18250.0%'],
  [{}, 'Unavailable'],
  [{ stakers: [] }, 'Unavailable'],
  [{ stakers: [{ payout_veld: 'invalid' }] }, 'Unavailable'],
  [{ stakers: [{ payout_veld: -1 }] }, 'Unavailable'],
  [{ stakers: [{ payout_veld: null }] }, 'Unavailable'],
  [{ stakers: [{ payout_veld: '' }] }, 'Unavailable'],
  [{ stakers: [{ payout_veld: true }] }, 'Unavailable'],
  [{ stakers: [{ payout_veld: 1 }, {}] }, 'Unavailable'],
]) {
  assert.equal(render(data), expected);
  checks++;
}
assert.equal(render({ distributable_veld: 1000 }, false), 'N/A');
checks++;
// Optional actual RPC receipts from the funded native journey.
if (process.argv[2]) {
  for (const name of fs.readdirSync(process.argv[2]).filter(n => n.endsWith('-getstakinginfo.json'))) {
    const response = JSON.parse(fs.readFileSync(path.join(process.argv[2], name), 'utf8'));
    assert.equal(response.result.budget_is_estimate, true);
    const units = response.result.stakers.reduce((sum, row) => sum + BigInt(row.payout_units), 0n);
    assert.equal(render(response.result), (Number(units) / 1e8 * 365 / 2000 * 100).toFixed(1) + '%');
    checks++;
  }
}
console.log(JSON.stringify({ status: 'PASS_WALLET_VAULT_ESTIMATE', checks }));
