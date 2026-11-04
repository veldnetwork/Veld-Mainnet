'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../include/network/ui_desktop.h'), 'utf8');
function extract(name) {
  let begin = source.indexOf('function ' + name + '(');
  if (source.slice(begin - 6, begin) === 'async ') begin -= 6;
  assert(begin >= 0);
  const end = source.indexOf('\n}', begin);
  assert(end > begin);
  return source.slice(begin, end + 2);
}
let parsed = 0;
const context = vm.createContext({
  _veldParseUnsignedTx: () => { ++parsed; return {outputs: []}; }
});
vm.runInContext(extract('bvDisplayPoolPrice') + '\n' + extract('_veldAssertOpReturnExact'), context);
const price = context.bvDisplayPoolPrice;
assert.equal(price({price_veld_per_btcveld: 1.25}), 1.25);
assert.equal(price({reserve_veld: 100, reserve_btcveld: 4}), 25);
assert.equal(price({price_veld_per_btcveld: 'ordinary text'}), 0);
assert.equal(price({price_veld_per_btcveld: Infinity}), 0);
assert.equal(price({reserve_veld: 100, reserve_btcveld: 0}), 0);
assert.equal(price(null), 0);
for (const missing of [undefined, null, 0]) {
  assert.throws(() => context._veldAssertOpReturnExact({unsigned_tx_hex: ''}, missing), /missing local/);
}
assert.equal(parsed, 0);
context._veldAssertOpReturnExact({unsigned_tx_hex: ''}, '');
assert.equal(parsed, 1);
// Parser is mocked here: this checks the local intent contract only and never
// constructs a transaction, signs, broadcasts or supplies executable markup.
assert(source.includes("escHtml(price?price.toLocaleString('en-US'):'—')"));
assert(source.includes("escHtml(_feeTxt)"));
console.log('PASS: numeric display values and explicit local signing policy');

vm.runInContext(extract('_veldGovernanceVoteIntent'), context);
const voteIdentity = '1'.repeat(64);
const govInfo = {blocks: 1920, gov_chain_prefix: 'chain|', gov_vote_version: 2};
const govIntent = context._veldGovernanceVoteIntent(govInfo,
  {id: 1, vote_identity: voteIdentity}, '1', 'yes');
assert.equal(govIntent.challenge, 'chain|GOV_VOTE_V2:1:' + voteIdentity + ':yes:@1920');
assert.equal(govIntent.marker, 'V2');
assert.equal(govIntent.identity, voteIdentity);
assert.throws(() => context._veldGovernanceVoteIntent(govInfo, {id: 1}, '1', 'yes'), /Refresh proposals/);
assert.throws(() => context._veldGovernanceVoteIntent({...govInfo, gov_vote_version: 3}, null, '1', 'yes'), /Unsupported/);
const legacyIntent = context._veldGovernanceVoteIntent({...govInfo, blocks: 1918, gov_vote_version: 1}, null, '1', 'yes');
assert.equal(legacyIntent.challenge, 'chain|GOV_VOTE:1:yes:@1918');
assert.equal(legacyIntent.identity, '');
console.log('PASS: versioned governance vote intent and ordinary legacy compatibility');

vm.runInContext(extract('_veldRecentSearch'), context);
context.setTimeout = (resolve) => resolve();
let attempts = 0, progressUpdates = 0;
context.rpc = async () => {
  if (++attempts === 1) {
    const error = new Error('ordinary incomplete lookup');
    error.code = -32005;
    throw error;
  }
  return {block_height: 7};
};
(async () => {
  const result = await context._veldRecentSearch('fixture', () => ++progressUpdates, () => true);
  assert.equal(result.block_height, 7);
  assert.equal(attempts, 2);
  assert.equal(progressUpdates, 1);
  console.log('PASS: search progress retries and ordinary completion');
})().catch(error => { console.error(error); process.exitCode = 1; });
