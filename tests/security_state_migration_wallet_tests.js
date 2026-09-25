'use strict';
const fs=require('fs'), vm=require('vm'), assert=require('assert');
const source=fs.readFileSync('include/network/ui_desktop.h','utf8');
const name='_veldGovernanceProposalChallenge';
const start=source.indexOf('function '+name+'(');
assert(start>=0);
let open=source.indexOf('{',start), depth=1, end=open+1;
while(depth && end<source.length) {
  if(source[end]==='{') ++depth;
  if(source[end]==='}') --depth;
  ++end;
}
const context={TextEncoder};
vm.createContext(context);
vm.runInContext(source.slice(start,end),context);
const challenge=context[name];
const fields=['general','ordinary-address','Budget café | phase:2','Ordinary UTF-8 proposal.','2879'];
const prefix='VELD_GOV|M|fixture-genesis|';
const reference=prefix+'GOV_PROPOSAL_V2:'+fields.map(f=>Buffer.byteLength(f,'utf8')+':'+f).join('');
assert.strictEqual(challenge(prefix,...fields.slice(0,4),2879,true),reference);
assert.strictEqual(challenge(prefix,...fields.slice(0,4),2879,false),
  prefix+'GOV_PROPOSAL:general:Budget café | phase:2|Ordinary UTF-8 proposal.:@2879');
assert.notStrictEqual(challenge(prefix,'general','ordinary-address','A|B','C',2880,true),
  challenge(prefix,'general','ordinary-address','A','B|C',2880,true));
assert(source.includes("fields[1] !== proposalIntent.marker"));
assert(source.includes("fields[6] !== '0'"));
assert(source.includes("info.gov_proposal_version === 2"));
console.log('PASS security_state_migration_wallet_tests UTF8_framing=PASS legacy_framing=PASS prepared_marker_binding=PASS');
