'use strict';
// Exercise display behavior using reported mining, connection, and mapping data.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[2] || path.join(__dirname, '../src/veld-miner-portal.py'), 'utf8');
const html = source.includes('PORTAL_HTML = r"""') ? source.split('PORTAL_HTML = r"""')[1].split('"""')[0] : source;
const script = html.match(/<script\b[^>]*>([\s\S]*?)<\/script>/)[1];
new vm.Script(script);
function extract(name) {
  const start = script.indexOf('function ' + name + '(');
  assert(start >= 0, name + ' exists');
  const lineEnd = script.indexOf('\n', start);
  const end = script[lineEnd - 1] === '}' ? lineEnd : script.indexOf('\n}', start) + 2;
  return script.slice(start, end);
}
const context = vm.createContext({window: {matchMedia: () => ({matches: true})}, networkOverviewOpen: false});
vm.runInContext(['esc', 'metric', 'directNetworkState', 'inboundMapping', 'directTopologyGraph', 'topologyGraph', 'topologyRoles', 'network'].map(extract).join('\n'), context);
const device = {id: 1, name: 'Main PC', online: true, peers: 3, inbound: 0};
const snapshot = {process_running: true, mining_enabled: true, mining_active: true,
  port_mapped: false, outbound: 3, exact_tip: 3, peer_roles: {fleet: 3},
  topology: {local_id: '18446744073709551601', nodes: [
    {id: '18446744073709551602', role: 'node', role_index: 0, tip_state: 'exact'},
    {id: '18446744073709551603', role: 'miner', role_index: 1, tip_state: 'exact'}
  ], edges: [], eligible_nodes: 2, reporting_nodes: 1}};
const original = JSON.stringify(snapshot);
let output = context.network(device, snapshot);
assert.match(output, /This miner/);
assert.match(output, /Main PC · Miner/);
assert.match(output, /3 reported direct peers/);
assert.match(output, /Fleet peers/);
assert.match(output, /Hashing/);
assert.match(output, /Not mapped/);
assert.match(output, /Outbound peers are connected/);
assert.doesNotMatch(output, /Unavailable|Status unavailable|Node 01/);
assert.equal((output.match(/class="link"/g) || []).length, 1, 'Three fleet sessions are one explicitly counted role group');
assert.equal(JSON.stringify(snapshot), original, 'Rendering does not mutate public identities or raw telemetry');

context.networkOverviewOpen = true;
output = context.network(device, snapshot);
assert.match(output, /Network overview/);
assert.match(output, /Node 01/, 'An unrelated public node is not renamed to a miner');
assert.match(output, /Miner 01/);
assert.match(context.network(device, snapshot), /aria-expanded="true"/, 'Refresh preserves expanded overview');
assert.equal(snapshot.topology.nodes[0].role, 'node');

assert.equal(context.inboundMapping(device, {...snapshot, port_mapped: true}).value, 'Mapped');
assert.equal(context.inboundMapping(device, {...snapshot, port_mapped: undefined}).value, 'Not reported');
assert.match(context.inboundMapping({...device, inbound: 1}, snapshot).detail, /Inbound peers are connected/);
assert.equal(context.inboundMapping({...device, online: false}, snapshot).value, 'Not current');
assert.equal(context.inboundMapping(device, {...snapshot, process_running: false}).value, 'Not running');
assert.doesNotMatch(context.inboundMapping({...device, peers: 0}, {...snapshot, outbound: 0}).detail, /^Outbound peers are connected/);

output = context.directTopologyGraph({...device, online: false}, snapshot);
assert.match(output, /Waiting for a fresh report/);
assert.doesNotMatch(output, /Hashing|class="link"/);
output = context.directTopologyGraph(device, {...snapshot, process_running: false});
assert.match(output, /Stopped/);
assert.doesNotMatch(output, /class="link"/);
output = context.directTopologyGraph(device, {...snapshot, mining_enabled: false, mining_active: false});
assert.match(output, /This node/);
assert.doesNotMatch(output, /This miner/);
assert.match(context.directTopologyGraph(device, {...snapshot, mining_enabled: false, mining_active: true}), /This miner/);

let state = context.directNetworkState(device, {...snapshot, peer_roles: {fleet: 1}});
assert.equal(state.groups.find(g => g.role === 'unknown').count, 2, 'Unclassified direct peers stay unknown');
state = context.directNetworkState(device, {...snapshot, peer_roles: {fleet: 4}});
assert.equal(state.groups.length, 1);
assert.equal(state.groups[0].role, 'unknown', 'Conflicting counts cannot invent peer identities');
assert.equal(state.groups[0].count, 3);
assert.equal(context.directNetworkState({...device, peers: 0}, snapshot).groups.length, 0);
output = context.network({...device, name: '<img src=x onerror=alert(1)>'}, snapshot);
assert.doesNotMatch(output, /<img/);
assert.match(output, /&lt;img/);
assert.equal(JSON.stringify(snapshot), original);
console.log('PASS portal network status: miner role, public identity separation, mapping, freshness, stopped state, role counts, and escaping');
