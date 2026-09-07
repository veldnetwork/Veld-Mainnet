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
const context = vm.createContext({window: {matchMedia: () => ({matches: true})}});
vm.runInContext(['esc', 'metric', 'inboundMapping', 'topologyGraph', 'topologyRoles', 'network'].map(extract).join('\n'), context);
const device = {id: 1, name: 'Main PC', online: true, peers: 3, inbound: 0};
const id = i => String(18446744073709551000n + BigInt(i));
const nodes = [1,2,3].map(i => ({id:id(i),role:'fleet',role_index:i,tip_state:'exact'}))
  .concat([1,2,3,4,5,6].map(i => ({id:id(i+3),role:'miner',role_index:i,tip_state:'exact'})));
const edges = nodes.slice(1).map(peer => ({first:nodes[0].id,second:peer.id,confirmed:peer.role==='fleet'}));
const snapshot = {process_running:true,mining_enabled:true,mining_active:true,
  port_mapped:false,outbound:3,exact_tip:3,peer_roles:{fleet:3},
  topology:{local_id:'',nodes,edges,eligible_nodes:9,reporting_nodes:3}};
const original = JSON.stringify(snapshot);
function checkFullNetwork(output) {
  assert.equal((output.match(/aria-label="Sanitized Veld peer topology"/g)||[]).length,1,'Exactly one full network graph');
  assert.equal((output.match(/<g class="peer /g)||[]).length,9,'All reported network identities remain visible');
  assert.equal((output.match(/<path class="edge /g)||[]).length,8,'All reported links remain visible');
  for (let i=1;i<=6;i++) assert.match(output,new RegExp('Miner 0'+i));
  for (let i=1;i<=3;i++) assert.match(output,new RegExp('Fleet 0'+i));
  assert.match(output,/3 direct · 3 \/ 9 reporting/);
  assert.match(output,/<b>6<\/b><span>Miners/);
  assert.match(output,/<b>0<\/b><span>Nodes/);
  assert.doesNotMatch(output,/Your connections|Network overview|This miner|network-overview|aria-expanded|Node 01/);
}
let output = context.network(device,snapshot);
checkFullNetwork(output);
checkFullNetwork(context.network(device,snapshot));
checkFullNetwork(context.network({...device,id:2,name:'Laptop'},snapshot));
assert.match(output,/Not mapped/);
assert.match(output,/Outbound peers are connected/);
assert.doesNotMatch(output,/Unavailable|Status unavailable/);
assert.equal(JSON.stringify(snapshot),original,'Rendering must not mutate telemetry');

const actualNode = {...snapshot,topology:{...snapshot.topology,nodes:[...nodes,{id:id(10),role:'node',role_index:1,tip_state:'exact'}],eligible_nodes:10}};
output=context.network(device,actualNode);
assert.match(output,/Node 01/,'A real reported node must not be relabeled as a miner');
assert.match(output,/<b>1<\/b><span>Nodes/);
assert.match(output,/<b>6<\/b><span>Miners/);
assert.equal(context.topologyRoles({nodes:[...nodes,nodes[0]]}).fleet,3,'Duplicate identities do not inflate role counts');

assert.equal(context.inboundMapping(device,{...snapshot,port_mapped:true}).value,'Mapped');
assert.equal(context.inboundMapping(device,{...snapshot,port_mapped:undefined}).value,'Not reported');
assert.match(context.inboundMapping({...device,inbound:1},snapshot).detail,/Inbound peers are connected/);
assert.equal(context.inboundMapping({...device,online:false},snapshot).value,'Not current');
assert.equal(context.inboundMapping(device,{...snapshot,process_running:false}).value,'Not running');
assert.doesNotMatch(context.inboundMapping({...device,peers:0},{...snapshot,outbound:0}).detail,/^Outbound peers are connected/);
assert.match(context.network(device,{}),/Network map appears when this client reports topology data/);
output=context.topologyGraph({nodes:[{id:id(11),role:'<img src=x onerror=alert(1)>',tip_state:'<script>'}],edges:[]});
assert.doesNotMatch(output,/<img|<script>/);
assert.match(output,/&lt;img/);
assert.equal(JSON.stringify(snapshot),original);
console.log('PASS portal network: single full graph, all identities and links, miner labels, genuine node roles, refresh, machine switch, mapping and escaping');
