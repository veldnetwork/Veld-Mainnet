'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const c=require('../website/topology-constellation-v1.js');
const id=i=>String(18446744073709551000n+BigInt(i));
for(const count of [0,1,21,64,128,512])for(const width of [240,393,1024]){
 const p=c.layout(count,width,390);assert.equal(p.length,count);
 assert(p.every(q=>q.x>=12&&q.x<=width-12&&q.y>=12&&q.y<=378));
 if(count)assert.equal(c.nearest(p,p[0].x,p[0].y),0);
 assert.equal(c.nearest(p,-100,-100),-1);
}
const raw={nodes:[{id:id(1),role:'miner',tip_state:'exact'},{id:id(2),role:'node',tip_state:'differs'},{id:id(3),role:'validator',tip_state:'stale'}],edges:[{first:id(1),second:id(2),confirmed:true},{first:id(1),second:id(3),confirmed:false}]};
const original=JSON.stringify(raw),s=c.scene(raw,id(1),393);
assert.equal(s.links.length,2);assert.equal(s.data.nodes.length,3);assert.equal(s.node.id,id(1));
assert.match(s.svg,/vc-differs/);assert.match(s.svg,/vc-unknown/);assert.match(s.svg,/vc-one/);
assert.doesNotMatch(s.svg,/184467|address|127\.0\.0/);
const reordered={nodes:[...raw.nodes].reverse(),edges:[...raw.edges].reverse().map(e=>({...e,first:e.second,second:e.first}))};
const refreshed=c.scene(reordered,id(1),393);
assert.deepEqual(refreshed.data.nodes,s.data.nodes);assert.deepEqual(refreshed.points,s.points);assert.equal(refreshed.node.id,s.node.id);
assert.deepEqual([...refreshed.links].sort((a,b)=>a.b.localeCompare(b.b)),[...s.links].sort((a,b)=>a.b.localeCompare(b.b)));assert.equal(JSON.stringify(raw),original);
const invalid={nodes:[...raw.nodes,raw.nodes[0],{id:18446744073709551001,role:'miner'},{id:'0'},{id:'18446744073709551616'},{id:'4',role:'<img onerror=x>',tip_state:'<script>'}],edges:[...raw.edges,{first:id(2),second:id(1),confirmed:false},{first:'4',second:'4'},{first:'5',second:'4'}]};
const clean=c.scene(invalid,id(1),393);assert.equal(clean.data.nodes.length,4);assert.equal(clean.links.length,2);assert.doesNotMatch(clean.svg,/<img|<script>|onerror/);
const source=fs.readFileSync(path.join(__dirname,'../src/veld-miner-portal.py'),'utf8').replace(/\r\n/g,'\n').split('PORTAL_HTML = r"""')[1].split('"""')[0];
for(const file of ['topology-constellation-v1.js','topology-portal-v1.js','topology-constellation-v1.css'])assert(source.includes(fs.readFileSync(path.join(__dirname,'../website',file),'utf8').replace(/\r\n/g,'\n').trim()),file+' embedded source matches');
if(process.argv[2]){
 const native=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
 for(const row of native){const expected=c.layout(row.count,row.width,row.height);row.points.forEach((p,i)=>{assert(Math.abs(p[0]-expected[i].x)<1e-8);assert(Math.abs(p[1]-expected[i].y)<1e-8)})}
}
console.log('PASS bounded layout, lossless IDs, selection, edge integrity, sanitization, source parity and native geometry');
