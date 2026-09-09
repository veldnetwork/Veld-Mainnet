'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require('node:path').join(__dirname,'../src/veld-miner-portal.py'),'utf8');
const script=source.split('PORTAL_HTML = r"""')[1].split('"""')[0].match(/<script\b[^>]*>([\s\S]*?)<\/script>/)[1];
new vm.Script(script);
const {extractFunction}=require('./javascript_function_source.js');
const context=vm.createContext({});
for(const name of ['esc','n','metric','spark','overview','mining','workers']) {
    const needle='function '+name+'(',start=script.indexOf(needle);
    assert(start>=0 && start===script.lastIndexOf(needle));
    vm.runInContext(extractFunction(script.slice(start),name),context);
}
assert.equal(context.n(null),'—');assert.equal(context.n(undefined),'—');assert.equal(context.n(0),'0');
const chart=context.spark([{height:3},{height:null},{height:4},{height:0}],'height','History');
assert.equal((chart.match(/<polyline/g)||[]).length,2,'Unknown samples break traces');
assert.match(chart,/0<\/text>/,'An observed zero remains plotted');
assert.match(context.spark([{height:null},{height:null}],'height','History'),/two known readings/);
const d={height:null,hashrate:null,sync_lag:null,peers:null,workers:2,blocks:null,gui_version:'3.0.5',daemon_version:'3.1.1',history:[],mining_state:'Warning'};
const s={mining_active:null,mining_ready:null,total_hashes:null,configured_workers:2};
const overview=context.overview(d,s);
assert.match(overview,/GUI version/);assert.match(overview,/Daemon version/);assert.match(overview,/v3.0.5/);assert.match(overview,/v3.1.1/);
assert.doesNotMatch(overview,/100.0%|<b>Validated<\/b>/);
assert.match(context.mining(d,s),/Unknown/);
const workers=context.workers(d,s);assert.match(workers,/Unknown/);assert.doesNotMatch(workers,/Paused|Waiting|0 H\/s/);
console.log('PASS portal diagnostics rendering: unknown, zero, separated versions, interrupted history');
