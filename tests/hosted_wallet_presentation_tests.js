'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const root=path.resolve(__dirname,'..'),dir=path.join(root,'website','hosted-wallet');
const source=fs.readFileSync(path.join(root,'include','network','ui_desktop.h'),'utf8');
const native=source.split('R"HTMLEOF(')[1].split(')HTMLEOF"')[0];
const overlay=fs.readFileSync(path.join(dir,'presentation.conf'),'utf8');
let rendered=native,count=0;
for(const match of overlay.matchAll(/^sub_filter '([^']*)' '([^']*)';$/gm)){
 assert(['</head>','</body>','<span>Earnings</span>'].includes(match[1]),'Only static insertion/label rules are permitted');
 rendered=rendered.split(match[1]).join(match[2]);count++;
}
assert.equal(count,3);
const scripts=html=>[...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m=>m[1]).filter(Boolean);
assert.deepEqual(scripts(rendered),scripts(native),'Hosted overlay must never rewrite native JavaScript');
for(const text of scripts(rendered))new vm.Script(text);
for(const [name,expected] of Object.entries(JSON.parse(fs.readFileSync(path.join(dir,'asset-sha256.json'),'utf8')))){
 const data=fs.readFileSync(path.join(dir,name));assert.equal(crypto.createHash('sha256').update(data).digest('hex'),expected,name);
 if(name.endsWith('.js'))new vm.Script(data.toString('utf8'),{filename:name});
}
const bootstrap=fs.readFileSync(path.join(root,'website','wallet-hosted-3.2.2.js'),'utf8');
for(const state of ['loading','complete']){
 let callback,calls=0;
 const context={window:{bvProbeNav(){calls++;}},document:{readyState:state,addEventListener(event,fn,options){assert.equal(event,'DOMContentLoaded');assert.equal(options.once,true);callback=fn;}}};
 vm.runInNewContext(bootstrap,context);assert.equal(calls,state==='complete'?1:0);if(callback)callback();assert.equal(calls,1);
}
vm.runInNewContext(bootstrap,{window:{},document:{readyState:'complete'}});
console.log('PASS hosted wallet static overlay, native script parity, captured assets and navigation bootstrap');
