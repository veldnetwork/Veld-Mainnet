/* One-command Windows browser qualification. Node + Playwright + Edge;
 * WSL Ubuntu supplies Python and OpenSSL. No production endpoints or keys.
 */
'use strict';
const fs=require('fs'),path=require('path'),{spawn}=require('child_process'),assert=require('assert/strict'),https=require('https');
const output=path.resolve(process.argv[2]||''),port=process.argv[3]||'34648';
assert(process.platform==='win32','This launcher exercises native Windows Edge with a WSL fixture.');
assert(process.argv[2]&&/^[1-9][0-9]{3,4}$/.test(port)&&Number(port)<=65535,'OUTPUT_DIRECTORY [PORT] required');
assert(!fs.existsSync(output),'Use a new evidence directory.');fs.mkdirSync(output,{recursive:true});
const source=path.resolve(__dirname,'../..');
function linux(p){assert(/^[A-Za-z]:[\\/]/.test(p),'An absolute local Windows drive path is required.');return '/mnt/'+p[0].toLowerCase()+p.slice(2).replaceAll('\\','/');}
const log=fs.openSync(path.join(output,'fixture.log'),'w');
const fixture=spawn('wsl.exe',['-d','Ubuntu','--cd',linux(source),'--','python3','-m','pool.qualification.website_fixture','--output',linux(output),'--port',port],{windowsHide:true,stdio:['ignore',log,log]});
let fixtureError=null,fixtureExit=null;fixture.on('error',e=>fixtureError=e);fixture.on('exit',(code,signal)=>fixtureExit={code,signal});
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
(async()=>{
 let code=1;
 try{
  const ready=path.join(output,'fixture-access.json'),deadline=Date.now()+30000;
  while(!fs.existsSync(ready)||!fs.existsSync(path.join(output,'fixture-ca.crt'))){if(fixtureError)throw fixtureError;if(fixtureExit)throw Error('Fixture exited; inspect fixture.log');assert(Date.now()<deadline,'Fixture readiness deadline');await delay(100);}
  // WSL publishes its loopback listener to Windows asynchronously. File readiness
  // alone does not prove the browser can reach the authenticated TLS endpoint.
  let reached=false;
  while(!reached){
   reached=await new Promise(resolve=>{
    const r=https.get('https://localhost:'+port+'/v1/public',{ca:fs.readFileSync(path.join(output,'fixture-ca.crt')),rejectUnauthorized:true,timeout:1000},res=>{res.resume();resolve(res.statusCode===200);});
    r.on('error',()=>resolve(false));r.on('timeout',()=>r.destroy(Error('readiness timeout')));
   });
   if(!reached){if(fixtureExit)throw Error('Fixture exited during TLS readiness');assert(Date.now()<deadline,'TLS readiness deadline');await delay(100);}
  }
  const child=spawn(process.execPath,[path.join(__dirname,'public_dashboard.cjs'),'https://localhost:'+port,ready,path.join(output,'fixture-ca.crt'),path.join(output,'browser')],{windowsHide:true,stdio:'inherit'});
  code=await new Promise((resolve,reject)=>{child.on('exit',c=>resolve(c??1));child.on('error',reject);});
 }catch(e){console.error(String(e));}
 finally{
  fs.writeFileSync(path.join(output,'stop-fixture'),'stop\n');const deadline=Date.now()+20000;
  while(fixtureExit===null&&!fixtureError&&Date.now()<deadline)await delay(100);
  fs.closeSync(log);
  if(fixtureExit===null){console.error('Fixture did not acknowledge shutdown. Inspect fixture.log; do not claim clean completion.');code=1;}
  fs.writeFileSync(path.join(output,'launcher.json'),JSON.stringify({status:code===0?'PASS_SCOPED_WEBSITE':'FAILED',fixture_exit:fixtureExit,source,synthetic_accounting:true,production_changed:false,finished_utc:new Date().toISOString()},null,2));
  process.exitCode=code;
 }
})();
