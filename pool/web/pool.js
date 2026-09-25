'use strict';
const el=id=>document.getElementById(id);
const MAINNET='7be77ab9e820bd9ffb60b269b45ced48288056e5839a1135fafc2f8557000a88';
const categories=[['mining','Block mining'],['comine_payout','Co-mining'],['staking_distribution','Staking yield']];
let credentials=null,generation=0,cursor=0,paged=false,refreshing=false,historyBusy=false,healthBusy=false,network=null;
const privateRequests=new Set();
function object(v){if(!v||typeof v!=='object'||Array.isArray(v))throw new Error('Invalid service report.');return v;}
function integer(v){if(typeof v!=='string'||!/^(0|[1-9][0-9]{0,79})$/.test(v))throw new Error('Invalid service report.');return BigInt(v);}
function bounded(v,max=1024){if(typeof v!=='string'||v.length>max)throw new Error('Invalid service report.');return v;}
function hash(v){if(typeof v!=='string'||!/^[a-f0-9]{64}$/.test(v))throw new Error('Invalid service report.');return v;}
function money(v,places=8,suffix=true){const n=integer(v),scale=10n**BigInt(8-places);return (n/100000000n).toLocaleString('en-US')+'.'+((n%100000000n)/scale).toString().padStart(places,'0')+(suffix?' VELD':'');}
function count(v){return integer(v).toLocaleString('en-US');}
function compactMoney(v){const n=integer(v);return n%100000000n===0n?(n/100000000n).toLocaleString('en-US')+' VELD':money(v,8);}
function text(id,value){el(id).textContent=value;}
function node(tag,value,className){const n=document.createElement(tag);if(value!==undefined)n.textContent=value;if(className)n.className=className;return n;}
function empty(id,message){const row=node('tr'),cell=node('td',message,'empty-state');cell.colSpan=4;row.append(cell);el(id).replaceChildren(row);}
function badge(value,label=value){return node('span',label,'status-badge '+value);}
function explorer(kind,id,label){
  const a=node(network===MAINNET?'a':'span',label);
  if(network===MAINNET){a.href='https://explorer.veld.network/'+kind+'/'+id;a.target='_blank';a.rel='noopener noreferrer';}
  return a;
}
async function call(action,payload,privateCall=false){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);
  if(privateCall)privateRequests.add(controller);
  try{
    const options={cache:'no-store',credentials:'omit',redirect:'error',signal:controller.signal};
    if(action!=='public'){options.method='POST';options.headers={'Content-Type':'application/json'};options.body=JSON.stringify(payload);}
    const response=await fetch('/v1/'+action,options);
    if(!(response.headers.get('content-type')||'').toLowerCase().startsWith('application/json'))throw new Error('Invalid service report.');
    if(Number(response.headers.get('content-length')||0)>16384)throw new Error('Service report exceeds the size limit.');
    const reader=response.body.getReader(),chunks=[];let size=0;
    try{for(;;){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>16384){await reader.cancel();throw new Error('Service report exceeds the size limit.');}chunks.push(part.value);}}finally{reader.releaseLock();}
    const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
    const data=object(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));
    if(!response.ok||data.ok!==true)throw new Error(data.retryable===true?'Service busy. Retrying shortly.':privateCall?'Access refused. Check your viewing access.':'Service report unavailable.');
    return object(data.result);
  }finally{clearTimeout(timer);privateRequests.delete(controller);}
}
function forget(){
  generation++;for(const request of privateRequests)request.abort();privateRequests.clear();
  credentials=null;cursor=0;paged=false;
  for(const id of ['access','account','token'])el(id).value='';
  el('private').hidden=true;el('payments').replaceChildren();el('reward-totals').replaceChildren();el('older').hidden=true;
  for(const id of ['address','account-updated','pending','available','reserved','paid','shares','payment-status','lottery','reward-policy','message'])text(id,'');
}
function accountReport(v){
  object(v);bounded(v.address,128);if(!/^V[A-Za-z0-9]{24,127}$/.test(v.address))throw new Error('Invalid account report.');
  integer(v.verified_shares);for(const k of ['pending','available','reserved','paid'])integer(v[k+'_units']);
  bounded(v.payment_status,100);bounded(v.lottery_status,1024);
  object(v.reward_totals);for(const [key]of categories)integer(v.reward_totals[key]??'0');
  if(v.reward_windows!==undefined){object(v.reward_windows);if(v.reward_windows.staking_yield!==undefined)bounded(v.reward_windows.staking_yield,1024);}
  return v;
}
function paymentReport(v,before){
  if(!Array.isArray(v.payments)||v.payments.length>20||!Number.isSafeInteger(v.next_before)||v.next_before<0||before&&v.next_before>=before)throw new Error('Invalid payment history.');
  for(const p of v.payments){object(p);integer(p.amount_units);const created=integer(p.created);if(created>253402300799n)throw new Error('Invalid payment date.');
    if(!['reserved','signed','confirmed'].includes(p.state))throw new Error('Invalid payment status.');if(p.txid!==null&&p.txid!==undefined)hash(p.txid);}
  return v;
}
async function payments(append=false){
  if(!credentials||historyBusy)return;historyBusy=true;el('older').disabled=true;
  const active=generation,before=append?cursor:0;
  try{
    const result=paymentReport(await call('history',{...credentials,before:String(before)},true),before);
    if(active!==generation||!credentials)return;
    const fragment=document.createDocumentFragment();
    for(const p of result.payments){
      const row=node('tr');row.append(node('td',new Date(Number(p.created)*1000).toLocaleString()),node('td',money(p.amount_units)));
      const status=node('td');status.append(badge(p.state,{reserved:'Preparing',signed:'Submitted / reconciling',confirmed:'Confirmed'}[p.state]));row.append(status);
      const tx=node('td');tx.append(p.txid?explorer('tx',p.txid,p.txid.slice(0,10)+'…'+p.txid.slice(-6)):node('span','Awaiting signature'));row.append(tx);fragment.append(row);
    }
    if(!append)el('payments').replaceChildren();
    el('payments').append(fragment);
    if(!el('payments').children.length)empty('payments','No payments yet. Your earned balance carries forward.');
    cursor=result.next_before;el('older').hidden=!cursor;if(append)paged=true;
  }finally{historyBusy=false;el('older').disabled=false;}
}
async function refresh(){
  if(!credentials||refreshing)return;refreshing=true;const active=generation;
  try{
    const report=accountReport(await call('account',credentials,true));
    if(active!==generation||!credentials)return;
    if(report.account!==credentials.account)throw new Error('Account identity mismatch.');
    text('address',report.address);for(const key of ['pending','available','reserved','paid'])text(key,money(report[key+'_units']));
    text('shares',count(report.verified_shares)+' shares');text('payment-status','Payments: '+report.payment_status+'.');
    text('lottery',report.lottery_status);text('reward-policy',report.reward_windows?.staking_yield||'');
    const fragment=document.createDocumentFragment();for(const [key,label]of categories){const card=node('div');card.append(node('span',label),node('strong',money(report.reward_totals[key]??'0')));fragment.append(card);}el('reward-totals').replaceChildren(fragment);
    el('private').hidden=false;text('account-updated','Updated '+new Date().toLocaleTimeString());text('message','Viewing this account. Keep your access private.');
    if(!paged)await payments();
  }catch(error){if(active===generation){text('message',error.name==='AbortError'?'Request timed out. Retrying shortly.':error.message);text('account-updated','Last report may be out of date.');}}
  finally{refreshing=false;}
}
function publicReport(v){
  object(v);hash(v.chain);for(const k of ['active_accounts','verified_shares'])integer(v[k]);if(v.reconciled_height!==null)integer(v.reconciled_height);
  if(typeof v.payments_enabled!=='boolean'||typeof v.co_mining_enabled!=='boolean')throw new Error('Invalid service flags.');
  if(!['Service responding','Reconciliation paused or starting'].includes(v.status))throw new Error('Invalid service status.');
  if(v.payment_policy){const p=object(v.payment_policy);for(const k of ['fee_ppm','minimum_units','batch_seconds','revision'])integer(p[k]);if(integer(p.fee_ppm)>100000n||integer(p.batch_seconds)<3600n||integer(p.batch_seconds)>604800n)throw new Error('Invalid payment policy.');}
  if(v.verification_queue){const q=object(v.verification_queue);for(const k of ['waiting','capacity'])if(!Number.isSafeInteger(q[k])||q[k]<0||q[k]>256)throw new Error('Invalid queue report.');}
  if(v.overview){
    const o=object(v.overview);if(o.version!==1)throw new Error('Unknown statistics format.');integer(o.blocks_won);
    object(o.reward_totals);for(const[k]of categories)integer(o.reward_totals[k]);
    object(o.payments);integer(o.payments.paid_units);integer(o.payments.confirmed_transactions);
    const w=object(o.work);integer(w.sample_shares);if(integer(w.window_seconds)>600n||w.bucket_seconds!=='10'||w.method!=='verified-expected-work'||typeof w.warming_up!=='boolean')throw new Error('Invalid hashrate report.');
    if(w.hashrate_hs!==null)integer(w.hashrate_hs);
    if(!Array.isArray(o.recent_blocks)||o.recent_blocks.length>12)throw new Error('Invalid block report.');
    for(const b of o.recent_blocks){object(b);hash(b.hash);integer(b.height);integer(b.amount_units);integer(b.confirmations);if(!['pending','available','orphaned'].includes(b.state))throw new Error('Invalid block status.');}
  }
  return v;
}
function rate(value){
  let n=integer(value),scale=1n,label='H/s';for(const [s,l]of [[1000000000000n,'TH/s'],[1000000000n,'GH/s'],[1000000n,'MH/s'],[1000n,'kH/s']])if(n>=s){scale=s;label=l;break;}
  return (n/scale).toLocaleString('en-US')+(scale>1n?'.'+(n%scale*100n/scale).toString().padStart(2,'0'):'')+' '+label;
}
function renderOverview(o){
  if(!o){for(const id of ['hashrate','blocks-won','total-paid','mining-total','comining-total','staking-total'])text(id,'—');text('hashrate-note','Statistics not reported');text('paid-note','Payment total not reported');empty('public-blocks','Block statistics are not reported by this service.');return;}
  text('blocks-won',count(o.blocks_won));text('total-paid',money(o.payments.paid_units,2,false));el('total-paid').title=money(o.payments.paid_units);
  text('paid-note',count(o.payments.confirmed_transactions)+' confirmed payment transactions');
  for(const[key,id]of [['mining','mining-total'],['comine_payout','comining-total'],['staking_distribution','staking-total']]){text(id,money(o.reward_totals[key],2,false));el(id).title=money(o.reward_totals[key]);}
  const w=o.work;text('hashrate',w.hashrate_hs===null?'Measuring…':rate(w.hashrate_hs));
  text('hashrate-note',w.warming_up?'Warming up · '+count(w.sample_shares)+' verified shares':count(w.sample_shares)+' shares · last '+w.window_seconds+' seconds');
  const fragment=document.createDocumentFragment();
  for(const b of o.recent_blocks){
    const row=node('tr'),identity=node('td'),link=explorer('block',b.hash,'#'+count(b.height));identity.append(link,node('small',b.hash.slice(0,7)+'…'+b.hash.slice(-5)));row.append(identity);
    const amount=node('td',money(b.amount_units,4));amount.title=money(b.amount_units);row.append(amount);
    const confirmations=node('td',count(b.confirmations),'confirmations'),progress=document.createElement('progress');progress.max=120;progress.value=Number(integer(b.confirmations)>120n?120n:integer(b.confirmations));progress.setAttribute('aria-label',b.confirmations+' confirmations; minimum 120');confirmations.append(progress);row.append(confirmations);
    const status=node('td');status.append(badge(b.state,{pending:'Maturing',available:'Mature',orphaned:'Orphaned'}[b.state]));row.append(status);
    [...row.children].forEach((cell,i)=>cell.dataset.label=['Block','Miner reward','Confirmations','Status'][i]);fragment.append(row);
  }
  el('public-blocks').replaceChildren(fragment);if(!o.recent_blocks.length)empty('public-blocks','No pool blocks recorded yet. Accepted work is tracked while we mine.');
}
async function health(){
  if(healthBusy)return;healthBusy=true;
  try{
    const v=publicReport(await call('public'));network=v.chain;
    text('network-label',network===MAINNET?'Mainnet':'Other network');text('chain',v.chain);
    text('health',v.status==='Service responding'?'Pool service online':'Reconciliation paused');
    el('status-light').className='status-light '+(v.status==='Service responding'?'online':'offline');
    text('updated','Updated '+new Date().toLocaleTimeString());text('active',count(v.active_accounts));text('height',v.reconciled_height===null?'Starting':count(v.reconciled_height));text('total-shares',count(v.verified_shares));
    text('queue',v.verification_queue?v.verification_queue.waiting+' / '+v.verification_queue.capacity:'Not reported');
    text('payments-enabled',v.payments_enabled?'Enabled':'Paused / not enabled');text('comining-enabled',v.co_mining_enabled?'Participating':'Not participating yet');
    text('comining-note',v.co_mining_enabled?'Co-mining is enabled. Only confirmed winnings create earnings.':'The pool needs 1,000 VELD staked to qualify. Lottery winnings and staking rewards are shared with contributors.');
    text('service-details','Service status reflects the pool’s last reconciliation.');text('data-message',v.status==='Service responding'?'':'Reconciliation is paused or starting. Balances and maturity may be delayed.');
    const p=v.payment_policy;
    if(p){const fee=integer(p.fee_ppm),percent=(fee/10000n)+'.'+(fee%10000n).toString().padStart(4,'0'),formatted=percent.replace(/\.?0+$/,'');text('fee',formatted+'%');text('minimum',compactMoney(p.minimum_units));text('schedule',p.batch_seconds==='86400'?'Daily':'Every '+Number(p.batch_seconds)/3600+'h');text('payment-policy',formatted+'% service fee · '+compactMoney(p.minimum_units)+' minimum per payout address · batches every '+Number(p.batch_seconds)/3600+' hours. Machines using the same address qualify together; account balances stay separate.');}
    else{for(const id of ['fee','minimum','schedule'])text(id,'—');text('payment-policy','Payment policy is not currently available.');}
    renderOverview(v.overview);
  }catch{
    text('health','Service unavailable');el('status-light').className='status-light offline';text('data-message','Live statistics could not be refreshed. Previous values may be stale; reconnecting automatically.');text('service-details','Do not rely on the last report until the connection recovers.');text('updated','Waiting for a fresh report');
  }finally{healthBusy=false;}
}
el('access').addEventListener('input',()=>{
  const copied=el('access').value;if(!copied)return;
  try{
    const access=object(JSON.parse(copied));
    if(Object.keys(access).sort().join(',')!=='account,endpoint,token'||typeof access.account!=='string'||typeof access.token!=='string'||typeof access.endpoint!=='string'||!/^[a-f0-9]{32}$/.test(access.account)||!/^[a-f0-9]{64}$/.test(access.token))throw new Error();
    const endpoint=new URL(access.endpoint);if(endpoint.origin!==location.origin||endpoint.username||endpoint.password||endpoint.search||endpoint.hash||endpoint.pathname!=='/')throw new Error();
    forget();el('account').value=access.account;el('token').value=access.token;text('message','Access ready. Select View my rewards.');
  }catch{forget();text('message','Access was not imported. Copy viewing access from this pool in your node.');}
});
el('login').addEventListener('submit',async event=>{
  event.preventDefault();
  const account=el('account').value.trim(),token=el('token').value.trim();
  if(!/^[a-f0-9]{32}$/.test(account)||!/^[a-f0-9]{64}$/.test(token)){text('message','Paste your viewing access or enter a valid account ID and viewing token.');return;}
  forget();credentials={account,token};el('view-account').disabled=true;
  // Aborted work from an older account finishes before a new refresh starts.
  try{while(refreshing||historyBusy)await new Promise(resolve=>setTimeout(resolve,20));if(credentials)await refresh();}finally{el('view-account').disabled=false;}
});
el('forget').addEventListener('click',forget);
el('older').addEventListener('click',async()=>{const active=generation;try{await payments(true);}catch(error){if(active===generation)text('message',error.name==='AbortError'?'Request timed out. Try again.':error.message);}});
text('endpoint',location.origin);
el('copy-endpoint').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(location.origin);text('copy-status','Endpoint copied.');}catch{text('copy-status','Select and copy the endpoint above.');}});
window.addEventListener('pagehide',forget);
document.addEventListener('visibilitychange',()=>{if(!document.hidden){health();refresh();}});
setInterval(()=>{if(!document.hidden){health();refresh();}},15000);health();
