'use strict';
const el = id => document.getElementById(id);
let credentials = null, cursor = 0, generation = 0, refreshing = false, historyBusy=false, paged=false, healthBusy=false;
function money(value) {
  if (typeof value!=='string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) throw new Error('Invalid balance response');
  const units = BigInt(value);
  return `${(units / 100000000n).toLocaleString('en-US')}.${(units % 100000000n).toString().padStart(8,'0')} VELD`;
}
async function call(action, payload) {
  const response = await fetch(`/v1/${action}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload), cache:'no-store', credentials:'omit', redirect:'error', signal:AbortSignal.timeout(20000)});
  const text = await response.text();
  if (text.length > 16384) throw new Error('Response exceeds limit');
  const result = JSON.parse(text);
  if (!result || typeof result!=='object' || Array.isArray(result)) throw new Error('Invalid service response');
  if (!response.ok || result.ok !== true) throw new Error(result.retryable ? 'Service busy. Try again shortly.' : 'Request refused. Check your account ID and viewing token.');
  if (!result.result || typeof result.result!=='object' || Array.isArray(result.result)) throw new Error('Invalid service response');
  return result.result;
}
function clearAccount() {
  generation++; credentials = null; cursor = 0; paged=false;
  el('access').value='';
  el('token').value = ''; el('account').value = ''; el('private').hidden = true;
  el('payments').replaceChildren(); el('reward-totals').replaceChildren(); el('address').textContent = ''; el('message').textContent = '';
}
async function payments(append=false) {
  if (!credentials || historyBusy) return;
  historyBusy=true;el('older').disabled=true;
  const active = generation;
  try {
  const result = await call('history',{...credentials,before:String(append ? cursor : 0)});
  if (active !== generation || !credentials) return;
  if (!Array.isArray(result.payments) || result.payments.length>50 || !Number.isSafeInteger(result.next_before) || result.next_before<0) throw new Error('Invalid payment history');
  if (!append) el('payments').replaceChildren();
  for (const payment of result.payments) {
    const row=document.createElement('tr');
    for (const value of [new Date(Number(payment.created)*1000).toLocaleString(),money(payment.amount_units),payment.state,payment.txid || 'Awaiting signature']) {
      const cell=document.createElement('td'); cell.textContent=value; row.appendChild(cell);
    }
    el('payments').appendChild(row);
  }
  if (!el('payments').children.length) {
    const row=document.createElement('tr'), cell=document.createElement('td');
    cell.colSpan=4; cell.textContent='No payments yet. Earned balances carry forward.'; row.appendChild(cell); el('payments').appendChild(row);
  }
  cursor=result.next_before; el('older').hidden=!cursor;
  if(append)paged=true;
  } finally {historyBusy=false;el('older').disabled=false;}
}
async function refresh() {
  if (!credentials || refreshing) return;
  refreshing=true; const active=generation;
  try {
    const account=await call('account',credentials);
    if (active!==generation || !credentials) return;
    el('address').textContent=account.address;
    for (const field of ['pending','available','reserved','paid']) el(field).textContent=money(account[`${field}_units`]);
    el('shares').textContent=account.verified_shares;
    el('payment-status').textContent=`Payments: ${account.payment_status}.`;
    el('lottery').textContent=account.lottery_status;
    el('reward-policy').textContent=account.reward_windows?.staking_yield || '';
    const rewards=el('reward-totals');rewards.replaceChildren();
    for(const [key,label] of [['mining','Block earnings'],['comine_payout','Co-mining earnings'],['staking_distribution','Staking yield']]) {
      const value=account.reward_totals?.[key] || '0';
      const item=document.createElement('div'),title=document.createElement('span'),amount=document.createElement('strong');
      title.textContent=label;amount.textContent=money(value);item.append(title,amount);rewards.append(item);
    }
    el('private').hidden=false; el('message').textContent='Updated '+new Date().toLocaleTimeString();
    if(!paged)await payments();
  } catch (error) { if (active===generation) el('message').textContent=error.message; }
  finally { refreshing=false; }
}
el('access').addEventListener('input',()=>{
  const copied=el('access').value;
  if(!copied)return;
  try {
    const access=JSON.parse(copied);
    if(!access || Array.isArray(access) || Object.keys(access).sort().join(',')!=='account,endpoint,token' ||
       typeof access.account!=='string' || typeof access.token!=='string' || typeof access.endpoint!=='string' ||
       !/^[a-f0-9]{32}$/.test(access.account) || !/^[a-f0-9]{64}$/.test(access.token) ||
       new URL(access.endpoint).origin!==location.origin)throw new Error('This access code is not for this pool.');
    el('account').value=access.account;el('token').value=access.token;
    el('access').value='';el('message').textContent='Access ready. Select View account.';
  } catch {el('access').value='';el('message').textContent='Access was not imported. Copy viewing access from this pool in your node.';}
});
el('login').addEventListener('submit',event=>{
  event.preventDefault(); generation++;paged=false;cursor=0;
  credentials={account:el('account').value.trim(),token:el('token').value};
  el('token').value=''; el('private').hidden=true; el('payments').replaceChildren(); refresh();
});
el('forget').addEventListener('click',clearAccount);
el('older').addEventListener('click',async()=>{try{await payments(true);}catch(error){el('message').textContent=error.message;}});
async function health() {
  if(healthBusy)return;healthBusy=true;
  try {
    const status=await call('health',{}); el('health').textContent=status.status;
    el('height').textContent=status.reconciled_height ?? 'Starting';
    el('active').textContent=status.active_accounts ?? '—';
    el('total-shares').textContent=status.verified_shares ?? '—';
    el('queue').textContent=`${status.verification_queue.waiting} / ${status.verification_queue.capacity}`;
    el('chain').textContent=status.chain || 'Network identity not reported';
    const policy=status.payment_policy;
    if(policy&&typeof policy==='object'&&['fee_ppm','minimum_units','batch_seconds'].every(k=>typeof policy[k]==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(policy[k]))&&BigInt(policy.fee_ppm)<=100000n&&BigInt(policy.batch_seconds)>=3600n&&BigInt(policy.batch_seconds)<=604800n){
      const fee=BigInt(policy.fee_ppm);const percent=((fee/10000n)+'.'+(fee%10000n).toString().padStart(4,'0')).replace(/\.?0+$/,'');
      el('payment-policy').textContent=percent+'% service fee · '+money(policy.minimum_units)+' minimum per payout address · batches every '+(Number(policy.batch_seconds)/3600)+' hours. Machines using the same address qualify together; account balances stay separate.';
    }else el('payment-policy').textContent='Payment policy is not available.';
    el('service-details').textContent=`Payments ${status.payments_enabled?'enabled':'not enabled'} · Co-mining ${status.co_mining_enabled?'enabled':'not enabled'} · Updated ${new Date().toLocaleTimeString()}`;
  }
  catch {el('payment-policy').textContent='Payment policy is not available.';el('health').textContent='Service unavailable';el('service-details').textContent='The last report may be stale. Reconnecting automatically.';}
  finally {healthBusy=false;}
}
el('endpoint').textContent=location.origin;
el('copy-endpoint').addEventListener('click',async()=>{
  try {await navigator.clipboard.writeText(location.origin);el('copy-endpoint').textContent='Copied';}
  catch {el('copy-endpoint').textContent='Select and copy the endpoint above';}
});
window.addEventListener('pagehide',clearAccount);
setInterval(()=>{health(); if(!document.hidden) refresh();},15000); health();
