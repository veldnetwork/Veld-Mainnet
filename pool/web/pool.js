'use strict';
const el = id => document.getElementById(id);
let credentials = null, cursor = 0, generation = 0, refreshing = false;
function money(value) {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error('Invalid balance response');
  const units = BigInt(value);
  return `${(units / 100000000n).toLocaleString('en-US')}.${(units % 100000000n).toString().padStart(8,'0')} VELD`;
}
async function call(action, payload) {
  const response = await fetch(`/v1/${action}`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload), cache:'no-store', credentials:'omit', redirect:'error', signal:AbortSignal.timeout(20000)});
  const text = await response.text();
  if (text.length > 16384) throw new Error('Response exceeds limit');
  const result = JSON.parse(text);
  if (!response.ok || result.ok !== true) throw new Error(result.retryable ? 'Service busy. Try again shortly.' : 'Request refused. Check your account ID and viewing token.');
  return result.result;
}
function clearAccount() {
  generation++; credentials = null; cursor = 0;
  el('access').value='';
  el('token').value = ''; el('account').value = ''; el('private').hidden = true;
  el('payments').replaceChildren(); el('address').textContent = ''; el('message').textContent = '';
}
async function payments(append=false) {
  if (!credentials) return;
  const active = generation;
  const result = await call('history',{...credentials,before:String(append ? cursor : 0)});
  if (active !== generation || !credentials) return;
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
    el('private').hidden=false; el('message').textContent='Updated '+new Date().toLocaleTimeString();
    await payments();
  } catch (error) { if (active===generation) el('message').textContent=error.message; }
  finally { refreshing=false; }
}
el('access').addEventListener('input',()=>{
  const copied=el('access').value;
  if(!copied)return;
  try {
    const access=JSON.parse(copied);
    if(Object.keys(access).sort().join(',')!=='account,endpoint,token' ||
       !/^[a-f0-9]{32}$/.test(access.account) || !/^[a-f0-9]{64}$/.test(access.token) ||
       new URL(access.endpoint).origin!==location.origin)throw new Error('This access code is not for this pool.');
    el('account').value=access.account;el('token').value=access.token;
    el('access').value='';el('message').textContent='Access ready. Select View account.';
  } catch {el('access').value='';el('message').textContent='Access was not imported. Copy viewing access from this pool in your node.';}
});
el('login').addEventListener('submit',event=>{
  event.preventDefault(); generation++;
  credentials={account:el('account').value.trim(),token:el('token').value};
  el('token').value=''; el('private').hidden=true; el('payments').replaceChildren(); refresh();
});
el('forget').addEventListener('click',clearAccount);
el('older').addEventListener('click',async()=>{try{await payments(true);}catch(error){el('message').textContent=error.message;}});
async function health() {
  try { const status=await call('health',{}); el('health').textContent=status.status; }
  catch {el('health').textContent='Service unavailable';}
}
window.addEventListener('pagehide',clearAccount);
setInterval(()=>{health(); if(!document.hidden) refresh();},15000); health();
