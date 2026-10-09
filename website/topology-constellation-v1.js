/* Constellation uses only sanitized public topology records. */
(function(global){
'use strict';
const names={fleet:'Fleet',miner:'Miner',node:'Node',validator:'Validator'};
const esc=x=>String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const id=x=>typeof x==='string'&&/^[1-9][0-9]{0,19}$/.test(x)&&BigInt(x)<=18446744073709551615n;
function layout(count,width,height){
 count=Math.min(count,512);width=Math.max(240,width);height=Math.max(240,height);
 const slots=[[.19,.22],[.60,.17],[.81,.53],[.46,.51],[.35,.82],[.13,.58]],aw=width-76,ah=height-60;
 return Array.from({length:count},(_,i)=>{const g=i%6,local=Math.floor(i/6),total=Math.ceil((count-g)/6),a=local*2.399963+.5*g,r=Math.sqrt((local+.55)/(total+.5));return {x:38+slots[g][0]*aw+Math.cos(a)*r*aw*.145,y:30+slots[g][1]*ah+Math.sin(a)*r*ah*.19}});
}
function normalize(raw){
 const seen=new Set(),nodes=[];
 for(const n of (Array.isArray(raw?.nodes)?raw.nodes:[]).slice(0,512)){
  if(!n||!id(n.id)||seen.has(n.id))continue;seen.add(n.id);
  nodes.push({id:n.id,role:Object.hasOwn(names,n.role)?n.role:'node',tip_state:['exact','differs','stale','unavailable'].includes(n.tip_state)?n.tip_state:'unavailable'});
 }
 nodes.sort((a,b)=>a.id.length-b.id.length||(a.id<b.id?-1:a.id>b.id?1:0));
 nodes.forEach((n,i)=>n.label=names[n.role]+' '+String(i+1).padStart(3,'0'));
 const edges=[],edgeKeys=new Set();
 for(const e of (Array.isArray(raw?.edges)?raw.edges:[]).slice(0,8192)){
  if(!e)continue;const a=e.first??e.a,b=e.second??e.b;
  if(!id(a)||!id(b)||a===b||!seen.has(a)||!seen.has(b))continue;
  const pair=[a,b].sort(),k=pair.join('/');if(edgeKeys.has(k))continue;edgeKeys.add(k);
  edges.push({a:pair[0],b:pair[1],confirmed:e.confirmed===true});
 }
 return {nodes,edges};
}
function nearest(points,x,y){let best=-1,distance=32**2;points.forEach((p,i)=>{const d=(p.x-x)**2+(p.y-y)**2;if(d<distance){best=i;distance=d}});return best;}
function scene(raw,selected,width,height=330){
 const data=normalize(raw),points=layout(data.nodes.length,width,height);
 let index=data.nodes.findIndex(n=>n.id===selected);if(index<0)index=Math.max(0,data.nodes.findIndex(n=>n.role==='miner'));
 const n=data.nodes[index],byId=new Map(data.nodes.map((n,i)=>[n.id,points[i]])),linked=new Set();
 const links=n?data.edges.filter(e=>e.a===n.id||e.b===n.id):[];links.forEach(e=>linked.add(e.a===n.id?e.b:e.a));
 let svg='';
 function line(e,active){const a=byId.get(e.a),b=byId.get(e.b);return `<path d="M${a.x},${a.y}L${b.x},${b.y}" class="vc-edge${active?' vc-active':''}${active&&!e.confirmed?' vc-one':''}"/>`;}
 if(data.nodes.length<200)data.edges.forEach((e,i)=>{if(i%3===0)svg+=line(e,false)});
 links.forEach(e=>svg+=line(e,true));
 data.nodes.forEach((p,i)=>{
  const at=points[i],chosen=i===index,bright=chosen||linked.has(p.id),r=chosen?7:linked.has(p.id)?4.5:data.nodes.length>200?2:3.1;
  svg+=`<g class="vc-peer vc-${p.role}${p.tip_state==='differs'?' vc-differs':''}${p.tip_state==='stale'||p.tip_state==='unavailable'?' vc-unknown':''}" opacity="${bright?1:.48}"><title>${esc(p.label+' · '+(p.tip_state==='exact'?'Exact tip':p.tip_state==='differs'?'Tip differs':'No recent tip report'))}</title>`;
  if(chosen)svg+=`<circle cx="${at.x}" cy="${at.y}" r="${r+13}" fill="currentColor" opacity=".055"/><circle cx="${at.x}" cy="${at.y}" r="${r+7}" fill="none" stroke="currentColor" opacity=".7"/>`;
  svg+=p.role==='fleet'?`<rect x="${at.x-r}" y="${at.y-r}" width="${r*2}" height="${r*2}" rx="2" fill="currentColor"/>`:p.role==='validator'?`<path d="M${at.x},${at.y-r*1.25}L${at.x+r*1.25},${at.y}L${at.x},${at.y+r*1.25}L${at.x-r*1.25},${at.y}Z" fill="currentColor"/>`:`<circle cx="${at.x}" cy="${at.y}" r="${r}" fill="currentColor"/>`;
  svg+='</g>';
 });
 if(n){const p=points[index],lw=n.label.length*6.7+20,lx=Math.max(12,Math.min(width-lw-12,p.x-lw/2)),ly=p.y>height-75?p.y-46:p.y+22;
  svg+=`<rect class="vc-label-box" x="${lx}" y="${ly}" width="${lw}" height="25" rx="5"/><text x="${lx+lw/2}" y="${ly+16}" text-anchor="middle">${esc(n.label)}</text>`;
 }
 svg+=`<text class="vc-hint" x="20" y="${height-12}">TAP A PEER TO TRACE ITS LINKS</text>`;
 return {data,points,index,node:n,links,svg:`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Reported network connections; select a peer to trace its links">${svg}</svg>`};
}
global.VeldConstellation={layout,normalize,nearest,scene};
if(typeof module!=='undefined')module.exports=global.VeldConstellation;
})(typeof window!=='undefined'?window:globalThis);
