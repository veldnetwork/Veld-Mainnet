/* The portal supplies the authenticated device report; no additional requests. */
let constellationReport=null,constellationScene=null,constellationFrame=0;
const constellationSelections=new Map();
function constellationDevice(){return String(current()?.id||'network');}
function paintConstellation(){
 const plot=document.querySelector('.vc-plot');if(!plot)return;
 const key=constellationDevice(),width=Math.max(240,plot.clientWidth),height=plot.clientHeight;
 const scene=VeldConstellation.scene(constellationReport,constellationSelections.get(key),width,height);
 constellationScene=scene;
 if(!scene.node){setHtml(plot,'<div class="vc-empty">Waiting for a fresh topology report.</div>');return;}
 constellationSelections.set(key,scene.node.id);if(constellationSelections.size>64)constellationSelections.delete(constellationSelections.keys().next().value);
 setHtml(plot,scene.svg);
 const shell=plot.closest('.vc-shell');shell.querySelector('.vc-name').textContent=scene.node.label;
 shell.querySelector('.vc-detail').textContent=scene.links.length+' reported links · '+({exact:'tip agrees',differs:'tip differs',stale:'no recent tip report',unavailable:'no recent tip report'}[scene.node.tip_state]);
 shell.querySelector('.vc-marker').className='vc-marker vc-'+scene.node.role+(scene.node.tip_state==='differs'?' vc-differs':'');
 shell.querySelector('.vc-total').textContent=scene.data.nodes.length.toLocaleString();
}
function queueConstellation(){cancelAnimationFrame(constellationFrame);constellationFrame=requestAnimationFrame(paintConstellation);}
function topologyGraph(t,device=current()){
 constellationReport=t;queueConstellation();
 const direct=Number.isSafeInteger(device?.peers)&&device.peers>=0?device.peers.toLocaleString():'—';
 return '<section class="vc-shell"><div class="vc-chrome"><div class="vc-wordmark"><span class="vc-logo" aria-hidden="true"></span>VELD</div><span class="vc-chrome-label">NETWORK / MAP</span></div><div class="vc-heading"><div><h3>Peer topology</h3><div class="vc-meta">'+direct+' direct · selected peer connections</div></div><div class="vc-stat"><strong class="vc-total">'+VeldConstellation.normalize(t).nodes.length+'</strong><span>reported peers</span></div></div><div class="vc-plot" tabindex="0" role="group" aria-label="Peer constellation. Select a peer with the pointer, Left and Right keys, or Next peer."></div><div class="vc-inspect" aria-live="polite"><span class="vc-marker vc-miner" aria-hidden="true"></span><div class="vc-description"><strong class="vc-name">Peer topology</strong><small class="vc-detail">Select a peer to trace its links</small></div><button type="button" class="vc-next">Next peer →</button></div><div class="vc-legend"><span><i class="vc-key miner"></i>Miner</span><span><i class="vc-key"></i>Node</span><span><i class="vc-key fleet"></i>Fleet</span><span><i class="vc-key validator"></i>Validator</span></div><div class="vc-foot"><span><i class="vc-link-key"></i>Both report</span><span><i class="vc-link-key one"></i>One-sided report</span></div></section>';
}
function stepConstellation(delta){
 const s=constellationScene;if(!s?.data.nodes.length)return;
 const next=(s.index+delta+s.data.nodes.length)%s.data.nodes.length;
 constellationSelections.set(constellationDevice(),s.data.nodes[next].id);queueConstellation();
}
document.addEventListener('click',event=>{
 if(event.target.closest('.vc-next')){stepConstellation(1);return;}
 const plot=event.target.closest('.vc-plot');if(!plot||!constellationScene)return;
 const bounds=plot.getBoundingClientRect(),i=VeldConstellation.nearest(constellationScene.points,event.clientX-bounds.left,event.clientY-bounds.top);
 if(i>=0){constellationSelections.set(constellationDevice(),constellationScene.data.nodes[i].id);queueConstellation();}
});
document.addEventListener('keydown',event=>{
 if(!event.target.matches('.vc-plot')||!['ArrowLeft','ArrowRight'].includes(event.key))return;
 event.preventDefault();stepConstellation(event.key==='ArrowRight'?1:-1);
});
window.addEventListener('resize',queueConstellation);
