'use strict';
const $ = id => document.getElementById(id);
let credential = new URLSearchParams(location.hash.slice(1)).get('token') || sessionStorage.getItem('airlock-demo-token') || '';
if (credential) sessionStorage.setItem('airlock-demo-token', credential);
history.replaceState(null, '', location.pathname);
let state = null;
let busy = false;
const reasons = {permitted:'Within the trusted assignment',outside_task_scope:'Borrower B is outside this assignment',tool_not_permitted:'External operations are not permitted',task_revoked:'Assignment revoked by the operator',task_expired:'Assignment has expired',identity_or_tenant_mismatch:'Agent or tenant does not match',invalid_arguments:'Arguments do not match the allowed tool',policy_unavailable:'Policy unavailable: execution denied',user_entitlement_removed:'Analyst entitlement has been removed'};
function node(tag,text,cls){const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(cls)el.className=cls;return el;}
function notice(text,error=false){$('connection').textContent=text;$('connection').className='notice'+(error?' error':'');}
async function request(path,method='GET'){
  const response=await fetch(path,{method,headers:{Authorization:'Bearer '+credential}});
  if(!response.ok){let msg='Request failed';try{msg=(await response.json()).detail||msg;}catch{}throw new Error(msg);}
  return response.json();
}
function controls(){for(const id of ['assign','download'])$(id).disabled=busy||!state;for(const id of ['read','cross-case','upload'])$(id).disabled=busy||!state?.task;$('revoke').disabled=busy||!state?.task||state.task.status!=='active';}
async function refresh(){
  state=await request('/api/state');
  const decisions=state.events.filter(e=>e.kind==='decision');
  const outcomes=new Map(state.events.filter(e=>e.kind==='outcome').map(e=>[e.correlation_id,e]));
  $('allowedCount').textContent=state.backend_reads.length;
  $('deniedCount').textContent=decisions.filter(e=>e.decision==='DENY').length;
  $('outsideCount').textContent=state.backend_reads.filter(e=>e.tenant!=='demo-bank'||e.borrower!=='A').length;
  $('integrity').textContent=state.signature_valid?'Valid':'INVALID';
  $('taskStatus').textContent=state.task?(state.task.status==='revoked'?'Revoked':Date.now()/1000>=state.task.expires_at?'Expired':'Active · borrower A'):'Not assigned';
  $('taskId').textContent=state.task?state.task.id:'Create an assignment to begin';
  $('taskExpiry').textContent=state.task?'Version '+state.task.version:'15-minute grants';
  $('assign').textContent=state.task?'Create new assignment':'Create assignment';
  $('ledger').textContent=JSON.stringify(state.backend_reads,null,2);
  $('publicKey').textContent=state.public_key;
  $('events').replaceChildren();
  for(const e of [...decisions].reverse()){
    const row=node('tr');row.append(node('td',e.tool+(e.resource?' / '+e.resource:'')));
    const verdict=node('td');verdict.append(node('span',e.decision,'tag '+e.decision.toLowerCase()));row.append(verdict);
    row.append(node('td',reasons[e.reason]||e.reason));
    const outcome=outcomes.get(e.correlation_id);
    row.append(node('td',e.decision==='DENY'?'Not dispatched':outcome?.execution==='completed'?'Completed · '+outcome.backend_request_id.slice(0,8):outcome?.execution||'Unresolved intent'));
    row.append(node('td',e.correlation_id.slice(0,8)));$('events').append(row);
  }
  if(!decisions.length){const row=node('tr');const cell=node('td','No requests yet.','muted');cell.colSpan=5;row.append(cell);$('events').append(row);}
  controls();
}
function showResult(r){
  const area=$('result');area.replaceChildren();
  area.append(node('div',r.decision==='ALLOW'?'ALLOWED':'BLOCKED','verdict '+r.decision.toLowerCase()));
  area.append(node('p',reasons[r.reason]||r.reason,'result-reason'));
  for(const [label,value] of [['Execution',r.execution==='completed'?'Backend returned the assigned documents':r.execution==='not_dispatched'?'Not dispatched to backend':r.execution],['Backend receipt',r.backend_request_id||'None'],['Request correlation',r.correlation_id],['Agent mode','Scripted test request']]){const item=node('div',undefined,'fact');item.append(node('label',label),node('strong',value));area.append(item);}
  if(r.draft){$('draftPanel').hidden=false;$('draft').replaceChildren(node('h3',r.draft.name));for(const observation of r.draft.observations){const p=node('p',undefined,'draft-item');p.append(node('span',observation.source,'source'),document.createTextNode(observation.text));$('draft').append(p);}$('draft').append(node('p',r.draft.notice,'small'));}
}
async function action(fn){if(busy)return;busy=true;controls();try{await fn();await refresh();notice('Local execution path connected. Evidence reflects requests made in this run.');}catch(e){notice(e.message,true);try{await refresh();}catch{}}finally{busy=false;controls();}}
$('assign').addEventListener('click',()=>action(async()=>{await request('/api/tasks','POST');$('result').replaceChildren(node('p','Assignment created. The agent may now read borrower A.','result-reason'));$('draftPanel').hidden=true;}));
$('revoke').addEventListener('click',()=>action(async()=>{await request('/api/tasks/'+encodeURIComponent(state.task.id)+'/revoke','POST');$('result').replaceChildren(node('div','REVOKED','verdict deny'),node('p','Repeat the read to verify access has stopped. Previously returned data cannot be recalled.','result-reason'));}));
for(const id of ['read','cross-case','upload'])$(id).addEventListener('click',()=>action(async()=>showResult(await request('/api/demo/'+id,'POST'))));
$('download').addEventListener('click',()=>action(async()=>{const bundle=await request('/api/evidence');const url=URL.createObjectURL(new Blob([JSON.stringify(bundle,null,2)],{type:'application/json'}));const a=node('a');a.href=url;a.download='airlock-evidence.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}));
refresh().then(()=>notice('Local execution path connected. Start by creating a trusted assignment.')).catch(()=>{notice('Open the private launch URL printed by the demo server. If you restarted it, use the new URL.',true);controls();});
