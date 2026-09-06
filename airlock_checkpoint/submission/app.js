'use strict';
const $ = id => document.getElementById(id);
let credential = new URLSearchParams(location.hash.slice(1)).get('token') || sessionStorage.getItem('airlock-demo-token') || '';
if (credential) sessionStorage.setItem('airlock-demo-token', credential);
history.replaceState(null, '', location.pathname);
let state = null, busy = false, step = 0;
const steps = [
 ['01 / GIVE PERMISSION','Start with one file.','Let the AI read borrower A\'s documents for this job.','Let AI read borrower A','Permission lasts 15 minutes. You can stop it sooner.'],
 ['02 / TRY ANOTHER FILE','What if it asks for more?','Try reading borrower B, who is not part of this job.','Try borrower B','Same AI. Different borrower.'],
 ['03 / TRY SENDING DATA','Can it send data outside?','Try an upload request that this job does not permit.','Try an external upload','This test sends no data to an external service.'],
 ['04 / STOP ACCESS','You stay in control.','Remove the AI\'s permission to read borrower A.','Stop AI access','Previously returned data cannot be recalled.'],
 ['05 / CHECK AGAIN','Does access really stop?','Ask for borrower A once more, after permission is removed.','Try borrower A again','Airlock checks permission on every request.'],
 ['DEMO COMPLETE','That\'s what Airlock does.','It checks each request against the job you approved.','Start again','Earlier requests stay in the history below.']
];
const reasons = {permitted:'This file is part of the approved job',outside_task_scope:'Borrower B is not part of this job',tool_not_permitted:'This job does not allow uploads',task_revoked:'You stopped access',task_expired:'Permission has expired',identity_or_tenant_mismatch:'Identity or bank does not match',invalid_arguments:'The request does not match the allowed tool',policy_unavailable:'Policy unavailable; request blocked',user_entitlement_removed:'The analyst no longer has access'};
function node(tag,text,cls){const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(cls)el.className=cls;return el;}
function notice(text,error=false){$('connection').hidden=!text;$('connection').textContent=text;$('connection').className='notice'+(error?' error':'');}
async function request(path,method='GET'){
 const response=await fetch(path,{method,headers:{Authorization:'Bearer '+credential}});
 if(!response.ok){let msg='Request failed. Please try again.';try{msg=(await response.json()).detail||msg;}catch{}throw new Error(msg);}
 return response.json();
}
function controls(){
 $('next').disabled=busy||!state;
 for(const id of ['read','cross-case','upload'])$(id).disabled=busy||!state?.task;
 $('revoke').disabled=busy||!state?.task||state.task.status!=='active';
 $('download').disabled=busy||!state;
 $('next').setAttribute('aria-busy',String(busy));
}
function renderStep(){
 const s=steps[step];
 for(const [id,index] of [['stepLabel',0],['stepTitle',1],['stepDescription',2],['actionNote',4]])$(id).textContent=s[index];
 $('next').replaceChildren(document.createTextNode(s[3]),node('span','→'));
 $('next').lastChild.setAttribute('aria-hidden','true');
 $('progressLabel').textContent=step===5?'Complete':'Step '+(step+1)+' of 5';
 $('progressDots').replaceChildren(...Array.from({length:5},(_,i)=>node('span',undefined,i<=step?'done':'')));
 controls();
}
async function refresh(){
 state=await request('/api/state');
 const decisions=state.events.filter(e=>e.kind==='decision');
 const outcomes=new Map(state.events.filter(e=>e.kind==='outcome').map(e=>[e.correlation_id,e]));
 $('allowedCount').textContent=state.backend_reads.length;
 $('deniedCount').textContent=decisions.filter(e=>e.decision==='DENY').length;
 $('outsideCount').textContent=state.backend_reads.filter(e=>e.tenant!=='demo-bank'||e.borrower!=='A').length;
 $('integrity').textContent=state.signature_valid?'Valid':'INVALID';
 const active=state.task?.status==='active' && Date.now()/1000<state.task.expires_at;
 $('fileA').className='file'+(active?' active':'');
 $('accessA').textContent=active?'AI has permission':state.task?.status==='revoked'?'Permission removed':state.task?'Permission expired':'Waiting for permission';
 $('iconA').textContent=active?'Can read':state.task?'No access':'—';
 $('ledger').textContent=JSON.stringify(state.backend_reads,null,2);
 $('publicKey').textContent=state.public_key;
 $('events').replaceChildren();
 for(const e of [...decisions].reverse()){
  const row=node('tr'); const outcome=outcomes.get(e.correlation_id);
  row.append(node('td',e.tool+(e.resource?' / '+e.resource:'')),node('td',e.decision==='DENY'?'Blocked':'Allowed'),node('td',reasons[e.reason]||e.reason),node('td',e.decision==='DENY'?'Not sent to backend':outcome?.execution||'Pending'));
  $('events').append(row);
 }
 if(!decisions.length){const row=node('tr');const cell=node('td','No requests yet.');cell.colSpan=4;row.append(cell);$('events').append(row);}
 controls();
}
function result(title,description,blocked=false){
 $('result').hidden=false;$('result').className=blocked?'blocked':'';
 $('result').replaceChildren(node('strong',title),node('p',description));
}
function showResult(r){
 if(r.decision==='ALLOW' && r.execution==='completed')result('Borrower A was read.', 'The documents reached the AI. Borrower B stayed off limits.');
 else if(r.decision==='DENY')result('Request blocked.',(reasons[r.reason]||r.reason)+'. Nothing was sent to the backend.',true);
 else result('The read did not complete.','The backend reported: '+r.execution+'. See the request history.',true);
 if(r.draft){$('draft').replaceChildren(node('h3',r.draft.name));for(const o of r.draft.observations)$('draft').append(node('p',o.source+': '+o.text));$('draft').append(node('p',r.draft.notice));}
}
async function action(fn){
 if(busy)return;busy=true;controls();notice('');
 try{await fn();await refresh();}catch(e){notice(e.message,true);try{await refresh();}catch{}}
 finally{busy=false;renderStep();}
}
$('next').addEventListener('click',()=>action(async()=>{
 if(step===5){step=0;$('result').hidden=true;$('recap').hidden=true;return;}
 if(step===0){
  await request('/api/tasks','POST');
  const r=await request('/api/demo/read','POST');showResult(r);
  if(r.decision!=='ALLOW'||r.execution!=='completed')return;
 }else if(step===3){
  await request('/api/tasks/'+encodeURIComponent(state.task.id)+'/revoke','POST');
  result('AI access stopped.','Now test whether another read gets through.');
 }else{
  const r=await request('/api/demo/'+({1:'cross-case',2:'upload',4:'read'}[step]),'POST');showResult(r);
  const expected={1:'outside_task_scope',2:'tool_not_permitted',4:'task_revoked'}[step];
  if(r.decision!=='DENY'||r.reason!==expected){notice('The result differs from this step. Check the history, or refresh to start a new demo.',true);return;}
 }
 step++;
 if(step===5){$('recap').hidden=false;$('recap').replaceChildren(node('span','1 permitted read'),node('span','3 requests blocked'),node('span','Access removed'));}
}));
for(const id of ['read','cross-case','upload'])$(id).addEventListener('click',()=>action(async()=>showResult(await request('/api/demo/'+id,'POST'))));
$('revoke').addEventListener('click',()=>action(async()=>{await request('/api/tasks/'+encodeURIComponent(state.task.id)+'/revoke','POST');result('AI access stopped.','Future reads will be checked against the removed permission.');}));
$('download').addEventListener('click',()=>action(async()=>{const bundle=await request('/api/evidence');const url=URL.createObjectURL(new Blob([JSON.stringify(bundle,null,2)],{type:'application/json'}));const a=node('a');a.href=url;a.download='airlock-evidence.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}));
renderStep();
refresh().then(()=>notice('')).catch(()=>{notice('Open the private launch link from the demo server to connect. A restarted server needs a new link.',true);controls();});
