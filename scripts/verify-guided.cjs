const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.AIRLOCK_PLAYWRIGHT_MODULE || 'playwright');
(async()=>{
 const out=path.resolve(process.env.AIRLOCK_ARTIFACTS||'submission-artifacts');
 fs.mkdirSync(out,{recursive:true});
 const browser=await chromium.launch({headless:true,channel:'msedge'});
 try {
 const context=await browser.newContext({viewport:{width:1440,height:1000},acceptDownloads:true});
 const page=await context.newPage(),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto(process.env.AIRLOCK_DEMO_URL);
 await page.waitForFunction(()=>!document.querySelector('#next').disabled);
 assert.equal(await page.locator('#technical').getAttribute('open'),null);
 await page.screenshot({path:path.join(out,'01-ready.png'),fullPage:true});
 for(const [label,result] of [
  ['Let AI read borrower A','Borrower A was read.'],
  ['Try borrower B','Borrower B is not part of this job. Nothing was sent to the backend.'],
  ['Try an external upload','This job does not allow uploads. Nothing was sent to the backend.'],
  ['Stop AI access','AI access stopped.'],
  ['Try borrower A again','You stopped access. Nothing was sent to the backend.']
 ]){
  await page.getByRole('button',{name:label,exact:false}).first().click();
  await page.locator('#result').getByText(result,{exact:true}).waitFor();
  await page.waitForFunction(()=>!document.querySelector('#next').disabled);
  if(label==='Let AI read borrower A'){
   assert.match(await page.locator('#stepDescription').textContent(),/supervisor/);
   assert.match(await page.locator('#actionNote').textContent(),/no live model/);
   await page.screenshot({path:path.join(out,'02-attack-scenario.png'),fullPage:true});
  }
 }
 assert.equal(await page.locator('#progressLabel').textContent(),'Complete');
 assert.equal(await page.locator('#allowedCount').textContent(),'1');
 assert.equal(await page.locator('#deniedCount').textContent(),'3');
 assert.equal(await page.locator('#outsideCount').textContent(),'0');
 assert.equal(await page.locator('#integrity').textContent(),'Valid');
 await page.screenshot({path:path.join(out,'03-verified.png'),fullPage:true});
 await page.locator('#technical > summary').click();
 const downloadEvent=page.waitForEvent('download');
 await page.getByRole('button',{name:'Download signed evidence',exact:true}).click();
 await (await downloadEvent).saveAs(path.join(out,'sample-evidence.json'));
 const bundle=JSON.parse(fs.readFileSync(path.join(out,'sample-evidence.json'),'utf8'));
 assert.equal(bundle.payload.backend_reads.length,1);
 assert.equal(bundle.payload.events.filter(e=>e.kind==='decision'&&e.decision==='DENY').length,3);
 await page.locator('#technical > summary').click();
 await page.getByRole('button',{name:'Start again',exact:false}).click();
 await page.waitForFunction(()=>document.querySelector('#progressLabel').textContent==='Step 1 of 5');
 assert.equal(await page.locator('#progressLabel').textContent(),'Step 1 of 5');
 await page.setViewportSize({width:390,height:844});
 await page.screenshot({path:path.join(out,'04-mobile.png'),fullPage:true});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 const bankQuestions=page.locator('.bank-questions > details');
 assert.equal(await bankQuestions.count(),5);
 for(let i=0;i<5;i++){
  await bankQuestions.nth(i).locator('summary').click();
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 }
 assert.match(await page.locator('#bankTeams').textContent(),/not an installed bank integration/);
 await page.screenshot({path:path.join(out,'05-bank-details-mobile.png'),fullPage:true});
 await page.setViewportSize({width:1440,height:1000});
 await page.screenshot({path:path.join(out,'06-bank-details-desktop.png'),fullPage:true});
 // Reload starts a new guided run, but never removes evidence.
 await page.reload();
 await page.waitForFunction(()=>!document.querySelector('#next').disabled);
 assert.equal(await page.locator('#deniedCount').textContent(),'3');
 // Unauthenticated browser must show a useful error, with actions unavailable.
 const guest=await browser.newContext();
 const guestPage=await guest.newPage();
 await guestPage.goto(new URL('/',process.env.AIRLOCK_DEMO_URL).href);
 await guestPage.locator('#connection.error').waitFor();
 assert.equal(await guestPage.locator('#next').isDisabled(),true);
 assert.deepEqual(errors,[]);
 fs.writeFileSync(path.join(out,'browser-test-results.json'),JSON.stringify({passed:true,guided_steps:5,desktop:'1440x1000',mobile:'390x844',completed_reads:1,denied_requests:3,out_of_scope_reads:0,evidence_download:true,restart_preserves_history:true,unauthenticated_error:true,javascript_errors:errors},null,2));
 console.log('PASS: guided flow, real read, 3 denials, evidence download, restart, mobile, unauthenticated state; no JS errors.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1);});
