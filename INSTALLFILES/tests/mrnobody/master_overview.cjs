const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const base = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2/web');
const html = fs.readFileSync(path.join(base, 'templates/index.html'), 'utf8').replace(/\{\{\s*url_for\('static', filename='([^']+)'\)\s*\}\}/g, (_, n) => '/static/' + n);
let role='master', configStatus='loaded', failed=false, healthFailed=false, malformed=false, requests=0, writes=0;
let agents=[{agent_id:'agent-1',name:'<img src=x onerror=alert(1)>',status:'online',last_seen_at:1700000000}];
const shared={status:'idle',active:false,execution:null,phases:[],scenarios:[],schedules:[],reports:[],networks:[],hosts:[],log:'',phase_status:{}};
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.MRN_CHROME_PATH,headless:true});
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1050}});
  await page.clock.install();
  const errors=[]; page.on('pageerror',e=>errors.push(String(e)));
  await page.route('**/*',route=>{
   if(route.request().method()!=='GET'){writes++;return route.fulfill({status:403});}
   const url=new URL(route.request().url());
   if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:html});
   if(['/static/app.js','/static/planning.js','/static/style.css'].includes(url.pathname))return route.fulfill({contentType:url.pathname.endsWith('.css')?'text/css':'text/javascript',body:fs.readFileSync(path.join(base,url.pathname.slice(1)))});
   if(url.pathname==='/api/health')return healthFailed?route.fulfill({status:503}):route.fulfill({json:{status:'ok',service:'MrNobody Incident Platform',deployment:{role,config_status:configStatus,lab_http_enabled:true,master_url_configured:false,transport_enabled:false}}});
   if(url.pathname==='/api/master/agents'){requests++;return failed?route.fulfill({status:503,json:{message:'Registry unavailable'}}):route.fulfill({json:malformed?{agents:null}:{agents,initialized:agents.length>0}});}
   return route.fulfill({json:shared});
  });
  await page.goto('https://mrnobody.test/');
  await page.locator('#masterAgentsTab').click();
  await page.waitForFunction(()=>document.getElementById('masterAgentsRuntime').textContent.includes('agent-1'));
  assert.ok(await page.locator('#masterAgentsRuntime').textContent().then(t=>t.includes('Online')));
  assert.equal(await page.locator('#masterAgentsPanel').isVisible(),true);
  assert.match(await page.locator('#masterAgentsRuntime').textContent(), /Last heartbeat/);
  assert.match(await page.locator('#masterAgentsRuntime').textContent(), /Name/);
  assert.equal(await page.locator('#masterAgentsRuntime img').count(),0);
  const firstAgent=page.getByRole('button',{name:'View agent agent-1',exact:true});
  await firstAgent.focus();await page.keyboard.press('Enter');
  const detail=page.locator('#masterAgentDetail');
  assert.match(await detail.textContent(), /Agent details.*Agent ID.*agent-1.*Name.*<img.*Status.*Online.*Last heartbeat/s);
  assert.match(await detail.textContent(), /Report metadata has not been synchronized/);
  assert.equal(await detail.locator('img').count(),0);
  assert.equal(await firstAgent.getAttribute('aria-expanded'),'true');
  assert.equal(await page.locator('#masterAgentDetailTitle').evaluate(el=>el===document.activeElement),true);
  agents=[{agent_id:'agent-1',name:'Renamed slave',status:'offline',last_seen_at:1700000060,reports_synced_at:1700000060,reports:[{id:'MRN-test',report_type:'standalone_phase',phase_id:'01',status:'complete',started:'2026-11-14T12:00:00Z'}]}];
  await page.clock.runFor(30000);
  await page.waitForFunction(()=>document.getElementById('masterAgentDetail')?.textContent.includes('Renamed slave'));
  assert.match(await detail.textContent(), /Offline/);
  assert.match(await detail.textContent(), /Last metadata sync:.*MRN-test.*standalone_phase.*complete.*P01/s);
  const heartbeat=await detail.locator('dd').last().textContent();
  assert.equal(heartbeat,await page.evaluate(()=>new Date(1700000060*1000).toLocaleString()));
  for(const width of [1440,768,390]){await page.setViewportSize({width,height:1050});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));}
  await page.getByRole('button',{name:'Back to agents',exact:true}).click();
  assert.equal(await detail.count(),0);
  assert.equal(await firstAgent.evaluate(el=>el===document.activeElement),true);
  agents=[{agent_id:'agent-offline',name:'Offline slave',status:'offline',last_seen_at:1700000000},{agent_id:'agent-pending',name:'Pending slave',status:'pending',last_seen_at:null}];
  await page.clock.runFor(30000);
  await page.waitForFunction(()=>document.getElementById('masterAgentsRuntime').textContent.includes('agent-pending'));
  assert.match(await page.locator('#masterAgentsRuntime').textContent(), /Offline.*Pending registration.*Never/s);
  await page.getByRole('button',{name:'View agent agent-pending',exact:true}).click();
  assert.match(await detail.textContent(), /Pending registration.*Never/s);
  await page.getByRole('button',{name:'View agent agent-offline',exact:true}).click();
  assert.match(await detail.textContent(), /agent-offline.*Offline/s);
  assert.doesNotMatch(await detail.textContent(), /agent-pending/);
  await page.locator('[data-page="system"]').click();
  await page.waitForLoadState('networkidle');
  const backgroundRequests=requests;
  await page.clock.runFor(30000);
  assert.equal(requests,backgroundRequests);
  await page.locator('#masterAgentsTab').click();
  agents=[]; await page.locator('#masterAgentsRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterAgentsRuntime').textContent.includes('No agents registered yet'));
  assert.match(await detail.textContent(), /no longer available/);
  failed=true; await page.locator('#masterAgentsRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterAgentsRuntime').textContent.includes('unavailable'));
  assert.equal(await detail.count(),0);
  failed=false;malformed=true;await page.locator('#masterAgentsRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterAgentsRuntime').textContent.includes('unavailable'));
  malformed=false;
  failed=false;agents=[{agent_id:'agent-2',name:'Lab2',status:'revoked',last_seen_at:null}];
  await page.locator('#masterAgentsRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterAgentsRuntime').textContent.includes('Revoked'));
  await page.getByRole('button',{name:'View agent agent-2',exact:true}).click();
  assert.match(await detail.textContent(), /agent-2.*Revoked.*Never/s);
  for(const [testRole,status,unavailable] of [['agent','loaded',false],['standalone','default',false],['master','invalid',false],['master','loaded',true]]) {
   const previous=requests;role=testRole;configStatus=status;healthFailed=unavailable;
   await page.reload();await page.locator('[data-page="system"]').click();
   await page.waitForFunction(()=>!document.getElementById('deploymentRuntime').textContent.includes('Loading'));
   assert.equal(await page.locator('#masterAgentsTab').isVisible(),false);
   assert.equal(await page.locator('#masterAgentsPanel').isVisible(),false);
   await page.clock.runFor(30000);assert.equal(requests,previous);
  }
  assert.equal(writes,0);assert.deepEqual(errors,[]);
  console.log('Agents browser tests passed: keyboard/click details, back/focus, selection switching, selected heartbeat refresh, removed agent, Master-only tab, all statuses, inactive-tab pause, safe text, empty/error/retry/malformed states, 3 widths, unchanged agent/standalone visibility and no writes.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
