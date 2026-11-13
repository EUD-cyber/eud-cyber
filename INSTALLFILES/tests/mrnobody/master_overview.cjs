const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const base = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2/web');
const html = fs.readFileSync(path.join(base, 'templates/index.html'), 'utf8').replace(/\{\{\s*url_for\('static', filename='([^']+)'\)\s*\}\}/g, (_, n) => '/static/' + n);
let role='master', failed=false, requests=0, writes=0;
let agents=[{agent_id:'agent-1',name:'<img src=x onerror=alert(1)>',status:'online',last_seen_at:1700000000}];
const shared={status:'idle',active:false,execution:null,phases:[],scenarios:[],schedules:[],reports:[],networks:[],hosts:[],log:'',phase_status:{}};
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.MRN_CHROME_PATH,headless:true});
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1050}});
  const errors=[]; page.on('pageerror',e=>errors.push(String(e)));
  await page.route('**/*',route=>{
   if(route.request().method()!=='GET'){writes++;return route.fulfill({status:403});}
   const url=new URL(route.request().url());
   if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:html});
   if(['/static/app.js','/static/planning.js','/static/style.css'].includes(url.pathname))return route.fulfill({contentType:url.pathname.endsWith('.css')?'text/css':'text/javascript',body:fs.readFileSync(path.join(base,url.pathname.slice(1)))});
   if(url.pathname==='/api/health')return route.fulfill({json:{status:'ok',service:'MrNobody Incident Platform',deployment:{role,config_status:'loaded',lab_http_enabled:false,master_url_configured:false,transport_enabled:false}}});
   if(url.pathname==='/api/master/agents'){requests++;return failed?route.fulfill({status:503,json:{message:'Registry unavailable'}}):route.fulfill({json:{agents,initialized:agents.length>0}});}
   return route.fulfill({json:shared});
  });
  await page.goto('https://mrnobody.test/');
  await page.locator('[data-page="system"]').click();
  await page.waitForFunction(()=>document.getElementById('masterAgentsRuntime').textContent.includes('agent-1'));
  assert.ok(await page.locator('#masterAgentsRuntime').textContent().then(t=>t.includes('Online')));
  assert.equal(await page.locator('#masterAgentsRuntime img').count(),0);
  for(const width of [1440,768,390]){await page.setViewportSize({width,height:1050});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));}
  agents=[]; await page.locator('#masterAgentsRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterAgentsRuntime').textContent.includes('No agent keys issued'));
  failed=true; await page.locator('#masterAgentsRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterAgentsRuntime').textContent.includes('unavailable'));
  failed=false;agents=[{agent_id:'agent-2',name:'Lab2',status:'revoked',last_seen_at:null}];
  await page.locator('#masterAgentsRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterAgentsRuntime').textContent.includes('Revoked'));
  const previous=requests;role='agent';await page.reload();await page.locator('[data-page="system"]').click();
  await page.waitForFunction(()=>document.getElementById('deploymentRuntime').textContent.includes('Agent'));
  assert.equal(await page.locator('#masterAgentsPanel').isVisible(),false);assert.equal(requests,previous);
  assert.equal(writes,0);assert.deepEqual(errors,[]);
  console.log('Master overview browser tests passed: Master-only visibility, safe text, empty/error/retry/revoked states, 3 widths and no writes.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
