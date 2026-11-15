const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const base = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2/web');
const html = fs.readFileSync(path.join(base, 'templates/index.html'), 'utf8').replace(/\{\{\s*url_for\('static', filename='([^']+)'\)\s*\}\}/g, (_, n) => '/static/' + n);
let role='master', configStatus='loaded', failed=false, malformed=false, healthFailed=false, requests=[], writes=0;
const event={id:2,agent_id:'agent-1',campaign_id:'<img src=x onerror=alert(1)>',event_type:'http_test',timestamp:'2026-11-15T11:30:00+00:00',received_at:1794742200,bytes:128,status:'received'};
let events=[event], next=2;
const shared={status:'idle',active:false,execution:null,phases:[],scenarios:[],schedules:[],reports:[],networks:[],hosts:[],log:'',phase_status:{}};
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.MRN_CHROME_PATH,headless:true});
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1050}});
  await page.clock.install();
  const errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.route('**/*',route=>{
   if(route.request().method()!=='GET'){writes++;return route.fulfill({status:403});}
   const url=new URL(route.request().url());
   if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:html});
   if(['/static/app.js','/static/planning.js','/static/style.css'].includes(url.pathname))return route.fulfill({contentType:url.pathname.endsWith('.css')?'text/css':'text/javascript',body:fs.readFileSync(path.join(base,url.pathname.slice(1)))});
   if(url.pathname==='/api/health')return healthFailed?route.fulfill({status:503}):route.fulfill({json:{status:'ok',deployment:{role,config_status:configStatus}}});
   if(url.pathname==='/api/master/receiver/events'){
    requests.push(url);
    return failed?route.fulfill({status:503}):route.fulfill({json:malformed?{events:null}:{events,next_before:next}});
   }
   if(url.pathname==='/api/master/agents')return route.fulfill({json:{agents:[]}});
   return route.fulfill({json:shared});
  });
  await page.goto('https://mrnobody.test/');
  await page.locator('#masterReceiverTab').click();
  const root=page.locator('#masterReceiverRuntime');
  await page.waitForFunction(()=>document.getElementById('masterReceiverRuntime').textContent.includes('http_test'));
  assert.match(await root.textContent(),/Agent.*agent-1.*Campaign.*<img.*event_type.*http_test.*Event timestamp.*received_at.*Declared synthetic bytes.*128.*Status.*received/s);
  assert.equal(await root.locator('img').count(),0);
  assert.equal(requests.at(-1).searchParams.get('limit'),'50');
  for(const width of [1440,768,390]){await page.setViewportSize({width,height:1050});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));}
  await page.locator('#masterReceiverOlder').click();
  await page.waitForFunction(()=>document.getElementById('masterReceiverOlder').disabled===false);
  assert.equal(requests.at(-1).searchParams.get('before'),'2');
  await page.locator('#masterReceiverRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterReceiverOlder').disabled===false);
  assert.equal(requests.at(-1).searchParams.has('before'),false);
  await page.locator('#masterReceiverAgent').fill('agent-1');
  await page.locator('#masterReceiverCampaign').fill('MRN-test');
  await page.getByRole('button',{name:'Apply filters',exact:true}).click();
  await page.waitForFunction(()=>document.getElementById('masterReceiverOlder').disabled===false);
  assert.equal(requests.at(-1).searchParams.get('agent_id'),'agent-1');
  assert.equal(requests.at(-1).searchParams.get('campaign_id'),'MRN-test');
  next=null;events=[{...event,id:3,bytes:256}];
  await page.clock.runFor(30000);
  await page.waitForFunction(()=>document.getElementById('masterReceiverRuntime').textContent.includes('256'));
  assert.equal(await page.locator('#masterReceiverOlder').isDisabled(),true);
  events=[];await page.locator('#masterReceiverRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterReceiverRuntime').textContent.includes('No receiver events'));
  failed=true;await page.locator('#masterReceiverRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterReceiverRuntime').textContent.includes('unavailable'));
  failed=false;malformed=true;await page.locator('#masterReceiverRefresh').click();
  await page.waitForLoadState('networkidle');
  assert.match(await root.textContent(),/unavailable/);
  malformed=false;events=[event];await page.locator('#masterReceiverRefresh').click();
  await page.waitForFunction(()=>document.getElementById('masterReceiverRuntime').textContent.includes('http_test'));
  await page.locator('[data-page="phases"]').click();
  await page.waitForLoadState('networkidle');
  const previous=requests.length;await page.clock.runFor(30000);assert.equal(requests.length,previous);
  for(const [r,s,unavailable] of [['agent','loaded',false],['standalone','loaded',false],['master','invalid',false],['master','loaded',true]]){
   role=r;configStatus=s;healthFailed=unavailable;
   const count=requests.length;await page.reload();
   await page.waitForLoadState('networkidle');
   assert.equal(await page.locator('#masterReceiverTab').isVisible(),false);
   assert.equal(await page.locator('#masterReceiverPanel').isVisible(),false);
   await page.clock.runFor(30000);assert.equal(requests.length,count);
  }
  assert.equal(writes,0);assert.deepEqual(errors,[]);
  console.log('Receiver browser tests passed: role/config/health gating, fields, safe text, pagination, exact filters, periodic refresh, inactive-tab pause, empty/error/malformed/retry, 3 widths and GET only.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
