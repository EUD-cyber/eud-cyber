const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const base = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2');
const html = fs.readFileSync(path.join(base, 'web/templates/index.html'), 'utf8').replace(/\{\{\s*url_for\('static', filename='([^']+)'\)\s*\}\}/g, (_, n) => '/static/' + n);
const parameters = fs.readFileSync(path.join(base,'scripts/11-persistence.sh'),'utf8').match(/ATTACK_PARAMETERS="([^"]+)"/)[1].split(',');
const phase={id:'11',name:'Persistence',parameters,education:{configuration:{protocol:{options:['ssh','winrm-http','winrm-https']}}}};
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.MRN_CHROME_PATH,headless:true});
 try {
  const page=await browser.newPage();const writes=[],errors=[];
  page.on('pageerror',e=>errors.push(String(e)));page.on('dialog',d=>d.accept());
  await page.route('**/*',route=>{
   const url=new URL(route.request().url());
   if(route.request().method()!=='GET') {
    writes.push(route.request().postDataJSON());
    return route.fulfill({json:{status:'started',incident_id:'MRN-ui-test'}});
   }
   if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:html});
   if(url.pathname.startsWith('/static/')) return route.fulfill({body:fs.readFileSync(path.join(base,'web',url.pathname.slice(1))),contentType:url.pathname.endsWith('.css')?'text/css':'text/javascript'});
   if(url.pathname==='/api/health')return route.fulfill({json:{deployment:{role:'agent',config_status:'loaded'}}});
   return route.fulfill({json:{status:'idle',active:false,phases:[],scenarios:[],schedules:[],reports:[],hosts:[],networks:[],phase_status:{}}});
  });
  await page.goto('https://mrnobody.test/');await page.waitForLoadState('networkidle');
  await page.evaluate(phase=>{showPage('phases');renderPhaseDetail(phase);},phase);
  assert.equal(await page.locator('#phase-11-live-lab').isChecked(),false);
  assert.equal(await page.locator('#phase-11-beacon-interval').inputValue(),'30');
  for(const [key,value] of Object.entries({target:'10.0.0.5',username:'student',password:'training-only',artifact:'p11-beacon-test'}))await page.locator('#phase-11-'+key).fill(value);
  await page.locator('#phase-11-protocol').selectOption('ssh');
  await page.locator('#phase-11-method').selectOption('systemd');
  await page.locator('#phase-11-persistence_dns').selectOption('enabled');
  await page.locator('#phase-11-persistence_resolver').fill('10.0.0.53');
  await page.locator('#phase-11-live-lab').check();
  await page.evaluate(phase=>runStandalonePhase(phase),phase);
  assert.equal(writes.length,1);assert.equal(writes[0].p11_live_lab,true);
  assert.equal(writes[0].beacon_interval,30);assert.equal(writes[0].beacon_count,6);
  assert.equal(writes[0].persistence_dns,'enabled');assert.equal(writes[0].method,'systemd');
  await page.locator('#phase-11-action').selectOption('cleanup');
  await page.evaluate(phase=>runStandalonePhase(phase),phase);assert.equal(writes.length,1);
  await page.locator('#phase-11-live-lab').uncheck();
  await page.evaluate(phase=>runStandalonePhase(phase),phase);
  assert.equal(writes.length,2);assert.equal(writes[1].p11_live_lab,false);
  await page.evaluate(phase=>renderPhaseDetail(phase),phase);
  assert.equal(await page.locator('#phase-11-live-lab').isChecked(),false);
  assert.deepEqual(errors,[]);
  console.log('P11 browser: opt-in/reset, bounded defaults, DNS retained, cleanup cannot start beacons.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
