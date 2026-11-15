const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const base = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2');
const html = fs.readFileSync(path.join(base, 'web/templates/index.html'), 'utf8').replace(/\{\{\s*url_for\('static', filename='([^']+)'\)\s*\}\}/g, (_, n) => '/static/' + n);
const parameters = fs.readFileSync(path.join(base,'scripts/06-exfil.sh'),'utf8').match(/ATTACK_PARAMETERS="([^"]+)"/)[1].split(',');
const phase={id:'06',name:'Exfiltration',parameters,education:{configuration:{protocol:{options:['ssh','winrm-http','winrm-https']}}}};
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.MRN_CHROME_PATH,headless:true});
 try {
  const page=await browser.newPage();const writes=[],errors=[];
  page.on('pageerror',e=>errors.push(String(e)));
  await page.route('**/*',route=>{
   const url=new URL(route.request().url());
   if(route.request().method()!=='GET') {
    writes.push(route.request().postDataJSON());
    return route.fulfill({json:{status:'success',incident_id:'MRN-ui-test'}});
   }
   if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:html});
   if(url.pathname.startsWith('/static/')) return route.fulfill({body:fs.readFileSync(path.join(base,'web',url.pathname.slice(1))),contentType:url.pathname.endsWith('.css')?'text/css':'text/javascript'});
   if(url.pathname==='/api/health')return route.fulfill({json:{deployment:{role:'agent',config_status:'loaded'}}});
   if(url.pathname==='/api/phase/06/status')return route.fulfill({json:{incident_id:'MRN-ui-test',status:'complete'}});
   return route.fulfill({json:{status:'idle',active:false,phases:[],scenarios:[],schedules:[],reports:[],hosts:[],networks:[],phase_status:{}}});
  });
  await page.goto('https://mrnobody.test/');await page.waitForLoadState('networkidle');
  await page.evaluate(phase=>{showPage('phases');renderPhaseDetail(phase);},phase);
  assert.equal(await page.locator('#phase-06-live-lab').isChecked(),false);
  for(const [key,value] of Object.entries({target:'10.0.0.5',username:'student',password:'training-only'}))await page.locator('#phase-06-'+key).fill(value);
  await page.locator('#phase-06-protocol').selectOption('ssh');
  await page.locator('#phase-06-live-lab').check();
  await page.evaluate(phase=>runStandalonePhase(phase),phase);
  assert.equal(writes.length,1);assert.equal(writes[0].live_lab,true);
  await page.waitForFunction(()=>!p06Feedback.pending);
  await page.locator('#phase-06-password').fill('training-only');
  await page.locator('#phase-06-file').fill('/etc/shadow');
  await page.evaluate(phase=>runStandalonePhase(phase),phase);
  assert.equal(writes.length,1);
  assert.match(await page.locator('#phase-06-feedback').textContent(),/requires the generated/);
  await page.evaluate(phase=>renderPhaseDetail(phase),phase);
  assert.equal(await page.locator('#phase-06-live-lab').isChecked(),false);
  assert.deepEqual(errors,[]);
  console.log('P06 browser: unchecked default, explicit outbound opt-in payload, custom path blocked, selection resets.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
