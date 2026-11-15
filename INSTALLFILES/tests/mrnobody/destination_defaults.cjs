const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const base = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2');
const html = fs.readFileSync(path.join(base, 'web/templates/index.html'), 'utf8').replace(/\{\{\s*url_for\('static', filename='([^']+)'\)\s*\}\}/g, (_, n) => '/static/' + n);
(async () => {
 const browser = await chromium.launch({executablePath:process.env.MRN_CHROME_PATH, headless:true});
 try {
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  const errors=[]; page.on('pageerror', e => errors.push(String(e)));
  let ip='', url='', writes=0, hold=false, release;
  await page.route('**/*', async route => {
   if (route.request().method() !== 'GET') { writes++; return route.fulfill({status:403}); }
   const p = new URL(route.request().url()).pathname;
   if (p === '/') return route.fulfill({contentType:'text/html', body:html});
   if (p.startsWith('/static/')) return route.fulfill({body:fs.readFileSync(path.join(base, 'web', p.slice(1))), contentType:p.endsWith('.css')?'text/css':'text/javascript'});
   if (p === '/api/config') {
    if (hold) await new Promise(resolve => { release=resolve; });
    return route.fulfill({json:{receiver_suggestions:{ipv4:ip, url}}});
   }
   if (p === '/api/health') return route.fulfill({json:{deployment:{role:'standalone',config_status:'loaded'}}});
   return route.fulfill({json:{status:'idle',active:false,phases:[],scenarios:[],schedules:[],reports:[],hosts:[],networks:[],phase_status:{}}});
  });
  for (const [address, full] of [['10.20.30.40','https://10.20.30.40:8443/api/'],['',''],['','https://master.test:9443/base']]) {
   ip=address; url=full;
   await page.goto('https://mrnobody.test/'); await page.waitForLoadState('networkidle');
   assert.equal(await page.locator('#incidentIp').inputValue(), address);
   for (const id of ['06','11']) {
    const script=fs.readFileSync(path.join(base,'scripts',id==='06'?'06-exfil.sh':'11-persistence.sh'),'utf8');
    const parameters=script.match(/ATTACK_PARAMETERS="([^"]+)"/)[1].split(',');
    await page.evaluate(phase => renderPhaseDetail(phase), {id,name:'Test phase',parameters});
    assert.equal(await page.locator(`#phase-${id}-target`).inputValue(),'');
    if(id==='11') assert.equal(await page.locator('#phase-11-persistence_resolver').inputValue(),'');
   }
   await page.evaluate(() => showPage('campaigns'));
   await page.locator('#incidentIp').fill('10.9.8.7');
   await page.evaluate(() => loadConfiguration());
   assert.equal(await page.locator('#incidentIp').inputValue(),'10.9.8.7');
   await page.locator('#incidentIp').fill('');
   await page.evaluate(() => loadConfiguration());
   assert.equal(await page.locator('#incidentIp').inputValue(),'');
  }
  hold=true; ip='10.20.30.40';
  await page.goto('https://mrnobody.test/');
  await page.waitForFunction(() => !!document.getElementById('incidentIp'));
  await page.evaluate(() => showPage('campaigns'));
  await page.locator('#incidentIp').fill('10.1.1.2');
  for (let i=0; !release && i<500; i++) await new Promise(r=>setTimeout(r,10));
  assert.ok(release, 'config request must start');
  release(); await page.waitForLoadState('networkidle');
  assert.equal(await page.locator('#incidentIp').inputValue(),'10.1.1.2');
  assert.equal(writes,0); assert.deepEqual(errors,[]);
  console.log('Destination UI: editable hints, blank defaults, phase scope, refresh/clear/race preservation; no writes.');
 } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exitCode=1;});
