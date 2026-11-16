const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const web = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2/web');
const html = fs.readFileSync(path.join(web,'templates/index.html'),'utf8').replace(/\{\{\s*url_for\('static', filename='([^']+)'\)\s*\}\}/g, (_,name) => '/static/' + name);
(async () => {
    const browser = await chromium.launch({executablePath:process.env.MRN_CHROME_PATH,headless:true});
    try {
        const page = await browser.newPage({viewport:{width:1440,height:1050}});
        await page.clock.install();
        const errors=[]; page.on('pageerror', error => errors.push(String(error)));
        await page.route('**/*', route => {
            const url=new URL(route.request().url());
            if (url.pathname === '/') return route.fulfill({contentType:'text/html',body:html});
            if (url.pathname.startsWith('/static/')) return route.fulfill({contentType:url.pathname.endsWith('.css')?'text/css':'text/javascript',body:fs.readFileSync(path.join(web,url.pathname.slice(1)))});
            if (url.pathname === '/api/health') return route.fulfill({json:{status:'ok',deployment:{role:'agent',config_status:'loaded',master_url_configured:true}}});
            return route.fulfill({json:{status:'idle',active:false,phases:[],scenarios:[],reports:[],schedules:[],hosts:[],networks:[],phase_status:{},log:''}});
        });
        await page.goto('https://slave.lab/');
        await page.waitForFunction(() => !document.getElementById('campaignP06LiveLab').disabled);
        await page.evaluate(() => configureScenario(null));
        const p06=page.locator('#campaignP06LiveLab'), p11=page.locator('#campaignP11LiveLab');
        assert.equal(await p06.isChecked(),false); assert.equal(await p11.isChecked(),false);
        assert.equal(await page.locator('#campaignBeaconCount').isDisabled(),true);
        await page.evaluate(() => {
            window.liveSubmissions=[];
            const original=window.fetch;
            window.fetch=async (url,options) => {
                if (options?.method === 'POST' && /\/api\/(?:scenario\/[^/]+\/)?start$/.test(String(url))) {
                    liveSubmissions.push({url:String(url),fields:Object.fromEntries(options.body.entries())});
                    return new Response(JSON.stringify({status:'started'}),{status:200,headers:{'Content-Type':'application/json'}});
                }
                return original(url,options);
            };
            window.confirm=text => {window.liveConfirmation=text;return true;};
        });
        async function submit() {
            for (const [id,value] of Object.entries({incidentIp:'192.168.1.5',webPorts:'80,443',sshUser:'ubuntu',sshPassword:'fixture-only',sshPort:'22',rdpUser:'Administrator',rdpPassword:'fixture-only',rdpPort:'3389',exfilPort:'9090'})) await page.locator('#'+id).fill(value);
            await page.locator('#wordlistEnabled').uncheck();
            await page.locator('#powershellEnabled').uncheck();
            await page.evaluate(() => startCampaign());
        }
        await submit();
        let sent=await page.evaluate(() => liveSubmissions.at(-1));
        assert.equal(sent.fields.p06_live_lab,'false'); assert.equal(sent.fields.p11_live_lab,'false');
        assert.equal(sent.fields.beacon_interval,undefined);
        await p06.check(); await p11.check();
        assert.equal(await page.locator('#campaignBeaconCount').isDisabled(),false);
        await page.locator('#campaignBeaconInterval').fill('30');
        await page.locator('#campaignBeaconDuration').fill('90');
        await page.locator('#campaignBeaconCount').fill('3');
        await submit();
        sent=await page.evaluate(() => liveSubmissions.at(-1));
        assert.deepEqual(Object.fromEntries(['p06_live_lab','p11_live_lab','beacon_interval','beacon_duration','beacon_count'].map(key=>[key,sent.fields[key]])),
            {p06_live_lab:'true',p11_live_lab:'true',beacon_interval:'30',beacon_duration:'90',beacon_count:'3'});
        const confirmation=await page.evaluate(() => liveConfirmation);
        assert.ok(confirmation.includes('one generated file on one verified P03 host'));
        assert.ok(confirmation.includes('3 Slave-origin attempts, 30s interval, 90s limit'));
        assert.ok(!JSON.stringify(JSON.parse(sent.fields.persistence)).includes('live_lab'));
        const before=await page.evaluate(() => liveSubmissions.length);
        await page.locator('#campaignBeaconCount').fill('61'); await submit();
        assert.equal(await page.evaluate(() => liveSubmissions.length),before);
        assert.match(await page.locator('#messageBox').textContent(),/beacon_count/);
        await page.locator('#campaignBeaconCount').fill('3');
        await page.evaluate(() => {window.confirm=() => false;}); await submit();
        assert.equal(await page.evaluate(() => liveSubmissions.length),before);
        for (const width of [1440,768,390]) {
            await page.setViewportSize({width,height:1050});
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2));
        }
        await page.evaluate(() => configureScenario({id:'preset-recon-only',name:'Recon',phases:['01'],runnable:true}));
        assert.equal(await p06.isChecked(),false); assert.equal(await p11.isChecked(),false);
        assert.equal(await page.locator('#campaignLiveLabFields').isVisible(),false);
        await page.evaluate(() => configureScenario(null));
        assert.equal(await page.locator('#campaignBeaconCount').inputValue(),'6');
        await p06.check();
        await page.evaluate(() => configureCampaignLiveLab({role:'master',config_status:'loaded',master_url_configured:true}));
        assert.equal(await p06.isChecked(),false); assert.equal(await p06.isDisabled(),true);
        await page.evaluate(() => configureCampaignLiveLab({role:'agent',config_status:'loaded',master_url_configured:true}));
        await p11.check();
        await page.evaluate(() => configureCampaignLiveLab(null));
        assert.equal(await p11.isChecked(),false); assert.equal(await p11.isDisabled(),true);
        assert.deepEqual(errors,[]);
        console.log('Campaign Live Lab UI passed: unchecked defaults, Agent gating, explicit multipart selections, bounded P11 values, confirmation/cancel, scenario reset, health-loss reset, no scenario persistence and 3 widths.');
    } finally { await browser.close(); }
})().catch(error => {console.error(error);process.exitCode=1;});