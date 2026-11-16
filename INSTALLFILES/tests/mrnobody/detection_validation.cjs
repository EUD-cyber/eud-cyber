const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const web = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2/web');
(async () => {
    const browser = await chromium.launch({executablePath:process.env.MRN_CHROME_PATH,headless:true});
    try {
        const page = await browser.newPage({viewport:{width:1280,height:1000},acceptDownloads:true});
        const errors = [], calls = []; let delay = false, release;
        page.on('pageerror',error => errors.push(String(error)));
        const summary = {schema_version:1,agent_id:'agent-1',campaign_id:'MRN-test',coverage:'unknown',
            verdict:'no_correlated_alert_in_supplied_slice',counts:{correlated_alert:0,candidate_alert:1,
                correlated_telemetry:0,candidate_telemetry:1,unmatched:0,ignored:0,duplicates:1,parsed:3},
            reference:{report_status:'not_synchronized',receiver_page_truncated:true},
            sources:[{kind:'wazuh',sha256:'b'.repeat(64),bytes:100}],limitations:['Untrusted imported evidence.'],
            receipts:[{id:1,phase:'P11',received_at:1700000000,ground_truth_linked:false,
                reference_techniques:['T1071.001'],phase_metadata_techniques:['T1543.003'],
                sensor_evidence:{correlated_alert:0,candidate_alert:1,correlated_telemetry:0,candidate_telemetry:1}}],
            rows:[{kind:'wazuh',line:1,sha256:'c'.repeat(64),timestamp:'2023-11-14T22:13:20Z',
                classification:'candidate_alert',rule_id:'100001',rule_techniques:['T1071.001','javascript:alert(1)'],
                receiver_event_ids:[1],receiver_match_count:1,basis:['declared_observer_and_time_only']}]};
        await page.route('**/*',async route => {
            const req=route.request(),url=new URL(req.url());
            if(url.pathname==='/master/validation')return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(web,'templates/detection_validation.html'),'utf8')});
            if(url.pathname.startsWith('/static/'))return route.fulfill({contentType:url.pathname.endsWith('.js')?'text/javascript':'text/css',body:fs.readFileSync(path.join(web,url.pathname.slice(1)),'utf8')});
            calls.push({path:url.pathname,method:req.method()});
            if(url.pathname==='/api/master/agents')return route.fulfill({json:{agents:[
                {agent_id:'agent-1',name:'<img src=x onerror=alert(1)>',status:'online'},
                {agent_id:'offline',status:'offline'},{agent_id:'revoked',status:'revoked'}]}});
            if(url.pathname.endsWith('/session'))return route.fulfill({json:{authenticated:true,csrf:'s'.repeat(43)}});
            assert.equal(url.pathname,'/api/master/admin/validation');assert.equal(req.method(),'POST');
            assert.equal(req.headers()['x-csrf-token'],'s'.repeat(43));assert.equal(url.search,'');
            assert.equal(req.postDataJSON().sources[0].content,'{"secret":"PRIVATE-RAW"}\n');
            if(delay)await new Promise(resolve=>{release=resolve;});
            return route.fulfill({json:summary});
        });
        await page.goto('https://master.lab/master/validation?agent_id=agent-1&campaign_id=MRN-test');
        await page.waitForFunction(()=>document.querySelector('#validationAgent').value==='agent-1');
        assert.equal(await page.locator('#validationAgent option').count(),3);
        assert.equal(await page.locator('img').count(),0);
        assert.equal(calls.filter(c=>c.method==='POST').length,0);
        await page.locator('#validationWazuhId').fill('001');
        await page.locator('#validationWazuh').setInputFiles({name:'slice.ndjson',mimeType:'application/json',buffer:Buffer.from('{"secret":"PRIVATE-RAW"}\n')});
        assert.equal(calls.filter(c=>c.method==='POST').length,0);
        await page.locator('#validationRun').click();
        await page.waitForFunction(()=>!document.querySelector('#validationDownload').disabled);
        assert.match(await page.locator('#validationResult').innerText(),/coverage unknown/);
        assert.match(await page.locator('#validationResult').innerText(),/not a “not detected” verdict/);
        assert.match(await page.locator('#validationResult').innerText(),/not_synchronized/);
        assert.match(await page.locator('#validationResult').innerText(),/Bounded output/);
        assert.ok(!(await page.content()).includes('PRIVATE-RAW'));
        assert.equal(await page.locator('a[href^="javascript:"]').count(),0);
        assert.ok(await page.locator('a[href="https://attack.mitre.org/techniques/T1071/001/"]').count()>0);
        const waiting=page.waitForEvent('download');await page.locator('#validationDownload').click();
        const download=await waiting;const stream=await download.createReadStream();let text='';
        for await(const chunk of stream)text+=chunk.toString();
        assert.equal(JSON.parse(text).coverage,'unknown');assert.ok(!text.includes('PRIVATE-RAW'));
        assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
        for(const width of [1280,768,390]){
            await page.setViewportSize({width,height:1000});
            assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));
        }
        if(process.env.MRN_UI_ARTIFACTS){fs.mkdirSync(process.env.MRN_UI_ARTIFACTS,{recursive:true});
            await page.screenshot({path:path.join(process.env.MRN_UI_ARTIFACTS,'detection-validation-mobile.png'),fullPage:true});}
        await page.locator('#validationCampaign').fill('MRN-changed');
        assert.equal(await page.locator('#validationResult').innerText(),'');
        assert.equal(await page.locator('#validationDownload').isDisabled(),true);
        delay=true;await page.locator('#validationRun').click();
        await page.waitForFunction(()=>document.querySelector('#validationRun').disabled);
        while(!release)await page.waitForTimeout(10);
        await page.locator('#validationClear').click();release();
        await page.waitForTimeout(100);
        assert.equal(await page.locator('#validationResult').innerText(),'');
        assert.equal(await page.locator('#validationDownload').isDisabled(),true);
        assert.equal(await page.locator('#validationWazuh').evaluate(el=>el.files.length),0);
        const posts=calls.filter(c=>c.method==='POST').length;
        await page.locator('#validationWazuh').setInputFiles({name:'large.json',mimeType:'application/json',buffer:Buffer.alloc(512*1024+1,120)});
        await page.locator('#validationRun').click();
        await page.getByRole('status').filter({hasText:'exceed 512 KiB'}).waitFor();
        assert.equal(calls.filter(c=>c.method==='POST').length,posts);
        assert.deepEqual(errors,[]);
        console.log('PASS detection validation: manual/CSRF import, safe rendering/download, candidate labels, stale response, clear, size bound and 3 widths.');
    } finally {await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
