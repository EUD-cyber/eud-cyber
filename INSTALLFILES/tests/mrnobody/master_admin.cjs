const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const web = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2/web');
(async () => {
    const browser = await chromium.launch({executablePath:process.env.MRN_CHROME_PATH, headless:true});
    try {
        const page = await browser.newPage({viewport:{width:1280,height:1000}});
        await page.clock.install();
        const calls = [], errors = [];
        let configured = false, authenticated = false, loseStart = true, rejectRetry = false, jobs = [], starts = [];
        const id = 'MRN-job-' + 'a'.repeat(32);
        const agent = {agent_id:'agent-1', name:'<img src=x onerror=alert(1)>', status:'online'};
        page.on('pageerror', error => errors.push(String(error)));
        await page.route('**/*', route => {
            const req = route.request(), url = new URL(req.url());
            if (url.pathname === '/master/admin') return route.fulfill({contentType:'text/html', body:fs.readFileSync(path.join(web, 'templates/master_admin.html'), 'utf8')});
            if (url.pathname.startsWith('/static/')) return route.fulfill({contentType:url.pathname.endsWith('.js') ? 'text/javascript' : 'text/css', body:fs.readFileSync(path.join(web, url.pathname.slice(1)), 'utf8')});
            calls.push({url, method:req.method(), headers:req.headers(), body:req.postData()});
            assert.equal(url.search, '');
            if (url.pathname.endsWith('/session')) {
                if (!configured) return route.fulfill({status:503, json:{message:'not configured'}});
                if (req.method() === 'POST') { assert.deepEqual(req.postDataJSON(), {credential:'a'.repeat(43)}); authenticated = true; }
                if (req.method() === 'DELETE') { assert.equal(req.headers()['x-csrf-token'], 'c'.repeat(43)); authenticated = false; }
                return route.fulfill({status:authenticated || req.method() === 'DELETE' ? 200 : 401,
                    json:authenticated ? {authenticated:true, csrf:'c'.repeat(43), web_job_control:true} : {authenticated:false}});
            }
            if (!authenticated) return route.fulfill({status:401, json:{message:'login required'}});
            if (url.pathname === '/api/master/agents') return route.fulfill({json:{agents:[agent,{agent_id:'offline',name:'Offline',status:'offline'}]}});
            if (url.pathname.endsWith('/jobs') && req.method() === 'POST') {
                assert.equal(req.headers()['x-csrf-token'], 'c'.repeat(43));
                starts.push(req.postDataJSON());
                if (rejectRetry) {rejectRetry = false; return route.fulfill({status:403,json:{message:'Retry rejected before dispatch'}});}
                jobs = [{job_id:id,agent_id:'agent-1',operation:'p11-live-lab',status:'running',stop_requested:false,reason:'',deadline:Date.now()/1000+180}];
                if (loseStart) {loseStart = false; return route.abort();}
                return route.fulfill({json:{job:jobs[0]}});
            }
            if (url.pathname.endsWith('/jobs')) return route.fulfill({json:{jobs}});
            if (url.pathname.endsWith('/stop')) {
                assert.deepEqual(req.postDataJSON(), {confirm_job_id:id});
                assert.equal(req.headers()['x-csrf-token'], 'c'.repeat(43));
                jobs[0].stop_requested = true;
                return route.fulfill({json:{job:jobs[0]}});
            }
            return route.fulfill({status:404,json:{message:'not found'}});
        });
        await page.goto('https://master.lab/master/admin');
        await page.getByRole('status').filter({hasText:'not configured'}).waitFor();
        assert.equal(await page.locator('#jobControl').isVisible(), false);
        configured = true;
        await page.getByLabel('Administrator credential', {exact:true}).fill('a'.repeat(43));
        await page.getByRole('button', {name:'Log in as administrator'}).click();
        await page.getByRole('status').filter({hasText:'Administrator authenticated'}).waitFor();
        await page.waitForFunction(() => document.querySelectorAll('#jobAgent option').length === 3);
        assert.equal(await page.locator('#jobAgent option[value="offline"]').isDisabled(), true);
        assert.equal(await page.locator('#jobStart').isDisabled(), true);
        assert.equal(await page.locator('#adminCredential').inputValue(), '');
        assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
        assert.ok(!(await page.content()).includes('a'.repeat(43)));
        assert.equal(await page.locator('img').count(), 0);
        await page.selectOption('#jobAgent', 'agent-1');
        await page.evaluate(() => { const start = document.getElementById('jobStart'); start.click(); start.click(); });
        await page.waitForFunction(() => document.getElementById('jobStart').textContent.includes('Retry'));
        await page.waitForFunction(() => !document.getElementById('jobStart').disabled);
        assert.equal(starts.length, 1);
        await page.reload();
        await page.waitForFunction(() => document.getElementById('jobStart').textContent.includes('Retry') && !document.getElementById('jobStart').disabled);
        rejectRetry = true;
        const rejected = page.waitForResponse(response => response.url().endsWith('/jobs') && response.status() === 403);
        await page.locator('#jobStart').click();
        await rejected;
        await page.waitForFunction(() => !document.getElementById('jobStart').disabled);
        assert.ok(await page.evaluate(() => sessionStorage.getItem('mrn-fixed-p11-pending')));
        await page.locator('#jobStart').click();
        await page.waitForFunction(() => document.getElementById('jobStart').textContent === 'Start fixed P11 job');
        assert.equal(starts.length, 3);
        assert.deepEqual(starts[0], starts[1]);
        assert.deepEqual(starts[0], starts[2]);
        assert.equal(await page.evaluate(() => sessionStorage.length + localStorage.length), 0);
        await page.waitForFunction(() => document.querySelectorAll('#jobList article').length === 1);
        const link = await page.locator('#jobList a').getAttribute('href');
        assert.ok(link.includes('campaign_id=' + id));
        assert.equal(await page.locator('#jobStart').isDisabled(), true);
        page.once('dialog', dialog => dialog.dismiss());
        await page.getByRole('button', {name:'Stop this job'}).click();
        assert.equal(calls.filter(call => call.url.pathname.endsWith('/stop')).length, 0);
        page.once('dialog', dialog => dialog.accept());
        await page.getByRole('button', {name:'Stop this job'}).click();
        await page.waitForFunction(() => document.getElementById('jobList').textContent.includes('stop requested'));
        assert.equal(calls.filter(call => call.url.pathname.endsWith('/stop')).length, 1);
        assert.equal(await page.getByRole('button', {name:'Stop this job'}).isDisabled(), true);
        jobs[0].status = 'stopped';
        await page.clock.fastForward(5000);
        await page.waitForFunction(() => document.getElementById('jobList').textContent.includes('Status: stopped'));
        assert.equal(starts.length, 3); // Refresh never starts another job.
        for (const width of [1280,768,390]) {
            await page.setViewportSize({width,height:1000});
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2));
        }
        if (process.env.MRN_UI_ARTIFACTS) {
            fs.mkdirSync(process.env.MRN_UI_ARTIFACTS, {recursive:true});
            await page.screenshot({path:path.join(process.env.MRN_UI_ARTIFACTS, 'master-p11-mobile.png'), fullPage:true});
        }
        await page.getByRole('button', {name:'Log out', exact:true}).click();
        await page.getByRole('status').filter({hasText:'Logged out'}).waitFor();
        assert.equal(await page.locator('#jobControl').isVisible(), false);
        const helper = fs.readFileSync(path.join(web, 'static/app.js'), 'utf8').match(/window\.mrnFetch = async[\s\S]*?\n};/)[0];
        await page.addScriptTag({content:helper});
        authenticated = true;
        await page.evaluate(() => { document.body.dataset.masterAdmin = 'true'; });
        await page.evaluate(() => window.mrnFetch('/api/update', {method:'POST', body:'{}', headers:{'Content-Type':'application/json'}}));
        assert.equal(calls.at(-1).headers['x-csrf-token'], 'c'.repeat(43));
        const beforeExternal = calls.length;
        assert.equal(await page.evaluate(async () => {
            try { await window.mrnFetch('https://evil.lab/api/update', {method:'POST'}); return false; }
            catch { return true; }
        }), true);
        assert.equal(calls.length, beforeExternal);
        await page.evaluate(() => { document.body.dataset.masterAdmin = 'false'; });
        const beforeLocal = calls.length;
        await page.evaluate(() => window.mrnFetch('/api/update', {method:'POST', body:'{}'}));
        assert.equal(calls.length, beforeLocal + 1);
        assert.equal(calls.at(-1).headers['x-csrf-token'], undefined);
        assert.deepEqual(errors, []);
        console.log('Master P11 UI passed: login, online selection, explicit start, no double click/reload replay, same-key lost-response retry, status refresh, confirmed/cancelled Stop, Receiver link, terminal state, logout, safe text and 3 widths.');
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
