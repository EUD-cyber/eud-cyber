const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const base = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2/web');
const html = fs.readFileSync(path.join(base, 'templates/index.html'), 'utf8')
    .replace(/\{\{\s*url_for\('static', filename='([^']+)'\)\s*\}\}/g, (_, n) => '/static/' + n)
    .replace(/data-master-admin="[^"]*"/, 'data-master-admin="true"');
const online = {agent_id:'online-agent', name:'Live', status:'online', last_seen_at:1700000000};
const old = {agent_id:'old-agent', name:'<img src=x onerror=alert(1)>', status:'offline', last_seen_at:1700000000,
    reports_synced_at:1700000000, reports:[{id:'MRN-history', status:'complete', report_type:'campaign'}], available_reports:['MRN-history']};
let agents = [online, old], archived = [], writes = [], fail = false, reject = false, csrfRequests = 0;
const shared = {status:'idle', active:false, execution:null, phases:[], scenarios:[], schedules:[], reports:[], networks:[], hosts:[], log:'', phase_status:{}};
(async () => {
    const browser = await chromium.launch({executablePath:process.env.MRN_CHROME_PATH, headless:true});
    try {
        const page = await browser.newPage({viewport:{width:1440, height:1050}});
        const errors = [];
        page.on('pageerror', error => errors.push(String(error)));
        await page.route('**/*', async route => {
            const request = route.request(), url = new URL(request.url());
            if (url.pathname === '/') return route.fulfill({contentType:'text/html', body:html});
            if (url.pathname.startsWith('/static/')) {
                const file = path.join(base, url.pathname.slice(1));
                return route.fulfill({contentType:file.endsWith('.css')?'text/css':'text/javascript', body:fs.readFileSync(file)});
            }
            if (url.pathname === '/api/health') return route.fulfill({json:{status:'ok', service:'MrNobody Incident Platform', deployment:{role:'master', config_status:'loaded'}}});
            if (url.pathname === '/api/master/admin/session') {
                csrfRequests++;
                return route.fulfill({json:{authenticated:true, csrf:'a'.repeat(43), web_job_control:true}});
            }
            if (request.method() !== 'GET') {
                writes.push({url:url.pathname, body:request.postDataJSON(), csrf:request.headers()['x-csrf-token']});
                if (fail) return route.abort();
                if (reject) return route.fulfill({status:409, json:{message:'Agent has active jobs.'}});
                assert.equal(url.pathname, '/api/master/admin/agents/old-agent/remove');
                archived = [{...old, status:'removed', removal:{removed_at:1700000100, actor:'master-operator'}}];
                agents = [online];
                return route.fulfill({json:{agent_id:'old-agent', removed:true}});
            }
            if (url.pathname === '/api/master/agents') return route.fulfill({json:{agents}});
            if (url.pathname === '/api/master/admin/removed-agents') return route.fulfill({json:{agents:archived}});
            return route.fulfill({json:shared});
        });
        await page.goto('https://mrnobody.test/');
        await page.locator('#masterAgentsTab').click();
        const remove = () => page.getByRole('button', {name:'Remove agent old-agent', exact:true});
        await remove().waitFor();
        assert.equal(await page.getByRole('button', {name:'Remove agent online-agent', exact:true}).isDisabled(), true);
        assert.equal(await remove().isEnabled(), true);
        assert.equal(await page.locator('#masterAgentsRuntime img').count(), 0);
        async function attempt(answer) {
            page.once('dialog', async dialog => {
                assert.equal(dialog.type(), 'prompt');
                assert.match(dialog.message(), /old-agent/);
                assert.match(dialog.message(), /permanently revoked/);
                if (answer === null) await dialog.dismiss();
                else await dialog.accept(answer);
            });
            await remove().click();
        }
        await attempt(null);
        assert.equal(writes.length, 0);
        await attempt('online-agent');
        await page.getByRole('status').filter({hasText:'ID did not match'}).waitFor();
        assert.equal(writes.length, 0);
        reject = true;
        await attempt('old-agent');
        await page.getByRole('status').filter({hasText:'Agent has active jobs'}).waitFor();
        await page.waitForFunction(() => document.querySelector('[aria-label="Remove agent old-agent"]')?.disabled === false);
        assert.equal(await remove().isEnabled(), true);
        assert.equal(writes.length, 1);
        assert.deepEqual(writes[0].body, {confirm_agent_id:'old-agent'});
        assert.equal(writes[0].csrf, 'a'.repeat(43));
        reject = false; fail = true;
        await attempt('old-agent');
        await page.getByRole('status').filter({hasText:'Could not remove old-agent'}).waitFor();
        await page.waitForFunction(() => document.querySelector('[aria-label="Remove agent old-agent"]')?.disabled === false);
        assert.equal(await remove().isEnabled(), true);
        fail = false;
        // Simulate a new heartbeat after a previous offline display.
        agents = [online, {...old, status:'online'}];
        await page.locator('#masterAgentsRefresh').click();
        await page.waitForFunction(() => document.querySelector('[aria-label="Remove agent old-agent"]')?.disabled);
        agents = [online, old];
        await page.locator('#masterAgentsRefresh').click();
        await page.waitForFunction(() => document.querySelector('[aria-label="Remove agent old-agent"]')?.disabled === false);
        await attempt('old-agent');
        await page.getByRole('status').filter({hasText:'Removed old-agent'}).waitFor();
        assert.equal(await remove().count(), 0);
        assert.equal(await page.getByRole('button', {name:'View agent online-agent', exact:true}).count(), 1);
        await page.getByRole('button', {name:'Load removed agents', exact:true}).click();
        await page.getByRole('button', {name:'View removed agent old-agent', exact:true}).click();
        const detail = page.locator('#masterAgentDetail');
        assert.match(await detail.textContent(), /Removed.*master-operator.*Old credentials are revoked/s);
        assert.equal(await detail.getByRole('link', {name:'View report', exact:true}).getAttribute('href'), '/api/master/agents/old-agent/reports/MRN-history');
        assert.equal(await detail.getByRole('link', {name:'View retained Receiver events'}).getAttribute('href'), '/api/master/receiver/events?agent_id=old-agent');
        assert.equal(await page.locator('#masterAgentsRuntime img').count(), 0);
        for (const width of [1440, 768, 390]) {
            await page.setViewportSize({width, height:1050});
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2));
        }
        assert.ok(csrfRequests >= 3);
        assert.deepEqual(errors, []);
        console.log('Agent removal browser checks passed: row controls, exact ID, cancel, conflict, network error, CSRF, refresh, retained history, escaping and responsive layouts.');
    } finally {
        await browser.close();
    }
})().catch(error => {console.error(error); process.exitCode=1;});
