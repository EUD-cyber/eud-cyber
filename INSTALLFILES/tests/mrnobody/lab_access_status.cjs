// Browser authority and transport are separate even with a valid read-session cookie.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const web = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2/web');
const html = fs.readFileSync(path.join(web,'templates/index.html'),'utf8')
    .replace(/\{\{\s*url_for\('static', filename='([^']+)'\)\s*\}\}/g, (_, name) => '/static/' + name)
    .replace('data-master-admin="{{ \'true\' if master_admin_required else \'false\' }}"', 'data-master-admin="true"');
(async () => {
    const browser = await chromium.launch({executablePath:process.env.MRN_CHROME_PATH,headless:true});
    try {
        const page = await browser.newPage();
        let authorized = false, unavailable = false;
        const writes = [], errors = [];
        page.on('pageerror', error => errors.push(String(error)));
        await page.route('**/*', route => {
            const req = route.request(), url = new URL(req.url());
            if (url.pathname === '/') return route.fulfill({contentType:'text/html',body:html});
            if (url.pathname.startsWith('/static/')) return route.fulfill({
                body:fs.readFileSync(path.join(web,url.pathname.slice(1))),
                contentType:url.pathname.endsWith('.css') ? 'text/css' : 'text/javascript'});
            if (url.pathname === '/api/master/admin/session') return route.fulfill({
                status:unavailable ? 503 : 200,
                json:{authenticated:true,lab_mode:true,web_job_control:authorized,csrf:'c'.repeat(43)}});
            if (req.method() !== 'GET') {
                writes.push(req.headers());
                return route.fulfill({json:{status:'success'}});
            }
            return route.fulfill({json:{status:'idle',active:false,phases:[],scenarios:[],
                schedules:[],reports:[],hosts:[],networks:[],phase_status:{}}});
        });
        async function attempt(url = '/api/execute') {
            return page.evaluate(async target => {
                try { await window.mrnFetch(target,{method:'POST',body:'{}'}); return 'sent'; }
                catch (error) { return error.message; }
            },url);
        }
        await page.goto('http://slave.lab/');
        await page.locator('#labAccessStatus').filter({hasText:'read-only for this browser'}).waitFor();
        assert.match(await attempt(),/read-only/);
        assert.equal(writes.length,0);
        assert.equal(await page.locator('a[href="/lab/control"]').count(),0);
        authorized = true;
        await page.reload();
        await page.locator('#labAccessStatus').filter({hasText:'this browser is authorized'}).waitFor();
        assert.equal(await attempt(),'sent');
        assert.equal(writes.length,1);
        assert.equal(writes[0]['x-csrf-token'],'c'.repeat(43));
        assert.match(await attempt('http://other-lab.test/api/execute'),/Same-origin/);
        unavailable = true;
        await page.reload();
        await page.locator('#labAccessStatus').filter({hasText:'access status unavailable'}).waitFor();
        assert.notEqual(await attempt(),'sent');
        assert.equal(writes.length,1);
        assert.deepEqual(errors,[]);
        console.log('PASS browser access status: read session cannot mutate, explicit authority sends CSRF, cross-origin and unavailable authority fail closed; no handoff link in normal GUI.');
    } finally { await browser.close(); }
})().catch(error => {console.error(error);process.exitCode=1;});
