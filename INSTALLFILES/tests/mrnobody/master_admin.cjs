const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require('playwright');
const web = path.resolve(__dirname, '../../TESTFILES/ATTACKER-V2/web');
(async () => {
    const browser = await chromium.launch({executablePath:process.env.MRN_CHROME_PATH, headless:true});
    try {
        const page = await browser.newPage();
        const calls = [], errors = [];
        let unavailable = true, authenticated = false;
        page.on('pageerror', error => errors.push(String(error)));
        await page.route('**/*', route => {
            const req = route.request(), url = new URL(req.url());
            if (url.pathname === '/master/admin') return route.fulfill({contentType:'text/html', body:fs.readFileSync(path.join(web, 'templates/master_admin.html'), 'utf8')});
            if (url.pathname.startsWith('/static/')) return route.fulfill({contentType:url.pathname.endsWith('.js') ? 'text/javascript' : 'text/css', body:fs.readFileSync(path.join(web, url.pathname.slice(1)), 'utf8')});
            calls.push({url, method:req.method(), headers:req.headers(), body:req.postData()});
            assert.equal(url.pathname, '/api/master/admin/session');
            assert.equal(url.search, '');
            if (unavailable) return route.fulfill({status:503, json:{message:'not configured'}});
            if (req.method() === 'POST') {
                assert.deepEqual(req.postDataJSON(), {credential:'a'.repeat(43)});
                authenticated = true;
            }
            if (req.method() === 'DELETE') {
                assert.equal(req.headers()['x-csrf-token'], 'c'.repeat(43));
                assert.deepEqual(req.postDataJSON(), {});
                authenticated = false;
            }
            return route.fulfill({status:authenticated || req.method() === 'DELETE' ? 200 : 401,
                json:authenticated ? {authenticated:true, csrf:'c'.repeat(43), web_job_control:false} : {authenticated:false}});
        });
        await page.goto('https://master.lab/master/admin');
        await page.getByRole('status').filter({hasText:'not configured'}).waitFor();
        unavailable = false;
        await page.getByLabel('Administrator credential', {exact:true}).fill('a'.repeat(43));
        await page.getByRole('button', {name:'Validate administrator login'}).click();
        await page.getByRole('status').filter({hasText:'Administrator authenticated'}).waitFor();
        assert.equal(await page.locator('#adminCredential').inputValue(), '');
        assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
        assert.ok(!(await page.content()).includes('a'.repeat(43)));
        await page.reload();
        await page.getByRole('status').filter({hasText:'Administrator authenticated'}).waitFor();
        await page.getByRole('button', {name:'Log out', exact:true}).click();
        await page.getByRole('status').filter({hasText:'Logged out'}).waitFor();
        assert.equal(calls.filter(call => call.method === 'POST').length, 1);
        assert.equal(calls.filter(call => call.method === 'DELETE').length, 1);
        assert.equal(await page.getByRole('button', {name:/start|stop/i}).count(), 0);
        assert.deepEqual(errors, []);
        console.log('Master admin prerequisite UI passed: missing configuration, login, refresh, logout, no token storage or job requests.');
    } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
