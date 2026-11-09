/* Browser contracts: real Flask/registry data and read-only execution guard. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawn} = require('node:child_process');
const {chromium} = require('playwright');

async function checkFullIncident(page, artifacts) {
    await page.evaluate(() => configureScenario(null));
    const p10 = page.getByRole('region', {name: 'P10 – Custom Remote Command', exact: true});
    const p11 = page.getByRole('region', {name: 'P11 Persistence – Full Incident', exact: true});
    assert.equal(await p10.count(), 1);
    assert.equal(await p11.count(), 1);
    assert.equal(await p10.locator('#campaignPowershell, #campaignBash').count(), 2);
    assert.equal(await p10.locator('[data-campaign-p11]').count(), 0);
    assert.equal(await p11.locator('[data-campaign-p11]').count(), 6);
    assert.equal(await p11.locator('textarea').count(), 0);
    assert.equal(await page.locator('#page-campaigns').getByText('P09 changes mrnobody membership', {exact:false}).count(), 0);
    assert.equal(await page.evaluate(() => {
        const toggle = document.querySelector('label[for="powershellEnabled"]');
        const commands = document.getElementById('campaignPowershellFields');
        const persistence = document.getElementById('campaignPersistenceFields');
        return toggle.nextElementSibling === commands &&
            !!(commands.compareDocumentPosition(persistence) & Node.DOCUMENT_POSITION_FOLLOWING);
    }), true);
    const powershell = p10.getByLabel('PowerShell command (Windows, optional)', {exact:true});
    const bash = p10.getByLabel('Bash command (Linux, optional)', {exact:true});
    for (const field of [powershell, bash]) {
        assert.equal(await field.getAttribute('maxlength'), '16384');
        assert.equal(await field.getAttribute('rows'), '5');
    }
    await page.getByLabel('Enable P10 Custom Remote Command', {exact:true}).focus();
    await page.keyboard.press('Tab');
    assert.equal(await powershell.evaluate(el => el === document.activeElement), true);
    await page.keyboard.press('Tab');
    assert.equal(await bash.evaluate(el => el === document.activeElement), true);
    await powershell.fill('Write-Output layout-fixture');
    await bash.fill('printf layout-fixture');
    await p11.getByLabel('P11 reserved domain', {exact:true}).fill('layout.test');
    await p11.getByLabel('P11 internal lab DNS resolver', {exact:true}).fill('192.168.1.53');
    await p11.getByLabel('P11 periodic DNS', {exact:true}).selectOption('enabled');
    const persistence = await p11.locator('[data-campaign-p11]').evaluateAll(inputs =>
        Object.fromEntries(inputs.map(input => [input.dataset.campaignP11, input.value])));
    await page.evaluate(() => {showPage('scenarios'); configureScenario(null);});
    assert.equal(await powershell.inputValue(), 'Write-Output layout-fixture');
    assert.equal(await bash.inputValue(), 'printf layout-fixture');
    for (const width of [1440,1024,768,390]) {
        await page.setViewportSize({width,height:1050});
        const commandBox = await p10.boundingBox(), persistenceBox = await p11.boundingBox();
        assert.ok(commandBox.y + commandBox.height < persistenceBox.y, 'P10 card must end before P11');
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false,
            'Full Incident overflows at ' + width);
        for (const section of [p10,p11]) {
            assert.notEqual(await section.evaluate(el => getComputedStyle(el).borderTopStyle), 'none');
        }
        if (artifacts && [1440,390].includes(width))
            await page.screenshot({path:path.join(artifacts,'full-incident-' + width + '.png'),fullPage:true});
    }
    await page.setViewportSize({width:1440,height:1050});
    await page.getByLabel('Enable P10 Custom Remote Command', {exact:true}).uncheck();
    assert.equal(await p10.isVisible(), false);
    assert.equal(await p11.isVisible(), true);
    assert.equal(await page.locator('#campaignPowershell').inputValue(), '');
    assert.equal(await page.locator('#campaignBash').inputValue(), '');
    await page.getByLabel('Enable P10 Custom Remote Command', {exact:true}).check();

    // Capture real FormData in the browser; never send a campaign start to Flask.
    await page.evaluate(() => {
        window.fullIncidentSubmissions = [];
        window.fullIncidentFetch = window.fetch;
        window.fetch = async (url, options) => {
            if (/\/api\/(?:scenario\/[^/]+\/)?start$/.test(String(url))) {
                window.fullIncidentSubmissions.push({url:String(url), fields:Object.fromEntries(options.body.entries())});
                return new Response(JSON.stringify({message:'Fixture accepted'}), {status:200,headers:{'Content-Type':'application/json'}});
            }
            return window.fullIncidentFetch(url, options);
        };
    });
    const accept = dialog => dialog.accept();
    page.on('dialog', accept);
    try {
        for (const [id,value] of Object.entries({incidentIp:'192.168.1.254',webPorts:'80,443',
            sshUser:'ubuntu',sshPort:'22',rdpUser:'Administrator',rdpPort:'3389',exfilPort:'9090'}))
            await page.locator('#' + id).fill(value);
        await page.locator('#wordlistEnabled').uncheck();
        // Existing required-credential validation still prevents submission.
        await page.locator('#sshPassword').fill('');
        await page.locator('#startButton').click();
        assert.equal(await page.evaluate(() => fullIncidentSubmissions.length), 0);
        const cases = [['Write-Output fixture',''],['','printf fixture'],
            ['Write-Output fixture','printf fixture'],['   ','printf fixture'],
            ['Write-Output fixture',' \n '],[' \n ','\t '],['','']];
        for (const [index,[ps,sh]] of cases.entries()) {
            await powershell.fill(ps);
            await bash.fill(sh);
            assert.ok((await page.locator('#campaignP10Review').textContent()).includes(
                !ps.trim() && !sh.trim() ? 'skipped (NOT_CONFIGURED)' :
                'PowerShell ' + (ps.trim() ? 'configured' : 'not configured')));
            await page.locator('#sshPassword').fill('fixture-only');
            await page.locator('#rdpPassword').fill('fixture-only');
            // Exercise both default and explicitly selected Full Incident routes.
            await page.evaluate(explicit => {selectedScenario = explicit ?
                {id:'full-incident',name:'Full Incident',phases:['03','09','10','11']} : null;}, index % 2 === 1);
            const count = await page.evaluate(() => fullIncidentSubmissions.length);
            await page.locator('#startButton').click();
            await page.waitForFunction(count => fullIncidentSubmissions.length === count + 1 &&
                document.getElementById('campaignPowershell').value === '' &&
                document.getElementById('campaignBash').value === '' &&
                !document.getElementById('startButton').disabled, count);
            const sent = await page.evaluate(() => fullIncidentSubmissions.at(-1));
            assert.equal(sent.fields.powershell_enabled, '1');
            assert.equal(sent.fields.powershell_windows, ps);
            assert.equal(sent.fields.bash, sh);
            assert.deepEqual(JSON.parse(sent.fields.persistence), persistence);
            assert.equal(await bash.inputValue(), '');
        }
    } finally {
        page.off('dialog', accept);
        await page.evaluate(() => {window.fetch = window.fullIncidentFetch; configureScenario(null);});
    }
}

async function checkStandalonePorts(page, catalogue) {
    await page.locator('[data-page="phases"]').click();
    const defaults = {ssh:'22', rdp:'3389', winrm:'5985', 'winrm-http':'5985', 'winrm-https':'5986'};
    for (const id of ['04','05','06','07','08','10']) {
        const phase = catalogue.phases.find(p => p.id === id);
        await page.evaluate(item => renderPhaseDetail(item), phase);
        const protocol = page.locator(`#phase-${id}-protocol`), port = page.locator(`#phase-${id}-port`);
        const mode = page.getByLabel('Port mode', {exact:true});
        assert.equal(await mode.inputValue(), 'auto');
        assert.equal(await port.inputValue(), defaults[await protocol.inputValue()]);
        assert.equal(await port.isEditable(), false);
        for (const value of phase.education.configuration.protocol.options) {
            await protocol.selectOption(value); assert.equal(await port.inputValue(), defaults[value]);
        }
        await mode.selectOption('custom'); await port.fill('15985');
        for (const value of phase.education.configuration.protocol.options) {
            await protocol.selectOption(value); assert.equal(await port.inputValue(), '15985');
        }
    }
    await page.evaluate(item => renderPhaseDetail(item), catalogue.phases.find(p => p.id === '10'));
    assert.equal(await page.locator('#phase-10-protocol').inputValue(), 'winrm-http');
    assert.equal(await page.locator('#phase-10-port').inputValue(), '5985');
    await page.locator('#phase-10-target').fill('192.168.2.200');
    await page.locator('#phase-10-username').fill('Administrator');
    await page.locator('#phase-10-password').fill('fixture-only');
    await page.locator('#phase-10-powershell').fill('Write-Output "WINRM_OK"');
    const sent = [];
    await page.route('**/api/phase/10/run', route => {
        sent.push(route.request().postDataJSON());
        return route.fulfill({json:{message:'Offline fixture accepted'}});
    });
    const accept = dialog => dialog.accept(); page.on('dialog', accept);
    try {
        await page.getByRole('button', {name:'DRY RUN',exact:true}).click();
        await page.waitForFunction(() => document.getElementById('phase-10-password').value === 'fixture-only');
        await page.getByRole('button', {name:'RUN P10',exact:true}).click();
        await page.waitForFunction(() => document.getElementById('phase-10-password').value === '');
        assert.equal(sent.length, 2);
        for (const data of sent) {
            assert.equal(data.target, '192.168.2.200'); assert.equal(data.protocol, 'winrm-http');
            assert.equal(data.port_mode, 'auto'); assert.equal(data.port, '5985');
            assert.equal(data.username, 'Administrator'); assert.equal(data.password, 'fixture-only');
            assert.equal(data.powershell, 'Write-Output "WINRM_OK"');
        }
        assert.equal(sent[0].dry_run, true); assert.equal(sent[1].dry_run, false);
    } finally {
        page.off('dialog', accept); await page.unroute('**/api/phase/10/run');
    }
}

async function checkP06(page, phase) {
    await page.locator('[data-page="phases"]').click();
    await page.evaluate(item => renderPhaseDetail(item), phase);
    const feedback = page.locator('#phase-06-feedback');
    assert.equal(await page.locator('#phase-06-file').getAttribute('type'), 'text');
    assert.equal(await page.locator('#phase-06-protocol').evaluate(el => el.tagName), 'SELECT');
    await page.evaluate(() => {
        window.p06Submissions = [];
        window.p06OriginalFetch = window.fetch;
        window.p06Status = {incident_id:'MRN-p06-fixture',active:true,status:'running',execution:null};
        window.p06Reject = false;
        window.fetch = async (url, options) => {
            if (String(url) === '/api/phase/06/run') {
                window.p06Submissions.push(JSON.parse(options.body));
                return new Response(JSON.stringify(window.p06Reject ?
                    {message:'Staging incident ID mismatch'} :
                    {incident_id:'MRN-p06-fixture',message:'submitted'}), {
                    status:window.p06Reject ? 400 : 200,headers:{'Content-Type':'application/json'}});
            }
            if (String(url) === '/api/execution-status') return new Response(JSON.stringify(window.p06Status),
                {status:200,headers:{'Content-Type':'application/json'}});
            return window.p06OriginalFetch(url, options);
        };
    });
    try {
        await page.getByRole('button', {name:'RUN P06',exact:true}).click();
        assert.ok((await feedback.textContent()).includes('P06 requires:'));
        assert.equal(await feedback.isVisible(), true);
        assert.equal(await page.evaluate(() => p06Submissions.length), 0);
        const values = {target:'192.168.1.20',username:'student',password:' fixture secret ',
            file:'/tmp/.nordic-MRN-p05/nordic-data-MRN-p05.txt',staging_incident:'MRN-p05'};
        for (const [key,value] of Object.entries(values)) await page.locator('#phase-06-'+key).fill(value);
        await page.locator('#phase-06-protocol').selectOption('ssh');
        await page.locator('#phase-06-port-mode').selectOption('custom');
        await page.locator('#phase-06-port').fill('70000');
        await page.getByRole('button', {name:'RUN P06',exact:true}).click();
        assert.ok((await feedback.textContent()).includes('1–65535'));
        assert.equal(await page.evaluate(() => p06Submissions.length), 0);
        await page.locator('#phase-06-port').fill('22');
        await page.getByRole('button', {name:'RUN P06',exact:true}).click();
        await page.waitForFunction(() => document.getElementById('phase-06-feedback').textContent.includes('P06 running'));
        const sent = await page.evaluate(() => p06Submissions[0]);
        assert.equal(sent.file, values.file); assert.equal(sent.password, values.password);
        assert.equal(sent.staging_incident, values.staging_incident); assert.equal(sent.protocol, 'ssh');
        await page.getByRole('button', {name:'RUN P06',exact:true}).click();
        assert.equal(await page.evaluate(() => p06Submissions.length), 1);
        await page.evaluate(() => {p06Status.active=false;p06Status.status='failed';});
        await page.waitForFunction(() => document.getElementById('phase-06-feedback').textContent.includes('P06 failed'));
        await page.locator('#phase-06-password').fill('fixture');
        await page.evaluate(() => {p06Status.status='complete';});
        await page.getByRole('button', {name:'RUN P06',exact:true}).click();
        await page.waitForFunction(() => document.getElementById('phase-06-feedback').textContent.includes('P06 complete'));
        await page.locator('#phase-06-password').fill('fixture');
        await page.locator('#phase-06-file').fill('');
        await page.locator('#phase-06-staging_incident').fill('');
        await page.getByRole('button', {name:'RUN P06',exact:true}).click();
        await page.waitForFunction(() => document.getElementById('phase-06-feedback').textContent.includes('P06 complete'));
        const synthetic = await page.evaluate(() => p06Submissions.at(-1));
        assert.ok(!synthetic.file); assert.ok(!synthetic.staging_incident);
        await page.locator('#phase-06-password').fill('fixture');
        await page.evaluate(() => {p06Reject=true;});
        await page.getByRole('button', {name:'RUN P06',exact:true}).click();
        await page.waitForFunction(() => document.getElementById('phase-06-feedback').textContent.includes('Staging incident ID mismatch'));
        assert.equal(await feedback.isVisible(), true);
    } finally {
        await page.evaluate(() => {window.fetch=window.p06OriginalFetch;p06Feedback.pending=false;});
    }
}

async function checkP09(page, phase) {
    await page.locator('[data-page="phases"]').click();
    await page.evaluate(item => renderPhaseDetail(item), phase);
    const feedback = page.locator('#phase-09-feedback');
    assert.equal(await page.locator('#phase-09-protocol').inputValue(), 'WinRM HTTP');
    assert.equal(await page.locator('#phase-09-port').inputValue(), '5985');
    for (const field of ['protocol', 'port']) assert.equal(await page.locator('#phase-09-'+field).isEditable(), false);
    assert.equal(await page.locator('#phase-09-timeout').inputValue(), '60');
    await page.evaluate(() => {
        window.p09OriginalFetch = window.fetch; window.p09Submissions = []; window.p09Mode = 'running';
        window.fetch = async (url, options) => {
            if (String(url) === '/api/phase/09/run') {
                window.p09Submissions.push(JSON.parse(options.body));
                if (p09Mode === 'network') throw new TypeError('fixture disconnect');
                if (p09Mode === 'html') return new Response('<html>Bad gateway</html>', {status:502});
                if (p09Mode === 'reject') return new Response(JSON.stringify({message:'P09 requires a private lab IPv4 target'}), {status:400});
                return new Response(JSON.stringify({incident_id:'MRN-p09-ui',message:'submitted'}));
            }
            if (String(url) === '/api/execution-status') return new Response(JSON.stringify({
                incident_id:'MRN-p09-ui',active:p09Mode === 'running',status:p09Mode === 'running' ? 'running' : p09Mode}));
            if (String(url) === '/api/log') return new Response(JSON.stringify({log:'PHASE_START\\nWINDOWS_PORT_CHECK\\nwinrm_http_port_unreachable\\nPHASE_FAILED'}));
            return p09OriginalFetch(url, options);
        };
    });
    try {
        await page.getByRole('button', {name:'RUN P09',exact:true}).click();
        assert.ok((await feedback.textContent()).includes('P09 requires:'));
        assert.equal(await page.evaluate(() => p09Submissions.length), 0);
        for (const [key,value] of Object.entries({target:'192.168.1.20',username:'student',password:' fixture secret '}))
            await page.locator('#phase-09-'+key).fill(value);
        await page.getByRole('button', {name:'RUN P09',exact:true}).click();
        await page.waitForFunction(() => document.getElementById('phase-09-feedback').textContent.includes('P09 running'));
        const sent = await page.evaluate(() => p09Submissions[0]);
        assert.equal(sent.protocol, 'winrm-http'); assert.equal(sent.port, 5985); assert.equal(sent.password, ' fixture secret ');
        assert.equal(await page.getByRole('button', {name:'RUN P09',exact:true}).isDisabled(), true);
        assert.equal(await page.locator('#phase-09-password').inputValue(), '');
        await page.evaluate(() => {p09Mode='failed';});
        await page.waitForFunction(() => document.getElementById('phase-09-feedback').textContent.includes('P09 failed'));
        await page.evaluate(() => refreshLog());
        assert.ok((await page.locator('#phasesLog').textContent()).includes('winrm_http_port_unreachable'));
        for (const mode of ['complete', 'skipped', 'reject', 'network', 'html']) {
            await page.locator('#phase-09-password').fill('fixture');
            await page.evaluate(value => {p09Mode=value;}, mode);
            await page.getByRole('button', {name:'RUN P09',exact:true}).click();
            const expected = {complete:'P09 complete',skipped:'P09 skipped',reject:'private lab IPv4',network:'could not be confirmed',html:'invalid response'}[mode];
            await page.waitForFunction(text => document.getElementById('phase-09-feedback').textContent.includes(text), expected);
            assert.equal(await feedback.isVisible(), true);
        }
    } finally {
        await page.evaluate(() => {window.fetch=p09OriginalFetch;p09Feedback.pending=false;});
    }
}

async function main() {
    const server=spawn(process.env.MRN_TEST_PYTHON || 'python',['-u','tests/mrnobody/ui_server.py'],{stdio:['ignore','pipe','pipe'],env:process.env});
    let browser;
    try {
        const url=await new Promise((resolve,reject)=>{
            const timer=setTimeout(()=>reject(new Error('UI server start timed out')),20000);
            let output='';server.stdout.on('data',chunk=>{output+=chunk;const m=output.match(/UI_TEST_URL=(http:\/\/127\.0\.0\.1:\d+)/);if(m){clearTimeout(timer);resolve(m[1]);}});
            server.stderr.on('data',data=>{if(String(data).includes('Traceback'))reject(new Error(String(data)));});
            server.on('exit',code=>{clearTimeout(timer);reject(new Error('UI server exited '+code));});
        });
        browser=await chromium.launch(process.env.MRN_CHROME_PATH ? {executablePath:process.env.MRN_CHROME_PATH,headless:true} : {headless:true});
        const page=await browser.newPage({viewport:{width:1440,height:1050},locale:'en-GB'});
        const errors=[];page.on('pageerror',error=>errors.push(String(error)));
        await page.goto(url);
        await page.waitForFunction(()=>document.getElementById('dashboardPhaseCount').textContent !== '—');
        const catalogue=await (await page.request.get(url+'/api/phases')).json();
        await checkStandalonePorts(page, catalogue);
        await checkP06(page, catalogue.phases.find(p => p.id === '06'));
        await checkP09(page, catalogue.phases.find(p => p.id === '09'));
        const nav=page.locator('.sidebar-nav .nav-item');
        assert.deepEqual(await nav.allTextContents().then(a=>a.map(x=>x.trim().replace(/^[^A-Za-z]+/,''))),['Dashboard','Attack Techniques','Scenarios','Scheduler','Reports','MITRE ATT&CK','Settings']);
        assert.equal(await page.locator('#dashboardPhaseCount').textContent(),String(catalogue.count));
        await page.locator('[data-page="phases"]').click();
        await page.locator('#phaseGrid .technique-card').first().waitFor();
        assert.equal(await page.locator('#phaseGrid .technique-card').count(),catalogue.count);
        assert.deepEqual(catalogue.phases.map(p=>p.id), Array.from({length:11},(_,i)=>String(i+1).padStart(2,'0')));
        for (const id of ['12','13','14','15','16','17','18']) {
            await page.locator('#techniqueSearch').fill('P'+id);
            assert.equal(await page.locator('#phaseGrid .technique-card').count(),0);
        }
        await page.locator('#techniqueSearch').fill('P11');
        await page.locator('#phaseGrid .technique-card').click();
        for (const title of ['What does it do?','What should students detect?','MITRE ATT&CK','Teaching purpose','Execution']) assert.ok(await page.locator('#phaseDetail').getByRole('heading',{name:title,exact:true}).count());
        assert.ok((await page.locator('#phaseDetail').textContent()).includes(catalogue.phases.find(x=>x.id==='11').education.prerequisites));
        await page.locator('#techniqueSearch').fill('');
        await page.locator('#techniquePlatform').selectOption('Windows');
        assert.equal(await page.locator('#phaseGrid .technique-card').count(),catalogue.phases.filter(x=>x.education.platforms.includes('Windows')).length);
        await page.locator('#techniqueTactic').selectOption('Persistence');
        assert.equal(await page.locator('#phaseGrid .technique-card').count(),catalogue.phases.filter(x=>x.education.platforms.includes('Windows')&&x.education.tactics.includes('Persistence')).length);
        const allTactics = page.locator('#catalogTactics .tactic-count').first();
        assert.equal(await allTactics.textContent(), `All tactics · ${catalogue.count}`);
        await allTactics.click();
        assert.equal(await page.locator('#techniqueTactic').inputValue(), '');
        assert.equal(await page.locator('#phaseGrid .technique-card').count(), catalogue.count);
        assert.ok(await page.locator('#catalogTactics').getByRole('button', {name: /^Collection ·/}).count());
        await page.locator('#techniqueMode').selectOption('Scheduler');
        await page.locator('#techniqueReadiness').selectOption('Installed');
        await page.locator('#techniqueSearch').fill('does-not-exist');
        assert.ok((await page.locator('#phaseGrid').textContent()).includes('No Attack Techniques match'));
        await page.locator('[data-page="mitre"]').click();
        assert.equal(await page.locator('.mitre-tactic').count(),new Set(catalogue.phases.flatMap(x=>x.education.tactics)).size);
        await page.locator('.mitre-tactic .mapped-technique').first().click();
        assert.equal(await page.locator('#page-phases').isVisible(),true);
        assert.equal(await page.locator('#phaseGrid .phase-selected').count(),1);
        assert.equal(await page.locator('.nav-active').count(),1);
        // P11 uses real registry fields; changing platform filters paired methods.
        await page.evaluate(item => renderPhaseDetail(item), catalogue.phases.find(p => p.id === '11'));
        assert.equal(await page.locator('#phase-11-persistence_domain').inputValue(), 'evilcorp.test');
        await page.locator('#phase-11-platform').selectOption('linux');
        assert.equal(await page.locator('#phase-11-method option[value="cron-systemd"]').isDisabled(), false);
        assert.equal(await page.locator('#phase-11-method option[value="task-service"]').isDisabled(), true);
        await page.locator('#phase-11-platform').selectOption('windows');
        assert.equal(await page.locator('#phase-11-method option[value="task-service"]').isDisabled(), false);
        assert.equal(await page.locator('#phase-11-persistence_dns option[value="enabled"]').count(), 1);
        await page.locator('[data-page="scenarios"]').click();
        assert.ok(await page.locator('#scenarioGrid .phase-card').count());
        await checkFullIncident(page, process.env.MRN_UI_ARTIFACTS);
        await page.locator('[data-page="scenarios"]').click();
        await page.locator('#scenarioGrid .phase-card').first().press('Enter');
        assert.ok(await page.locator('#scenarioDetail button').count());
        await page.locator('#newCustomScenario').click();
        for(let i=0;i<2;i++)await page.locator('#builderBody').getByRole('button',{name:'Next',exact:true}).click();
        assert.equal(await page.locator('.builder-selection').isVisible(),true);
        assert.ok((await page.locator('.builder-selected').textContent()).includes('Auto-added prerequisite'));
        await page.locator('.builder-choices').getByRole('button',{name:/P10/}).click();
        assert.ok((await page.locator('.builder-selected').textContent()).includes('P03'));
        await page.locator('.builder-choices').getByRole('button',{name:/P11/}).click();
        await page.locator('#builderBody').getByRole('button',{name:'Next',exact:true}).click();
        await page.locator('#builderBody').getByLabel(/^P11 periodic DNS activity/).selectOption('enabled');
        await page.locator('#builderBody').getByLabel('P11 internal non-forwarding lab DNS resolver', {exact:true}).fill('192.168.1.53');
        await page.locator('#builderBody').getByLabel('P11 reserved test domain (.test)', {exact:true}).fill('fixture.test');
        for(let i=0;i<3;i++) await page.locator('#builderBody').getByRole('button',{name:'Next',exact:true}).click();
        assert.ok((await page.locator('#builderBody').textContent()).includes('fixture.test'), await page.locator('#builderBody').textContent());
        await page.locator('[data-page="schedules"]').click();
        assert.ok((await page.locator('#scheduleList').textContent()).includes('No schedules saved'));
        await page.locator('#scheduleList').getByRole('button',{name:'New schedule / Run Now'}).click();
        assert.equal(await page.locator('#scheduleEditor').isVisible(),true);
        await page.locator('[data-page="reports"]').click();
        await page.waitForFunction(()=>document.getElementById('reportTable').textContent.includes('No incident reports'));
        assert.equal(await page.locator('#reportPhaseFilter option[value="18"]').count(),0);
        await page.locator('[data-page="system"]').click();
        await page.waitForFunction(()=>document.getElementById('settingsRuntime').textContent.includes('Version'));
        assert.equal(await page.locator('#page-system input[type=checkbox]').count(),0);
        assert.equal(await page.locator('#updateButton').isVisible(),true);
        // No advertised read-only preview can launch an execution.
        assert.equal((await page.request.post(url+'/api/start',{data:{}})).status(),403);
        // Hostile strings remain text even in rich detail sections and badges.
        await page.evaluate(()=>{const item={id:'99',name:'<img src=x onerror=alert(1)>',standalone:false,parameters:[],education:{description:'<script>bad()</script>',tactics:['<img src=x>'],platforms:['<svg onload=bad()>'],readiness:'<img src=x>'},mitre:{techniques:[]}};window.MrnUI.setCatalogue([item]);renderPhaseDetail(item);});
        assert.equal(await page.locator('#phaseDetail img, #phaseDetail script, #phaseGrid svg').count(),0);
        // Reload restores real metadata for responsive QA and screenshots.
        await page.reload();await page.waitForFunction(()=>document.getElementById('dashboardPhaseCount').textContent !== '—');
        const artifacts=process.env.MRN_UI_ARTIFACTS;
        for(const width of [1440,1024,768,390]) {
            await page.setViewportSize({width,height:1050});
            for(const section of ['dashboard','phases','scenarios','schedules','reports','mitre','system']) {
                await page.locator(`[data-page="${section}"]`).click();
                assert.equal(await page.locator(`#page-${section}`).isVisible(),true);
                const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);
                assert.equal(overflow,false,`${section} overflows at ${width}px`);
                if(artifacts&&(width===1440||width===390))await page.screenshot({path:path.join(artifacts,`${section}-${width}.png`),fullPage:true});
            }
            await page.locator('[data-page="scenarios"]').click();await page.locator('#newCustomScenario').click();
            for(let i=0;i<2;i++)await page.locator('#builderBody').getByRole('button',{name:'Next',exact:true}).click();
            assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false,`builder overflows at ${width}px`);
            if(artifacts&&(width===1440||width===390))await page.screenshot({path:path.join(artifacts,`builder-${width}.png`),fullPage:true});
        }
        assert.deepEqual(errors,[]);
        console.log('Browser UI passed: live registry search/filter/detail, MITRE navigation, builder dependencies, scheduler, reports, settings, safe rendering and 1440/1024/768/390px layouts.');
    } finally {if(browser)await browser.close();server.kill();}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
