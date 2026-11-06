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
                document.getElementById('campaignPowershell').value === '', count);
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
        const nav=page.locator('.sidebar-nav .nav-item');
        assert.deepEqual(await nav.allTextContents().then(a=>a.map(x=>x.trim().replace(/^[^A-Za-z]+/,''))),['Dashboard','Attack Techniques','Scenarios','Scheduler','Reports','MITRE ATT&CK','Settings']);
        assert.equal(await page.locator('#dashboardPhaseCount').textContent(),String(catalogue.count));
        await page.locator('[data-page="phases"]').click();
        await page.locator('#phaseGrid .technique-card').first().waitFor();
        assert.equal(await page.locator('#phaseGrid .technique-card').count(),catalogue.count);
        await page.evaluate(()=>updatePhases({'18':'partial'}));
        await page.locator('#techniqueSearch').fill('P18');
        assert.equal(await page.locator('#phaseGrid .phase-status').textContent(),'Partial');
        assert.equal(await page.locator('#phaseGrid .technique-card').count(),1);
        await page.locator('#phaseGrid .technique-card').click();
        for (const title of ['What does it do?','What should students detect?','MITRE ATT&CK','Teaching purpose','Execution']) assert.ok(await page.locator('#phaseDetail').getByRole('heading',{name:title,exact:true}).count());
        assert.ok((await page.locator('#phaseDetail').textContent()).includes(catalogue.phases.find(x=>x.id==='18').education.prerequisites));
        assert.equal(await page.locator('#phaseDetail a[href="https://attack.mitre.org/techniques/T1071/004/"]').count(),1);
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
        assert.equal(await page.locator('#reportPhaseFilter option[value="18"]').count(),1);
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
