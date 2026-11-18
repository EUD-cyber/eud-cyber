const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require('playwright');
const web=path.resolve(__dirname,'../../TESTFILES/ATTACKER-V2/web');
(async()=>{
    const browser=await chromium.launch({executablePath:process.env.MRN_CHROME_PATH,headless:true});
    try{
        const page=await browser.newPage({viewport:{width:1280,height:1000}});
        const starts=[],errors=[];let lost=true,job=null,stops=0,readOnly=false;
        page.on('pageerror',e=>errors.push(String(e)));
        await page.route('**/*',route=>{
            const req=route.request(),url=new URL(req.url());assert.equal(url.protocol,'http:');
            if(url.pathname==='/master/admin')return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(web,'templates/master_admin.html'),'utf8')});
            if(url.pathname.startsWith('/static/'))return route.fulfill({contentType:url.pathname.endsWith('.js')?'text/javascript':'text/css',body:fs.readFileSync(path.join(web,url.pathname.slice(1)),'utf8')});
            if(url.pathname.endsWith('/session')){
                assert.equal(req.method(),'GET');return route.fulfill({json:{authenticated:true,lab_mode:true,web_job_control:!readOnly,csrf:'c'.repeat(43)}});
            }
            if(url.pathname==='/api/master/agents')return route.fulfill({json:{agents:[{agent_id:'agent-1',status:'online',name:'Slave'}]}});
            if(url.pathname.endsWith('/jobs')&&req.method()==='POST'){
                assert.equal(req.headers()['x-csrf-token'],'c'.repeat(43));starts.push(req.postDataJSON());
                assert.match(starts.at(-1).request_key,/^web-[a-f0-9-]{36}$/);
                job={job_id:'MRN-job-'+'a'.repeat(32),agent_id:'agent-1',operation:'p11-live-lab',status:'running',stop_requested:false};
                if(lost){lost=false;return route.abort();}return route.fulfill({json:{job}});
            }
            if(url.pathname.endsWith('/jobs'))return route.fulfill({json:{jobs:job?[job]:[]}});
            if(url.pathname.endsWith('/stop')){
                assert.equal(req.headers()['x-csrf-token'],'c'.repeat(43));assert.deepEqual(req.postDataJSON(),{confirm_job_id:job.job_id});
                stops++;job.status='stopped';job.stop_requested=true;return route.fulfill({json:{job}});
            }
            throw new Error('Unexpected route '+url.pathname);
        });
        await page.goto('http://192.168.50.3/master/admin');
        await page.getByRole('status').filter({hasText:'Lab Mode: access'}).waitFor();
        assert.equal(await page.locator('#adminLogin').isVisible(),false);
        assert.equal(await page.locator('#adminLogout').isVisible(),false);
        assert.match(await page.locator('#adminAccessHint').innerText(),/HTTP exposes/);
        assert.equal(starts.length,0);
        await page.selectOption('#jobAgent','agent-1');await page.locator('#jobStart').click();
        await page.waitForFunction(()=>document.querySelector('#jobStart').textContent.includes('Retry'));
        await page.reload();
        await page.waitForFunction(()=>document.querySelector('#jobStart').textContent.includes('Retry')&&!document.querySelector('#jobStart').disabled);
        await page.locator('#jobStart').click();
        await page.waitForFunction(()=>document.querySelectorAll('#jobList article').length===1 && sessionStorage.length===0);
        assert.equal(starts.length,2);assert.deepEqual(starts[0],starts[1]);
        assert.equal(await page.evaluate(()=>sessionStorage.length+localStorage.length),0);
        page.once('dialog',d=>d.dismiss());await page.getByRole('button',{name:'Stop this job'}).click();assert.equal(stops,0);
        page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'Stop this job'}).click();
        await page.waitForFunction(()=>document.querySelector('#jobList').textContent.includes('Status: stopped'));
        assert.equal(stops,1);
        readOnly=true;job.status='running';job.stop_requested=false;
        await page.goto('http://master.lab/master/admin');
        await page.getByRole('status').filter({hasText:'read-only access'}).waitFor();
        await page.waitForFunction(()=>document.querySelectorAll('#jobList article').length===1);
        assert.equal(await page.locator('#adminLogin').isVisible(),false);
        assert.equal(await page.locator('#jobStart').isDisabled(),true);
        assert.equal(await page.getByRole('button',{name:'Stop this job'}).isDisabled(),true);
        assert.equal(starts.length,2);assert.equal(stops,1);
        for(const width of [1280,768,390]){
            await page.setViewportSize({width,height:1000});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));
        }
        assert.deepEqual(errors,[]);
        console.log('PASS HTTP Lab Mode UI: IP/DNS without login, read-only start/stop disabled, no automatic job, reload retry, CSRF, confirmed Stop, 3 widths.');
    }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
