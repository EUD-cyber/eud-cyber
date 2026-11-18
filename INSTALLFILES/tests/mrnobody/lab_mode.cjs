const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const http=require('node:http');
const {spawn}=require('node:child_process');
const {once}=require('node:events');
const readline=require('node:readline');
const {chromium}=require('playwright');
const web=path.resolve(__dirname,'../../TESTFILES/ATTACKER-V2/web');

async function checkNavigation(browser){
    const command=process.env.MRN_FIXTURE_COMMAND ? JSON.parse(process.env.MRN_FIXTURE_COMMAND)
        : [process.env.MRN_PYTHON||'python',path.join(__dirname,'lab_mode.py')];
    const fixture=spawn(command[0],[...command.slice(1),'--navigation-server'],
        {stdio:['pipe','pipe','pipe']});
    const lines=readline.createInterface({input:fixture.stdout});
    let target,portal,page,diagnostics='';
    fixture.stderr.on('data',data=>{diagnostics=(diagnostics+data).slice(-4000);});
    try{
        const ready=await Promise.race([
            once(lines,'line'),
            once(fixture,'exit').then(()=>{throw new Error('Navigation fixture exited: '+diagnostics);}),
            new Promise((_,reject)=>{const timer=setTimeout(()=>reject(new Error('Navigation fixture timeout: '+diagnostics)),15000);timer.unref();})
        ]);
        const {ports}=JSON.parse(ready[0]);
        portal=http.createServer((req,res)=>{
            if(req.url==='/redirect'){res.writeHead(302,{Location:target});res.end();}
            else{res.setHeader('Content-Type','text/html');res.end('<a href="'+target+'">Open lab</a><a href="/redirect">Redirect to lab</a>');}
        }).listen(0,'127.0.0.1');
        await once(portal,'listening');
        page=await browser.newPage();
        for(const port of ports){
            for(const host of ['127.0.0.1','localhost']){
                target='http://'+host+':'+port+'/';
                const source='http://'+(host==='localhost'?'127.0.0.1':'localhost')+':'+portal.address().port;
                for(const redirect of [false,true]){
                    await page.goto(source);
                    const [response]=await Promise.all([page.waitForNavigation(),
                        page.getByRole('link',{name:redirect?'Redirect to lab':'Open lab',exact:true}).click()]);
                    assert.equal(response.status(),200,await response.text());
                    const headers=await response.request().allHeaders();
                    assert.equal(headers['sec-fetch-site'],'cross-site');
                    assert.equal(headers['sec-fetch-mode'],'navigate');
                    assert.equal(headers['sec-fetch-dest'],'document');
                    assert.equal(await page.locator('body').innerText(),'dashboard');
                    const session=await page.evaluate(async()=>{
                        const result=await fetch('/api/master/admin/session');return {status:result.status,body:await result.json()};
                    });
                    assert.equal(session.status,200);assert.equal(session.body.authenticated,true);
                    assert.equal(session.body.web_job_control,true);
                    const saved=await page.evaluate(async csrf=>{
                        const result=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:'{}'});
                        return {status:result.status,body:await result.json()};
                    },session.body.csrf);
                    assert.equal(saved.status,200);assert.equal(saved.body.saved,true);
                }
            }
        }
        console.log('PASS real Flask/browser: portal links/redirects into Master/Slave via IP/DNS, automatic CSRF and immediate GUI writes without activation.');
    }finally{
        if(page)await page.close();
        if(portal)await new Promise(resolve=>portal.close(resolve));
        lines.close();fixture.stdin.end();
        if(fixture.exitCode===null){
            const timer=setTimeout(()=>fixture.kill(),5000);timer.unref();
            await once(fixture,'exit');clearTimeout(timer);
        }
    }
}
(async()=>{
    const browser=await chromium.launch({executablePath:process.env.MRN_CHROME_PATH,headless:true});
    try{
        await checkNavigation(browser);
        const page=await browser.newPage({viewport:{width:1280,height:1000}});
        const starts=[],errors=[];let lost=true,job=null,stops=0;
        page.on('pageerror',e=>errors.push(String(e)));
        await page.route('**/*',route=>{
            const req=route.request(),url=new URL(req.url());assert.equal(url.protocol,'http:');
            if(url.pathname==='/master/admin')return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(web,'templates/master_admin.html'),'utf8')});
            if(url.pathname==='/lab/control')return route.fulfill({contentType:'text/html',body:fs.readFileSync(path.join(web,'templates/lab_control.html'),'utf8')});
            if(url.pathname.startsWith('/static/'))return route.fulfill({contentType:url.pathname.endsWith('.js')?'text/javascript':'text/css',body:fs.readFileSync(path.join(web,url.pathname.slice(1)),'utf8')});
            if(url.pathname.endsWith('/session')){
                assert.equal(req.method(),'GET'); // Never activate or log in from the GUI.
                return route.fulfill({json:{authenticated:true,lab_mode:true,web_job_control:true,csrf:'c'.repeat(43)}});
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
        await page.getByRole('status').filter({hasText:'Lab Mode: controls ready'}).waitFor();
        assert.equal(await page.locator('#adminLogin').isVisible(),false);
        assert.equal(await page.locator('#adminLogout').isVisible(),false);
        assert.match(await page.locator('#adminAccessHint').innerText(),/available automatically/);
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
        await page.goto('http://master.lab/master/admin');
        await page.getByRole('status').filter({hasText:'Lab Mode: controls ready'}).waitFor();
        assert.equal(await page.locator('#adminLogin').isVisible(),false);
        assert.equal(await page.locator('#adminLogout').isVisible(),false);
        assert.equal(starts.length,2);assert.equal(stops,1);
        for(const width of [1280,768,390]){
            await page.setViewportSize({width,height:1000});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));
        }
        assert.deepEqual(errors,[]);
        console.log('PASS open Lab Mode UI: IP/DNS, no login/logout, automatic controls, no automatic job, reload retry, CSRF, confirmed Stop, 3 widths.');
    }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
