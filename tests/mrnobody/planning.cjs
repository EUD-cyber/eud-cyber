const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const elements = new Map();
function element(tag = 'div') {
    return {tag, children: [], listeners: {}, value: '', checked: false,
        appendChild(child) {this.children.push(child);},
        replaceChildren() {this.children = [];},
        addEventListener(name, fn) {this.listeners[name] = fn;},
        setAttribute(name,value) {this[name]=value;}
    };
}
for (const id of ['builderBody','planningMessage','customLibrary','scheduleEditor','scheduleList','newCustomScenario']) elements.set(id, element());
const dependencyMap = {'01':[], '02':['01'], '03':['01'], '04':['03'], '05':['03'], '06':['03','05'], '07':['03'], '08':['01','03'], '09':['03'], '10':['03'], '11':['03']};
const caps = Object.entries(dependencyMap).map(([id, dependencies]) => ({
    id, dependencies, name:{'01':'Discovery','02':'Web Discovery','03':'Initial Access','04':'Lateral Movement','05':'Staging','06':'Exfiltration','07':'Impact','08':'Wordlist Authentication'}[id],
    fields: id === '01' ? {subnet:{label:'Subnets',type:'networks'}} : {
        target:{label:'Target IPv4',type:'ipv4'}, protocol:{label:'Protocol',options:['ssh','rdp']}, port:{label:'Port',type:'port'},
        ...(id === '04' ? {source:{label:'Source IPv4',type:'ipv4'}} : {}),
        ...(id === '06' ? {file:{label:'Synthetic staged file',type:'path'}} : {})},
    required_fields: id === '01' ? ['subnet'] : ['target', ...(['03','08'].includes(id) ? ['protocol'] : []), ...(id === '04' ? ['source'] : []), ...(id === '06' ? ['file'] : [])],
    timing: ['01','02'].includes(id) ? ['start_offset','duration','delay_min','delay_max','jitter'] : ['start_offset'],
    credentials:['03','04','05','06','07','09','10','11'].includes(id), wordlist:id === '08', standalone:true,
    runtime_powershell:id === '10'
}));
for (const cap of caps.filter(c=>['09','10'].includes(c.id))) {
    cap.name = cap.id === '09' ? 'AD Privilege Escalation' : 'Custom PowerShell';
    cap.fields.protocol.options = ['winrm-http','winrm-https'];
    cap.fields.timeout = {label:'Action timeout',type:'timeout'};
    cap.required_fields = ['target','protocol'];
}
for (const cap of caps.filter(c=>['10','11'].includes(c.id))) {
    cap.name = cap.id === '10' ? 'Custom Remote Command' : 'Persistence';
    cap.fields.protocol.options = ['ssh','winrm-http','winrm-https'];
    cap.fields.platform = {label:'Execution platform',options:['auto','windows','linux']};
    cap.fields.timeout = {label:'Action timeout',type:'timeout'};
    cap.required_fields = ['target','protocol'];
    if (cap.id === '11') {
        cap.fields.method = {label:'Persistence method',options:['auto','scheduled-task','service','cron','systemd']};
        cap.fields.action = {label:'Persistence action',options:['create','cleanup']};
        cap.fields.artifact = {label:'Artifact suffix',type:'text'};
    }
}
const definitions = [], plans = [], requests = [];
const context = vm.createContext({document:{getElementById:id=>elements.get(id) || [...elements.values()].flatMap(walk).find(n=>n.id===id), createElement:element, querySelectorAll:()=>[],addEventListener(){}},
    window:{}, Date, Intl, console, FormData, showPage:page=>{context.page=page;}, confirm:()=>true,
    fetch:async (url, options={}) => {
        const data = options.body instanceof FormData ? options.body : options.body ? JSON.parse(options.body) : null;
        requests.push({url, method:options.method,data});
        let value = {};
        if (url === '/api/planning/capabilities') value={phases:caps};
        if (url === '/api/custom-scenarios') {
            if (options.method==='POST') {value={...data,id:'custom-'+definitions.length};definitions.push(value);}
            else value={scenarios:definitions};
        }
        if (url.startsWith('/api/custom-scenarios/') && options.method==='PUT') {
            value = data; definitions.splice(definitions.findIndex(d=>d.id===data.id),1,data);
        }
        if (url === '/api/scenarios') value={scenarios:[{id:'full-incident',name:'Full Incident'},...definitions.map(x=>({...x,custom:true}))]};
        if (url === '/api/schedules') {
            if(options.method==='POST'){value={id:'schedule-test'};plans.push({...data,id:value.id,next_run:data.at,last_status:'never'});}
            else value={schedules:plans};
        }
        if(url === '/api/executions/run' || url.startsWith('/api/scenario/')) value={status:'started'};
        return {ok:true,json:async()=>value};
    }
});
vm.runInContext(fs.readFileSync(__dirname+'/../../TESTFILES/ATTACKER-V2/web/static/planning.js','utf8'),context);
const walk = node => [node,...node.children.flatMap(walk)];
const body = () => elements.get('builderBody');
const textButton = (root,label) => walk(root).find(n=>n.tag==='button'&&n.textContent===label);
const click = async (root,label) => {const b=textButton(root,label);assert.ok(b,label);b.listeners.click();await new Promise(r=>setImmediate(r));};
const field = (root,label) => {const wrapper=walk(root).find(n=>n.tag==='label'&&n.children[0]?.textContent===label);assert.ok(wrapper,label);return wrapper.children[1];};
const change = (input,value) => {input.value=value;input.listeners.change();};
const text = root => walk(root).map(n => n.textContent || '').join('\n');
const set = (label,value,root=body()) => change(field(root,label),value);
const next = () => click(body(),'Next');
const back = () => click(body(),'Back');
const phaseRows = () => body().children.filter(n=>n.className==='planning-row' && n.children.some(c=>c.tag==='span' && /^P\d\d ·/.test(c.textContent)));
const row = id => phaseRows().find(n=>text(n).includes('P'+id+' ·'));
const ids = () => phaseRows().map(n=>n.children.find(c=>c.tag==='span').textContent.slice(1,3));
const error = () => walk(body()).find(n=>n.className==='planning-error').textContent;
const title = () => body().children[0].textContent;
const add = async id => {set('Add phase',id);await click(body(),'Add');};
async function select(mode='auto') {context.window.MrnPlanning.newDraft();await next();if(mode==='fixed')set('Targets','fixed');await next();}
async function review() {while(textButton(body(),'Next')) {await next();assert.equal(error(),'');}}
async function main() {
    await context.window.MrnPlanning.refresh();
    context.window.MrnPlanning.newDraft();
    set('Name','');await next();assert.match(error(),/name/);assert.match(title(),/^1\./);
    set('Name','<img src=x onerror=alert(1)>');set('Description',' ');await next();assert.match(error(),/Description/);
    set('Description','Lab');await next();set('Targets','bad');await next();assert.match(error(),/Choose/);
    set('Targets','auto');await next();assert.deepEqual(ids(),['01']);
    assert.ok(row('01').children.find(n=>n.type==='checkbox').disabled);
    assert.ok(textButton(row('01'),'↓').disabled);
    await click(row('01'),'Remove');assert.deepEqual(ids(),['01']);
    await add('06');assert.deepEqual(ids(),['01','03','05','06']);
    assert.match(text(row('05')),/Auto-added prerequisite/);assert.match(text(row('06')),/staged data from P05/);
    assert.ok(textButton(row('03'),'Remove').disabled);assert.ok(textButton(row('06'),'↑').disabled);
    await click(row('06'),'↑');assert.deepEqual(ids(),['01','03','05','06']);
    const check=row('03').children.find(n=>n.type==='checkbox');check.checked=false;check.listeners.change();assert.ok(row('03').children.find(n=>n.type==='checkbox').checked);
    await add('08');assert.deepEqual(ids(),['01','03','05','06','08']);
    await add('02');assert.equal(new Set(ids()).size,ids().length);
    await click(row('02'),'↑');assert.deepEqual(ids(),['01','03','05','06','02','08']);
    await click(row('08'),'Remove');assert.ok(!row('08'));
    await next();assert.equal(walk(body()).filter(n=>n.tag==='input').length,0);
    await back();await back();set('Targets','fixed');await next();assert.deepEqual(ids(),['06','02']);
    await back();set('Targets','auto');await next();assert.deepEqual(ids(),['01','03','05','06','02']);

    await select('fixed');assert.deepEqual(ids(),[]);await next();assert.match(error(),/Enable at least one/);
    for(const id of ['01','03','04','06'])await add(id);
    await next();await next();assert.match(title(),/^4\./);assert.match(error(),/P01/);
    set('Common Target (optional)','192.168.1.20');assert.equal(field(body(),'Target IPv4').value,'192.168.1.20');assert.equal(field(body(),'Source IPv4').value,'');assert.equal(field(body(),'Subnets').value,'');
    assert.match(text(body()),/Inherited from Common Target/);
    const panels=()=>body().children.filter(n=>n.className==='panel');
    set('Target IPv4','192.168.1.99',panels()[1]);assert.match(text(panels()[1]),/Local override/);
    set('Common Target (optional)','192.168.1.30');assert.equal(field(panels()[1],'Target IPv4').value,'192.168.1.99');assert.equal(field(panels()[2],'Target IPv4').value,'192.168.1.30');
    set('Subnets','10.0.0.0/8');await next();assert.match(error(),/subnets/);
    set('Subnets','192.168.1.0/24');await next();assert.match(error(),/Protocol/);
    set('Protocol','ssh',panels()[1]);set('Port','65536',panels()[1]);await next();assert.match(error(),/port/);
    set('Port','22',panels()[1]);await next();assert.match(error(),/Source/);
    set('Source IPv4','8.8.8.8');await next();assert.match(error(),/private lab/);
    set('Source IPv4','192.168.1.10');await next();assert.match(error(),/Synthetic staged file/);
    set('Synthetic staged file','/etc/passwd');await next();assert.match(error(),/@staged/);
    set('Synthetic staged file','@staged');await next();assert.match(title(),/^5\./);
    set('Execution profile','slow');assert.equal(field(body(),'Target duration · Hours').value,4);
    set('Target duration · Hours','0');await next();assert.match(error(),/Slow/);
    set('Target duration · Hours','2');set('Target duration · Minutes','30');await next();await next();
    assert.match(text(body()),/Slow Campaign · target \/ planned span 2 h 30 min/);assert.match(text(body()),/best-effort/);
    assert.equal(walk(body()).find(n=>n.tag==='summary').textContent,'Advanced / Show JSON');assert.equal(walk(body()).find(n=>n.tag==='details').open,undefined);
    assert.ok(walk(body()).find(n=>n.tag==='pre').textContent.includes('"file": "@staged"'));
    assert.match(text(body()),/Required runtime credentials: Linux \/ SSH/);
    await click(body(),'Save');assert.equal(definitions[0].profile.duration,9000);assert.equal(definitions[0].phases[1].parameters.target,'192.168.1.99');
    assert.ok(!JSON.stringify(definitions).includes('commonTarget'));assert.ok(!JSON.stringify(definitions).includes('autoAdded'));
    assert.match(text(elements.get('customLibrary')),/Fixed Targets · P01 → P03 → P04 → P06 · Slow Campaign/);

    context.window.MrnPlanning.newDraft(definitions[0]);await next();set('Targets','auto');await next();await next();await review();
    assert.ok(walk(body()).find(n=>n.tag==='pre').textContent.includes('"parameters": {}'));
    await click(body(),'Save');assert.ok(definitions[0].phases.every(p=>Object.keys(p.parameters).length===0));

    await select();await add('02');await next();await next();set('Execution profile','custom');
    set('Start offset · Hours','1');set('Start offset · Minutes','15');set('Target activity duration · Minutes','2');set('Jitter (%)','101');await next();assert.match(error(),/jitter/);
    set('Jitter (%)','25');set('Minimum action delay · Seconds','3');set('Maximum action delay · Seconds','2');await next();assert.match(error(),/maximum delay/);
    set('Maximum action delay · Seconds','4');await next();set('When','recurring');await next();assert.match(error(),/date/);
    set('Start date / time (your browser timezone)','2000-01-01T12:00');await next();assert.match(error(),/future/);
    set('Start date / time (your browser timezone)','2099-11-02T12:00');set('Repeat every','2');set('Repeat unit','week');await next();
    assert.match(text(body()),/Repeat every 2 weeks/);assert.ok(text(body()).includes(Intl.DateTimeFormat().resolvedOptions().timeZone));
    assert.match(text(body()),/1 h 17 min/);await click(body(),'Save scenario + schedule');
    assert.equal(plans[0].interval,1209600);assert.match(plans[0].at,/Z$/);
    const saved=definitions.at(-1);assert.equal(saved.phases[0].timing.start_offset,4500);assert.equal(saved.phases[0].timing.duration,120);assert.equal(saved.phases[0].timing.jitter,.25);
    assert.match(text(elements.get('customLibrary')),/1 schedule\(s\)/);
    assert.ok(textButton(elements.get('scheduleList'),'Disable'));

    // New fixed phases inherit; resetting/clearing the convenience target is explicit.
    await select('fixed');await add('03');await next();set('Common Target (optional)','192.168.1.20');
    await back();await add('07');await next();
    let fixedPanels=body().children.filter(n=>n.className==='panel');assert.equal(field(fixedPanels[1],'Target IPv4').value,'192.168.1.20');
    set('Target IPv4','192.168.1.99',fixedPanels[0]);await click(fixedPanels[0],'Use Common Target');
    assert.equal(field(body(),'Target IPv4').value,'192.168.1.20');
    set('Common Target (optional)','');assert.equal(field(body(),'Target IPv4').value,'');
    await back();const leaf=row('07').children.find(n=>n.type==='checkbox');leaf.checked=false;leaf.listeners.change();
    assert.equal(row('07').children.find(n=>n.type==='checkbox').checked,false);await click(row('07'),'Remove');assert.deepEqual(ids(),['03']);

    await select();await add('08');await review();assert.match(text(body()),/P08 wordlist upload/);
    const upload=field(body(),'P08 wordlist upload (execution only)');upload.files=[new Blob(['execution-only-wordlist'])];
    set('P08 usernames (execution only)','ubuntu');await click(body(),'Save + Run Now');
    const request=requests.find(r=>r.url.startsWith('/api/scenario/'));assert.ok(request.data instanceof FormData);assert.equal(request.data.get('wordlist_users'),'ubuntu');assert.equal(await request.data.get('wordlist_file').text(),'execution-only-wordlist');
    assert.ok(!JSON.stringify(definitions).includes('execution-only-wordlist'));assert.ok(!JSON.stringify(plans).includes('wordlist'));
    await select();await add('08');await review();
    set('P08 wordlist path on server (execution only)','/usr/share/wordlists/lab.txt');
    await click(body(),'Save + Run Now');
    const serverRun=requests.filter(r=>r.url.startsWith('/api/scenario/')).at(-1);
    assert.equal(serverRun.data.get('wordlist_path'),'/usr/share/wordlists/lab.txt');
    assert.equal(serverRun.data.get('wordlist_file'),null);
    assert.ok(!JSON.stringify(definitions).includes('/usr/share/wordlists/lab.txt'));
    await context.window.MrnPlanning.runCustom(definitions.at(-1).id);assert.match(title(),/^7\./);
    await back();set('When','once');assert.match(text(body()),/NORDIC_WORDLIST_FILE/);
    await click(elements.get('scheduleList'),'New schedule / Run Now');
    const editor=elements.get('scheduleEditor');set('Run Once or Recurring','recurring',editor);set('Repeat every','4',editor);set('Repeat unit','hour',editor);set('Start date/time (browser timezone)','2099-11-03T12:00',editor);
    await click(editor,'Save schedule');assert.equal(plans.at(-1).interval,14400);
    await click(elements.get('customLibrary'),'Duplicate');assert.match(field(body(),'Name').value,/\(copy\)$/);
    for (const pid of ['09','10']) {
        await select(); await add(pid); assert.deepEqual(ids(),['01','03',pid]);
        assert.ok(row('03').children.find(n=>n.type==='checkbox').disabled);
        assert.ok(textButton(row(pid),'↑').disabled);
    }
    await select('fixed'); await add('10'); await next();
    assert.match(text(body()),/remote command .* is requested on Review/);
    set('Common Target (optional)','192.168.1.10'); set('Protocol','rdp'); await next(); assert.match(error(),/supported protocol/);
    set('Protocol','winrm-https'); set('Action timeout','301'); await next(); assert.match(error(),/5–300/);
    set('Action timeout','60'); await next(); await next(); await next();
    const command=field(body(),'P10 remote command (PowerShell / Bash) (runtime only, never saved)');
    assert.equal(command.tag,'textarea'); command.value='Write-Output "COMMAND_SECRET"';
    await click(body(),'Save + Run Now');
    const dispatched=requests.filter(r=>r.url==='/api/executions/run').at(-1);
    assert.equal(dispatched.data.credentials.powershell,'Write-Output "COMMAND_SECRET"');
    assert.equal(command.value,'');
    assert.ok(!JSON.stringify(definitions).includes('COMMAND_SECRET'));
    assert.ok(!JSON.stringify(plans).includes('COMMAND_SECRET'));
    await click(elements.get('scheduleList'),'New schedule / Run Now');
    const fullEditor=elements.get('scheduleEditor');
    assert.ok(!text(fullEditor).includes('P10 remote command (PowerShell / Bash) (runtime only, never saved)'));
    set('P10 Custom Remote Command','1',fullEditor);
    field(fullEditor,'P10 remote command (PowerShell / Bash) (runtime only, never saved)').value='Get-Date';
    set('Linux / SSH password','S',fullEditor);set('Windows / RDP / WinRM password','R',fullEditor);
    await click(fullEditor,'Run Now');
    const fullRun=requests.filter(r=>r.url==='/api/executions/run').at(-1);
    assert.equal(fullRun.data.execution.powershell_enabled,true);
    assert.equal(fullRun.data.credentials.powershell,'Get-Date');
    await select(); await add('11'); assert.deepEqual(ids(),['01','03','11']);
    assert.ok(textButton(row('03'),'Remove').disabled);
    await next();
    set('Execution platform','linux'); set('Persistence method','systemd');
    const protocolOptions=field(body(),'Protocol').children.map(c=>c.value);
    assert.ok(protocolOptions.includes('ssh')); assert.ok(!protocolOptions.includes('winrm-http'));
    set('Target IPv4','8.8.8.8'); await next(); assert.match(error(),/private lab/);
    set('Target IPv4','192.168.1.44'); set('Persistence action','cleanup'); set('Artifact suffix','lesson');
    await review(); assert.match(text(body()),/systemd/);
    await click(body(),'Save');
    let p11=definitions.at(-1).phases.find(p=>p.id==='11');
    assert.equal(p11.parameters.method,'systemd'); assert.equal(p11.parameters.action,'cleanup');
    assert.equal(p11.parameters.target,'192.168.1.44');
    await select('fixed'); await add('11'); assert.deepEqual(ids(),['11']); await next();
    set('Common Target (optional)','192.168.1.55'); set('Execution platform','windows');
    assert.ok(!field(body(),'Persistence method').children.some(c=>c.value==='cron'));
    set('Protocol','winrm-https'); set('Persistence method','cron'); await next(); assert.match(error(),/method and platform/);
    set('Persistence method','service'); set('Persistence action','cleanup'); await review();
    assert.match(text(body()),/192.168.1.55/);
    await click(body(),'Save + Run Now');
    assert.equal(requests.filter(r=>r.url==='/api/executions/run').at(-1).data.execution.type,'custom');
    console.log('Builder DOM tests passed: dependencies, protected actions, target modes, common targets, validation, review, friendly units, P08/P09/P10 runtime inputs, Full Incident toggle and library summaries.');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
