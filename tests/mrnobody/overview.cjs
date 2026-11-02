const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
function element(tag) {
    return {tag, children: [], listeners: {}, appendChild(n) {this.children.push(n);},
        replaceChildren() {this.children = [];}, setAttribute(k,v) {this[k]=v;},
        addEventListener(k,v) {this.listeners[k]=v;},
        set innerHTML(_) {throw new Error('Unsafe rendering');}};
}
const root=element('div'), id=element('span');
const context=vm.createContext({window:{}, document:{getElementById:k=>k==='incidentId'?id:k==='executionOverview'?root:null,createElement:element}, Date, Number,
    showPage:p=>{context.page=p;}, openReport:i=>{context.report=i;}, fetch:async()=>({ok:true,json:async()=>({status:'idle'})})});
vm.runInContext(fs.readFileSync('TESTFILES/ATTACKER-V2/web/static/app.js','utf8').split('// MRN_EXECUTION_OVERVIEW')[1],context);
const walk=n=>[n,...n.children.flatMap(walk)];
const text=()=>walk(root).map(n=>n.textContent||'').join('\n');
const render=context.window.MrnOverview.render;
render({status:'idle'}); assert.match(text(),/No active execution/);
const run={active:true,status:'running',incident_id:'MRN-test',started:'2026-11-01T12:00:00Z',elapsed_seconds:120,
    execution:{type:'campaign',id:'full-incident',name:'Full Incident',profile:{mode:'normal'},trigger:'manual'},
    current_phase:{id:'03',name:'Access'},next_phase:{id:'07',name:'Impact'},
    progress:{percent:50,complete:1,total:2},timeline:[{id:'03',name:'Access',status:'running'},{id:'07',name:'Impact',status:'pending'}]};
render(run);assert.equal(id.textContent,'MRN-test');assert.match(text(),/Built-in campaign/);assert.match(text(),/Normal/);
assert.match(text(),/50% · 1\/2 executable/);assert.match(text(),/Next planned phase/);assert.match(text(),/phase states/);
for(const type of ['custom','phase']) {
    render({...run,execution:{...run.execution,type}});
    assert.match(text(),type==='custom'?/Custom scenario/:/Standalone phase/);
}
for(const mode of ['slow','custom']) {
    render({...run,planned_seconds:7200,execution:{...run.execution,profile:{mode},trigger:'scheduler',schedule_id:'schedule-test'},
        timeline:[{id:'03',name:'Access',status:'running',start_offset:3600,duration:120}]});
    assert.match(text(),/Scheduler · schedule-test/);assert.match(text(),/2 h · best-effort/);
    assert.match(text(),/Planned start \+1 h · activity window 2 min/);
}
for(const status of ['complete','partial','failed','interrupted']) {
    render({...run,active:false,status,report_id:'MRN-test'});
    assert.match(text(),/Last execution/);assert.match(text(),/No active execution/);
    walk(root).find(n=>n.tag==='button').listeners.click();assert.equal(context.page,'reports');assert.equal(context.report,'MRN-test');
}
for (const [result, status, label] of [['command_error', 'skipped', 'Custom remote command failed'], ['success_with_warning', 'complete', 'Completed with nonfatal stderr/warnings']]) {
    render({...run, timeline:[{id:'10',name:'PowerShell',status,action_result:result},{id:'04',status:'running'}]});
    assert.ok(text().includes(label));
    assert.ok(text().includes(status));
}
const hostile='<img src=x onerror="alert(1)">';
render({...run,execution:{...run.execution,name:hostile},logs:[hostile],timeline:['complete','running','pending','skipped','failed','interrupted'].map((status,i)=>({id:String(i),name:hostile,status}))});
assert.ok(text().includes(hostile));assert.equal(walk(root).filter(n=>n.tag==='img').length,0);
assert.equal(walk(root).filter(n=>n.className?.startsWith('overview-phase')).length,6);
render({...run,report_id:'javascript:alert(1)'});assert.equal(walk(root).filter(n=>n.tag==='button').length,0);
const html=fs.readFileSync('TESTFILES/ATTACKER-V2/web/templates/index.html','utf8');
render({...run, current_phase:{id:'04',name:'Lateral'}, next_phase:{id:'05',name:'Staging'},
    timeline:[{id:'03',status:'complete'},{id:'09',status:'skipped'},{id:'04',status:'running'},{id:'05',status:'pending'}]});
assert.match(text(),/09[\s\S]*skipped/i);
assert.match(text(),/04/);
assert.match(text(),/05/);
// Legacy Live Campaign cards must use the same terminal status.
const cards=['09','04'].map(phase=>({dataset:{phase}, status:{},
    querySelector(){return this.status;}, classList:{remove(){},add(value){this.value=value;}}}));
context.document.querySelectorAll=()=>cards;
const statusSource=fs.readFileSync('TESTFILES/ATTACKER-V2/web/static/app.js','utf8');
vm.runInContext(statusSource.slice(statusSource.indexOf('function updatePhases('),statusSource.indexOf('async function refreshStatus(')),context);
context.updatePhases({'09':'skipped','04':'running'});
assert.equal(cards[0].status.textContent,'SKIPPED');
assert.equal(cards[0].classList.value,'phase-skipped');
assert.equal(cards[1].status.textContent,'RUNNING');
const nav=html.match(/<nav class="sidebar-nav">([\s\S]*?)<\/nav>/)[1];
const order=[...nav.matchAll(/data-page="([^"]+)"/g)].map(m=>m[1]);
assert.deepEqual(order,['dashboard','campaigns','scenarios','phases','schedules','inventory','reports','system']);
const navItems=order.map(page=>({dataset:{page},classList:{toggle(cls,active){this.active=active;}}}));
context.document.querySelectorAll=s=>s==='.nav-item'?navItems:[];
context.document.getElementById=()=>({classList:{add(){}}});
context.refreshLog=()=>{};context.refreshReports=()=>{};
const app=fs.readFileSync('TESTFILES/ATTACKER-V2/web/static/app.js','utf8');
vm.runInContext(app.slice(app.indexOf('function showPage('),app.indexOf('// Ground truth is rendered')),context);
for(const page of order) {context.showPage(page);assert.equal(navItems.filter(n=>n.classList.active).length,1);assert.equal(navItems.find(n=>n.classList.active).dataset.page,page);}
console.log('Overview DOM tests passed: idle, campaign/custom/standalone, timing, scheduler, progress, terminal summaries, reports, safe rendering and navigation.');
