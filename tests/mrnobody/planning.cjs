const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const elements = new Map();
function element(tag = 'div') {
    return {tag, children: [], listeners: {}, value: '', checked: false,
        appendChild(child) {this.children.push(child);},
        replaceChildren() {this.children = [];},
        addEventListener(name, fn) {this.listeners[name] = fn;}
    };
}
for (const id of ['builderBody','planningMessage','customLibrary','scheduleEditor','scheduleList','newCustomScenario']) elements.set(id, element());
const caps = [
    {id:'01', name:'Discovery', fields:{subnet:{label:'Subnets',type:'networks'}}, timing:['start_offset','duration','delay_min','delay_max','jitter'], standalone:true},
    {id:'03', name:'Initial Access', fields:{target:{label:'Target IPv4',type:'ipv4'},protocol:{label:'Protocol',options:['ssh','rdp']},port:{label:'Port',type:'port'}}, credentials:true,timing:['start_offset'],standalone:true}
];
const definitions = [], plans = [], requests = [];
const context = vm.createContext({document:{getElementById:id=>elements.get(id), createElement:element, querySelectorAll:()=>[],addEventListener(){}},
    window:{}, Date, Intl, console, showPage:page=>{context.page=page;}, confirm:()=>true,
    fetch:async (url, options={}) => {
        const data = options.body ? JSON.parse(options.body) : null;
        requests.push({url, method:options.method,data});
        let value = {};
        if (url === '/api/planning/capabilities') value={phases:caps};
        if (url === '/api/custom-scenarios') {
            if (options.method==='POST') {value={...data,id:'custom-test'};definitions.push(value);}
            else value={scenarios:definitions};
        }
        if (url === '/api/scenarios') value={scenarios:[{id:'full-incident',name:'Full Incident'},...definitions.map(x=>({...x,custom:true}))]};
        if (url === '/api/schedules') {
            if(options.method==='POST'){value={id:'schedule-test'};plans.push({...data,id:value.id,next_run:data.at,last_status:'never'});}
            else value={schedules:plans};
        }
        if(url === '/api/executions/run') value={status:'started'};
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
async function main() {
    await context.window.MrnPlanning.refresh();
    context.window.MrnPlanning.newDraft();
    change(field(body(),'Name'),'<img src=x onerror=alert(1)>');
    await click(body(),'Next'); // target mode
    await click(body(),'Next'); // phases
    change(field(body(),'Add phase'),'01'); await click(body(),'Add');
    change(field(body(),'Add phase'),'03'); await click(body(),'Add');
    await click(body(),'↓'); // reorder selected phases (03 ahead of 01)
    await click(body(),'Next'); // automatic phase configuration
    assert.equal(walk(body()).filter(n=>n.tag==='input').length,0); // no irrelevant fixed target inputs
    await click(body(),'Back'); await click(body(),'Back'); // target mode
    change(field(body(),'Targets'),'fixed'); await click(body(),'Next'); await click(body(),'Next');
    const targets=walk(body()).filter(n=>n.tag==='label'&&n.children[0]?.textContent==='Target IPv4');
    assert.equal(targets.length,1);
    change(targets[0].children[1],'192.168.1.20');
    change(field(body(),'Protocol'),'ssh'); change(field(body(),'Subnets'),'192.168.1.0/24');
    await click(body(),'Next'); // timing
    change(field(body(),'Execution profile'),'custom');
    assert.equal(walk(body()).filter(n=>n.tag==='label'&&n.children[0]?.textContent==='Target activity duration (seconds)').length,1); // only discovery
    change(field(body(),'Target activity duration (seconds)'),'120');
    await click(body(),'Next'); await click(body(),'Next');
    const review=walk(body()).find(n=>n.tag==='pre');assert.ok(review.textContent.includes('<img')); // text, never innerHTML
    await click(body(),'Save');
    assert.equal(definitions.length,1);
    assert.deepEqual(definitions[0].phases.map(x=>x.id),['03','01']);
    assert.equal(definitions[0].phases[1].timing.duration,120);
    assert.ok(!JSON.stringify(definitions).includes('password'));
    const library=elements.get('customLibrary');await click(library,'Duplicate');
    assert.equal(field(body(),'Name').value,'<img src=x onerror=alert(1)> (copy)');
    await context.window.MrnPlanning.refresh();
    await click(elements.get('scheduleList'),'New schedule / Run Now');
    change(field(elements.get('scheduleEditor'),'Start date/time (browser timezone)'),'2026-11-02T12:00');
    await click(elements.get('scheduleEditor'),'Save schedule');
    assert.equal(plans.length,1);assert.equal(plans[0].interval,0);assert.match(plans[0].at,/Z$/);
    await click(elements.get('scheduleList'),'Run Now');
    assert.ok(requests.some(r=>r.url==='/api/schedules/schedule-test/run'));
    assert.ok(textButton(elements.get('scheduleList'),'Disable'));
    assert.ok(textButton(elements.get('scheduleList'),'Edit / supply credentials'));
    console.log('Builder DOM tests passed: dynamic fields, order, profiles, safe rendering, save/duplicate, schedules and Run Now.');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
