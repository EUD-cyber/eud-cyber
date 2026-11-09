// Exercise the real Standalone renderer, change handlers and submission callbacks offline.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync('TESTFILES/ATTACKER-V2/web/static/app.js', 'utf8');
const standalone = source.slice(source.indexOf('function phaseFieldLabel('), source.indexOf('document.addEventListener("DOMContentLoaded", () => {', source.indexOf('function phaseFieldLabel(')));
function element(tag) {
    let value = '';
    return {tag, children: [], listeners: {}, dataset: {}, classList: {remove() {}},
        get value() {return tag === 'select' && !value ? this.children[0]?.value || '' : String(value);},
        set value(v) {value = String(v);},
        get options() {return this.children;},
        get selectedOptions() {return this.children.filter(c => c.value === this.value);},
        set innerHTML(_) {this.children = [];},
        appendChild(n) {this.children.push(n);}, setAttribute(k,v) {this[k] = v;},
        addEventListener(k,v) {(this.listeners[k] ||= []).push(v);}, focus() {},
        async fire(k) {for (const fn of this.listeners[k] || []) await fn();}};
}
const walk = n => [n, ...n.children.flatMap(walk)];
const root = element('div'), requests = [], messages = [];
const byId = id => walk(root).find(n => n.id === id);
const context = vm.createContext({document: {createElement: element, getElementById: byId}, phaseDetail: root,
    MrnUI: {detail() {}}, MrnStandaloneReport: {mount() {}, track() {}},
    window: {confirm: () => true}, showMessage: (...args) => messages.push(args),
    p06Feedback: {pending: false}, showP06Feedback() {},
    apiPost: async (url, data) => {requests.push({url, data}); return {message: 'submitted'};},
    refreshLog: async () => {}, console: {log() {}, error() {}}, followP06Job() {}});
vm.runInContext(standalone, context);
const phase = (id, options) => ({id, name: 'Offline test', standalone: true,
    parameters: ['target', 'port', 'protocol', 'username', 'password', 'timeout', ...(id === '10' ? ['platform', 'powershell'] : [])],
    education: {configuration: {protocol: {options}}}});
let current;
const input = key => byId(`phase-${current.id}-${key}`);
const change = async (key, value) => {input(key).value = value; await input(key).fire('change');};
const mount = p => {current = p; context.renderPhaseDetail(p);};
(async () => {
    for (const p of [phase('04', ['ssh','winrm','winrm-http','winrm-https']),
        phase('05', ['ssh','winrm-http','winrm-https']), phase('06', ['ssh','winrm-http','winrm-https']),
        phase('07', ['ssh','winrm-http','winrm-https']), phase('08', ['ssh','rdp']), phase('10', ['ssh','winrm-http','winrm-https'])]) {
        mount(p);
        const defaults = {ssh:22, rdp:3389, winrm:5985, 'winrm-http':5985, 'winrm-https':5986, http:80, https:443};
        assert.equal(input('port-mode').value, 'auto');
        assert.equal(input('port').value, String(defaults[input('protocol').value]), 'initial consistency');
        assert.equal(input('port').readOnly, true);
        input('username').value = 'entered-user';
        for (const protocol of p.education.configuration.protocol.options) {
            await change('protocol', protocol);
            assert.equal(input('port').value, String(defaults[protocol]));
            assert.equal(input('username').value, 'entered-user');
            assert.equal(input('username').placeholder, /^(winrm|rdp)/.test(protocol) ? 'Administrator' : 'ubuntu');
        }
        await change('port-mode', 'custom');
        assert.equal(input('port').readOnly, false);
        input('port').value = '12345';
        for (const protocol of p.education.configuration.protocol.options) {
            await change('protocol', protocol); assert.equal(input('port').value, '12345');
        }
        await change('port-mode', 'auto');
        assert.equal(input('port').value, String(defaults[input('protocol').value]));
        await change('port-mode', 'custom'); assert.equal(input('port').value, '12345', 'restore custom value');
    }
    mount(phase('10', ['ssh','winrm-http','winrm-https']));
    assert.equal(input('protocol').value, 'winrm-http'); assert.equal(input('port').value, '5985');
    await change('platform', 'linux'); assert.equal(input('protocol').value, 'ssh'); assert.equal(input('port').value, '22');
    await change('platform', 'windows'); assert.equal(input('protocol').value, 'winrm-http'); assert.equal(input('port').value, '5985');
    for (const key of ['target','username','password','powershell']) input(key).value = {
        target:'192.168.2.200', username:'Administrator', password:'runtime-secret', powershell:'Write-Output "WINRM_OK"'}[key];
    const button = text => walk(root).find(n => n.tag === 'button' && n.textContent === text);
    button('DRY RUN').fire('click'); await new Promise(r => setImmediate(r));
    assert.equal(input('password').value, 'runtime-secret'); assert.equal(input('powershell').value, 'Write-Output "WINRM_OK"');
    button('RUN P10').fire('click'); await new Promise(r => setImmediate(r));
    assert.equal(requests.length, 2);
    for (const {url,data} of requests) {
        assert.equal(url, '/api/phase/10/run'); assert.equal(data.port, '5985'); assert.equal(data.port_mode, 'auto');
        assert.equal(data.protocol, 'winrm-http'); assert.equal(data.target, '192.168.2.200');
        assert.equal(data.username, 'Administrator'); assert.equal(data.password, 'runtime-secret');
        assert.equal(data.powershell, 'Write-Output "WINRM_OK"');
    }
    assert.equal(requests[0].data.dry_run, true); assert.equal(requests[1].data.dry_run, false);
    await change('port-mode', 'custom'); input('port').value = '15985';
    await change('protocol', 'winrm-https');
    await context.runStandalonePhase(current, true);
    assert.equal(requests.at(-1).data.port, '15985'); assert.equal(requests.at(-1).data.port_mode, 'custom');
    for (const bad of ['', '0','65536','-1','22.5','1e3']) {
        input('port').value = bad; const count = requests.length;
        await context.runStandalonePhase(current, true); assert.equal(requests.length, count);
        assert.match(messages.at(-1)[0], /Port must be/);
    }
    console.log('Standalone defaults, protocol/platform changes, custom ports and Dry Run → Run submissions passed.');
})().catch(error => {console.error(error); process.exitCode = 1;});
