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
        appendChild(n) {this.children.push(n); n.parentElement = this;}, setAttribute(k,v) {this[k] = v;},
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

    // P11 uses the shared renderer and real submit callbacks, with no remote execution.
    const p11 = {...phase('11', ['ssh', 'winrm-http', 'winrm-https']),
        parameters: ['target', 'port', 'protocol', 'username', 'password', 'platform', 'method', 'action', 'artifact',
            'timeout', 'persistence_dns', 'persistence_domain', 'persistence_resolver', 'persistence_interval', 'persistence_duration']};
    mount(p11);
    assert.equal(input('protocol').value, 'winrm-http');
    assert.equal(input('port').value, '5985');
    assert.equal(input('artifact').value, 'telemetry');
    assert.equal(input('method').value, 'auto');
    assert.match(input('method').options[0].textContent, /task-service/);
    assert.match(byId('phase-11-artifact-help').textContent, /mrnobody-p11-telemetry.service/);
    assert.match(byId('phase-11-action-help').textContent, /same target, username, method and artifact/);
    const dnsKeys = ['persistence_domain', 'persistence_resolver', 'persistence_interval'];
    dnsKeys.forEach(k => assert.equal(input(k).parentElement.hidden, true));
    assert.notEqual(input('persistence_duration').parentElement.hidden, true, 'lifetime also bounds DNS-disabled paired activity');
    for (const [protocol, port, method] of [['ssh', '22', 'cron-systemd'], ['winrm-http', '5985', 'task-service'], ['winrm-https', '5986', 'task-service']]) {
        await change('protocol', protocol); assert.equal(input('port').value, port);
        assert.match(input('method').options[0].textContent, new RegExp(method));
    }
    await change('platform', 'linux'); assert.equal(input('protocol').value, 'ssh'); assert.equal(input('port').value, '22');
    await change('method', 'cron');
    await change('protocol', 'winrm-https');
    assert.equal(input('platform').value, 'windows'); assert.equal(input('method').value, 'cron', 'manual choice is preserved');
    let count = requests.length;
    await context.runStandalonePhase(current, true);
    assert.equal(requests.length, count); assert.match(messages.at(-1)[0], /method and platform/);
    await change('method', 'auto');
    await change('port-mode', 'custom'); input('port').value = '12345';
    await change('platform', 'linux'); assert.equal(input('port').value, '12345');
    await change('port-mode', 'auto'); assert.equal(input('port').value, '22');
    await change('port-mode', 'custom'); assert.equal(input('port').value, '12345');
    for (const bad of ['', '0', '65536', '-1', '22.5', '1e3']) {
        input('port').value = bad; count = requests.length;
        await context.runStandalonePhase(current, true); assert.equal(requests.length, count);
    }
    for (const good of ['1', '65535']) {
        input('port').value = good; await context.runStandalonePhase(current, true);
        assert.equal(requests.at(-1).data.port, good);
    }
    await change('port-mode', 'auto');
    input('target').value = '192.168.2.200'; input('username').value = 'ubuntu'; input('password').value = 'fixture-only';
    await change('persistence_dns', 'enabled');
    dnsKeys.forEach(k => assert.equal(input(k).parentElement.hidden, false));
    input('persistence_domain').value = 'evilcorp.test';
    input('persistence_resolver').value = '192.168.2.53';
    input('persistence_interval').value = '30'; input('persistence_duration').value = '600';
    for (const [key, bad] of [['persistence_domain', 'example.com'], ['persistence_resolver', '8.8.8.8'],
        ['persistence_resolver', '192.168.2.255'], ['persistence_interval', '601'], ['persistence_duration', '59'],
        ['artifact', 'BAD'], ['artifact', ''], ['timeout', '301']]) {
        const saved = input(key).value; input(key).value = bad; count = requests.length;
        await context.runStandalonePhase(current, true); assert.equal(requests.length, count, key);
        input(key).value = saved;
    }
    await change('method', 'cron'); count = requests.length;
    await context.runStandalonePhase(current, true); assert.equal(requests.length, count, 'DNS requires paired method');
    await change('method', 'auto');
    const start = requests.length;
    for (const dry of [true, false]) await context.runStandalonePhase(current, dry);
    assert.equal(requests.length, start + 2);
    for (const {url, data} of requests.slice(start)) {
        assert.equal(url, '/api/phase/11/run'); assert.equal(data.port, '22'); assert.equal(data.port_mode, 'auto');
        assert.equal(data.method, 'auto'); assert.equal(data.action, 'create'); assert.equal(data.artifact, 'telemetry');
        assert.equal(data.persistence_domain, 'evilcorp.test'); assert.equal(data.persistence_resolver, '192.168.2.53');
        assert.equal(data.persistence_interval, '30'); assert.equal(data.persistence_duration, '600');
        assert.equal(data.username, 'ubuntu'); assert.equal(data.password, 'fixture-only');
    }
    assert.equal(requests[start].data.dry_run, true); assert.equal(requests[start + 1].data.dry_run, false);
    await change('persistence_dns', 'disabled');
    dnsKeys.forEach(k => assert.equal(input(k).parentElement.hidden, true));
    input('persistence_resolver').value = 'invalid hidden draft';
    await context.runStandalonePhase(current, true);
    dnsKeys.forEach(k => assert.equal(k in requests.at(-1).data, false));
    await change('persistence_dns', 'enabled');
    assert.equal(input('persistence_resolver').value, 'invalid hidden draft');
    assert.equal(input('persistence_interval').value, '30');
    input('persistence_resolver').value = '192.168.2.53';
    await change('method', 'cron-systemd'); await change('action', 'cleanup');
    for (const dry of [true, false]) {
        await context.runStandalonePhase(current, dry);
        const data = requests.at(-1).data;
        assert.equal(data.action, 'cleanup'); assert.equal(data.artifact, 'telemetry'); assert.equal(data.method, 'cron-systemd');
        dnsKeys.forEach(k => assert.equal(k in data, false));
    }
    await change('action', 'create');
    assert.equal(input('method').value, 'cron-systemd'); assert.equal(input('artifact').value, 'telemetry');
    assert.equal(input('persistence_resolver').value, '192.168.2.53');
    await change('platform', 'windows'); await change('method', 'task-service');
    await context.runStandalonePhase(current, true);
    assert.equal(requests.at(-1).data.port, '5985'); assert.equal(requests.at(-1).data.method, 'task-service');
    console.log('P11 Auto/Custom, platform/manual methods, retained DNS fields, validation and create/cleanup payloads passed.');

    console.log('Standalone defaults, protocol/platform changes, custom ports and Dry Run → Run submissions passed.');
})().catch(error => {console.error(error); process.exitCode = 1;});
