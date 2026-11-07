const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('TESTFILES/ATTACKER-V2/web/static/app.js', 'utf8').replace(/\r\n/g, '\n');
const moduleSource = source.split('// MRN_STANDALONE_REPORT\n')[1]?.split('// MRN_STANDALONE_REPORT_END')[0];
assert.ok(moduleSource, 'Standalone report controller is distributed in app.js');
function element(tag) {
    return {tag, children: [], listeners: {}, appendChild(n) {this.children.push(n);},
        replaceChildren() {this.children = [];}, setAttribute(k, v) {this[k] = v;},
        addEventListener(k, v) {this.listeners[k] = v;},
        set innerHTML(_) {throw Error('Unsafe rendering');}};
}
const walk = n => [n, ...n.children.flatMap(walk)];
const text = n => walk(n).map(n => n.textContent || '').join('\n');
const settle = () => new Promise(resolve => setImmediate(resolve));
function harness(storage = {}) {
    let job = {}, report = () => Promise.reject(Error('HTTP 404'));
    const requests = [], timers = new Map();
    let nextTimer = 0;
    const detail = element('div');
    detail.scrollIntoView = () => {detail.scrolled = true;};
    const context = vm.createContext({window: {localStorage: {
        getItem: k => storage[k], setItem: (k, v) => {storage[k] = v;}}},
        document: {createElement: element, getElementById: k => k === 'reportDetail' ? detail : null},
        fetchReport: id => {requests.push(id); return report(id);},
        apiGet: async url => {assert.equal(url, '/api/execution-status'); return job;},
        showPage: page => {context.page = page;}, openReport: id => {context.opened = id;},
        setTimeout: cb => {timers.set(++nextTimer, cb); return nextTimer;}, clearTimeout: id => timers.delete(id)});
    vm.runInContext(moduleSource + '\nwindow.controller = MrnStandaloneReport;', context);
    const controller = context.window.controller;
    const root = element('div');
    return {controller, root, context, requests, detail, timers,
        mount: phase => {root.replaceChildren(); controller.mount(root, phase);},
        job: value => {job = value;}, report: fn => {report = fn;},
        button: () => walk(root).find(n => n.textContent === 'View Report'),
        retry: () => walk(root).find(n => n.textContent === 'Check report').listeners.click()};
}
const reportFor = (id, phase = '04', status = 'complete') => ({incident: {id, status}, report_type: 'standalone_phase', phase_id: phase});
(async () => {
    const storage = {}, h = harness(storage);
    h.mount('04'); assert.equal(h.button(), undefined);
    h.job({incident_id: 'MRN-run-A', active: true});
    h.controller.track('04', 'MRN-run-A'); await settle();
    assert.equal(h.button().disabled, true); assert.match(text(h.root), /Running · report pending/);
    assert.deepEqual(h.requests, ['MRN-run-A']);
    assert.equal(h.root.children.at(-1)['aria-label'], 'Standalone execution report');
    // A different job/latest report must never redirect or determine this run's outcome.
    h.job({incident_id: 'MRN-run-B', active: false, status: 'complete', report_id: 'MRN-run-B'});
    await h.retry();
    assert.match(text(h.root), /this run's job status is unavailable/);
    assert.ok(h.requests.every(id => id === 'MRN-run-A'));
    assert.equal(h.button().disabled, true);
    h.job({incident_id: 'MRN-run-A', active: false, status: 'failed'});
    await h.retry(); assert.match(text(h.root), /failed · No readable report.*generation may have failed/);
    h.report(async id => reportFor(id, '04', 'failed'));
    await h.retry(); assert.equal(h.button().disabled, false);
    h.button().listeners.click();
    assert.equal(h.context.page, 'reports'); assert.equal(h.context.opened, 'MRN-run-A'); assert.ok(h.detail.scrolled);
    assert.equal(h.timers.size, 0);
    assert.deepEqual(JSON.parse(storage['mrn.standalone-reports.v1']), {'04': 'MRN-run-A'});
    // Reload and phase reselection recover only the saved exact run.
    const restored = harness(storage);
    restored.report(async id => reportFor(id)); restored.mount('04'); await settle();
    assert.equal(restored.button().disabled, false);
    restored.mount('05'); assert.equal(restored.button(), undefined);
    restored.mount('04'); await settle(); assert.match(text(restored.root), /MRN-run-A/);
    // All phase RUNs use this controller, including P06 and DRY RUNs.
    for (const phase of ['01', '05', '06', '18']) {
        const run = harness(); run.mount(phase); run.report(async id => reportFor(id, phase));
        run.controller.track(phase, `MRN-phase-${phase}`); await settle();
        assert.equal(run.button().disabled, false);
    }
    // A stale response from A cannot overwrite a newly submitted B, even on the same phase.
    const race = harness(); race.mount('04');
    let resolveA;
    race.report(id => id === 'MRN-A' ? new Promise(resolve => {resolveA = resolve;}) : Promise.resolve(reportFor(id)));
    race.controller.track('04', 'MRN-A'); race.controller.track('04', 'MRN-B'); await settle();
    resolveA(reportFor('MRN-A')); await settle(); race.button().listeners.click();
    assert.equal(race.context.opened, 'MRN-B'); assert.doesNotMatch(text(race.root), /MRN-A/);
    // A response belonging to another incident/phase fails closed.
    const wrong = harness(); wrong.mount('04'); wrong.report(async () => reportFor('MRN-other'));
    wrong.controller.track('04', 'MRN-expected'); await settle();
    assert.equal(wrong.button().disabled, true); assert.match(text(wrong.root), /identity does not match/);
    wrong.report(async () => reportFor('MRN-expected', '05')); await wrong.retry();
    assert.equal(wrong.button().disabled, true);
    wrong.report(async () => {throw Error('HTTP 503');}); await wrong.retry();
    assert.match(text(wrong.root), /Unable to check report/);
    const invalid = harness({'mrn.standalone-reports.v1': '{broken'}); invalid.mount('04');
    invalid.controller.track('04', 'javascript:alert(1)'); assert.equal(invalid.button(), undefined);
    // Integration with the existing execution and report detail entry points.
    const detailSource = source.slice(source.indexOf('function renderPhaseDetail('), source.indexOf('// RUN STANDALONE PHASE'));
    assert.ok(detailSource.indexOf('MrnStandaloneReport.mount(phaseDetail, phase.id)') > detailSource.indexOf('phaseDetail.appendChild(controls)'));
    const runSource = source.slice(source.indexOf('async function runStandalonePhase('), source.indexOf('async function runStandalonePhase(') + 8000);
    assert.match(runSource, /MrnStandaloneReport.track\(phase.id, result.incident_id\)/);
    assert.match(source, /function renderReport\(detail, report, id, mode = "investigation"/);
    assert.match(source, /Ground Truth View/);
    // Execute the actual RUN handler: successful submissions bind their returned
    // incident ID for every installed phase; rejected submissions retain context.
    const handler = source.slice(source.indexOf('async function runStandalonePhase('), source.indexOf('document.addEventListener("DOMContentLoaded", () => {', source.indexOf('async function runStandalonePhase(')));
    const submitted = harness();
    const fields = {target: '192.168.1.20', protocol: 'ssh', username: 'student', password: 'temporary-secret'};
    submitted.context.document.getElementById = id => {
        const key = id.replace(/^phase-\d+-/, '');
        return key in fields ? {value: fields[key]} : null;
    };
    Object.assign(submitted.context, {p06Feedback: {pending: false}, showP06Feedback() {}, showMessage() {},
        phaseFieldLabel: value => value, followP06Job() {}, refreshLog: async () => {}, console: {log() {}, error() {}}});
    submitted.context.window.confirm = () => true;
    vm.runInContext(handler, submitted.context);
    for (let number = 1; number <= 18; number++) {
        const phase = String(number).padStart(2, '0');
        submitted.mount(phase);
        submitted.report(async id => reportFor(id, phase));
        submitted.context.apiPost = async (url, data) => {
            assert.equal(url, `/api/phase/${phase}/run`);
            assert.equal(data.dry_run, false);
            return {incident_id: `MRN-handler-${phase}`};
        };
        await submitted.context.runStandalonePhase({id: phase, name: 'Fixture', parameters: Object.keys(fields)});
        await settle();
        assert.equal(submitted.button().disabled, false);
        assert.match(text(submitted.root), new RegExp(`MRN-handler-${phase}`));
    }
    console.log('Standalone report tests passed: exact run, pending, concurrent jobs, failure with report, missing/failed generation, reload, stale responses, navigation and phase hooks.');
})().catch(error => {console.error(error); process.exitCode = 1;});
