const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('TESTFILES/ATTACKER-V2/web/static/app.js', 'utf8');
const start = source.indexOf('function revealReportDetails(');
const end = source.indexOf('for (const id of ["reportTypeFilter"', start);
assert.ok(start > 0 && end > start);
const frames = [], effects = [], pending = new Map();
let reduced = false, visible = true;
const detail = {replaceChildren() {this.rendered = null;}};
const heading = {style: {}, getClientRects: () => visible ? [{}] : [],
    focus: options => effects.push(['focus', options]),
    scrollIntoView: options => effects.push(['scroll', options])};
const context = vm.createContext({
    document: {getElementById: id => id === 'reportDetail' ? detail : heading,
        querySelectorAll: () => [{getBoundingClientRect: () => ({top: 0, bottom: 82})}]},
    window: {requestAnimationFrame: callback => frames.push(callback),
        getComputedStyle: () => ({position: 'sticky'}), matchMedia: () => ({matches: reduced})},
    fetchReport: id => new Promise((resolve, reject) => pending.set(id, {resolve, reject})),
    renderReport: (_, report, id) => {detail.rendered = id;},
    reportNode: (_, message) => {detail.message = message;}
});
vm.runInContext('let reportOpenVersion = 0; let reportNavigationVersion = 0;\n' + source.slice(start, end), context);
const open = (id, reveal = true) => context.openReport(id, {reveal});
const resolve = async (id, task, responseId = id) => {
    pending.get(id).resolve({incident: {id: responseId}}); await task;
};
const flush = () => {while (frames.length) frames.shift()();};
(async () => {
    assert.equal(effects.length, 0, 'Initial load never reveals');
    let task = open('A');
    assert.equal(frames.length, 0, 'Wait for asynchronous load');
    await resolve('A', task);
    assert.equal(detail.rendered, 'A');
    assert.equal(effects.length, 0, 'Wait for layout frame');
    flush();
    assert.equal(heading.style.scrollMarginTop, '98px');
    assert.equal(effects[0][0], 'focus');
    assert.equal(effects[0][1].preventScroll, true);
    assert.equal(effects[1][1].behavior, 'smooth');
    effects.length = 0;
    reduced = true;
    task = open('A'); await resolve('A', task); flush();
    assert.equal(effects.at(-1)[1].behavior, 'instant');
    effects.length = 0;
    task = open('unrelated', false); await resolve('unrelated', task); flush();
    assert.equal(effects.length, 0);
    const old = open('old'), latest = open('latest');
    await resolve('latest', latest); await resolve('old', old); flush();
    assert.equal(detail.rendered, 'latest');
    assert.equal(effects.length, 2, 'Only latest response reveals');
    effects.length = 0;
    task = open('queued'); await resolve('queued', task);
    const newer = open('newer'); flush();
    assert.equal(effects.length, 0, 'New selection cancels queued reveal');
    await resolve('newer', newer); flush(); effects.length = 0;
    task = open('leaving');
    vm.runInContext('++reportNavigationVersion', context);
    await resolve('leaving', task); flush();
    assert.equal(effects.length, 0, 'Navigation during fetch cancels reveal');
    task = open('leave-frame'); await resolve('leave-frame', task);
    vm.runInContext('++reportNavigationVersion', context); flush();
    assert.equal(effects.length, 0, 'Navigation before frame cancels reveal');
    task = open('wrong'); await resolve('wrong', task, 'other'); flush();
    assert.equal(detail.rendered, null);
    assert.match(detail.message, /identity/); assert.equal(effects.length, 0);
    task = open('failed'); pending.get('failed').reject(Error('HTTP 503')); await task; flush();
    assert.match(detail.message, /503/); assert.equal(effects.length, 0);
    visible = false;
    task = open('hidden'); await resolve('hidden', task); flush();
    assert.equal(effects.length, 0);
    assert.match(source, /openReport\(report.id, \{reveal: true\}\)/);
    assert.match(source, /if \(pageName\) \+\+reportNavigationVersion/);
    const html = fs.readFileSync('TESTFILES/ATTACKER-V2/web/templates/index.html', 'utf8');
    assert.match(html, /<h2 id="reportDetailsHeading" tabindex="-1">/);
    console.log('Reports reveal passed: async rendering, exact identity, races, navigation, focus, sticky header, reduced motion, hidden/error/unrelated states.');
})().catch(error => {console.error(error); process.exitCode = 1;});
