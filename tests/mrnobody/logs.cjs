// Exercise the complete controller in a fake DOM; real network calls are forbidden.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const makeElement = () => ({textContent: '', scrollHeight: 1000, scrollTop: 900,
    clientHeight: 100, listeners: {}, addEventListener(event, fn) { this.listeners[event] = fn; }});
const panels = Array.from({length: 5}, makeElement);
const statuses = Array.from({length: 4}, makeElement);
const buttons = Array.from({length: 4}, makeElement);
const dashboardRefresh = makeElement();
const intervals = [];
const context = vm.createContext({
    document: {
        getElementById: id => id === 'refreshLogButton' ? dashboardRefresh : null,
        querySelectorAll: selector => ({'[data-live-log]': panels,
            '[data-log-status]': statuses, '[data-refresh-log]': buttons}[selector] || []),
        addEventListener() {}
    },
    console: {error() {}},
    setInterval: (fn, delay) => { intervals.push({fn,delay}); return intervals.length; },
    fetch() { throw new Error('Real network requests are forbidden'); }
});
vm.runInContext(fs.readFileSync(__dirname + '/../../TESTFILES/ATTACKER-V2/web/static/app.js','utf8'), context);
async function main() {
    let requests = 0;
    context.apiGet = async url => { assert.equal(url, '/api/log'); requests++; return {log:'phase / scenario / update output <script>alert(1)</script>'}; };
    panels[1].scrollTop = 100; // A reader inspecting older output must keep their position.
    await context.refreshLog();
    assert.equal(requests, 1);
    for (const panel of panels) assert.equal(panel.textContent, 'phase / scenario / update output <script>alert(1)</script>');
    assert.equal(panels[0].scrollTop, 1000);
    assert.equal(panels[1].scrollTop, 100);
    assert(statuses.every(s => s.textContent.includes('2 seconds')));
    for (const button of [...buttons, dashboardRefresh]) await button.listeners.click();
    assert.equal(requests, 6);
    context.startPolling(); context.startPolling();
    assert.equal(intervals.length, 3); // Navigation/actions do not add pollers.
    assert(intervals.some(i => i.fn === context.refreshLog && i.delay === 2000));
    let resolve;
    context.apiGet = () => { requests++; return new Promise(r => {resolve=r;}); };
    const pending = context.refreshLog();
    await context.refreshLog();
    assert.equal(requests, 7); // Slow polls cannot pile up.
    resolve({log:'final output'}); await pending;
    context.apiGet = async () => { throw new Error('offline'); };
    await context.refreshLog();
    assert(panels.every(p => p.textContent === 'final output'));
    assert(statuses.every(s => s.textContent.includes('Retrying')));
    context.apiGet = async () => ({log:''});
    await context.refreshLog();
    assert(panels.every(p => p.textContent === 'Waiting for output...'));
    assert(statuses.every(s => s.textContent.includes('Live')));
    // Every page switch immediately refreshes the shared output.
    await context.showPage('system');
    console.log('Live log tests passed: shared fetch, manual refresh, polling, scrolling, errors, recovery, text-only rendering.');
}
main().catch(error => { console.error(error); process.exitCode=1; });
