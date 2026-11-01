const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const elements = new Map();
function element() {
    return {
        children: [], listeners: {}, textContent: "",
        appendChild(child) { this.children.push(child); return child; },
        replaceChildren() { this.children = []; },
        addEventListener(type, callback) { this.listeners[type] = callback; },
        classList: { add() {}, remove() {}, toggle() {} },
        set innerHTML(value) { throw new Error("Evidence must not be rendered as HTML"); }
    };
}
for (const id of ["reportTable", "reportDetail", "reportIncidentCount", "reportCompromisedCount", "reportExfilCount", "reportImpactCount"])
    elements.set(id, element());
let calls = [];
let response;
const context = vm.createContext({
    document: { getElementById: id => elements.get(id), querySelectorAll: () => [], createElement: element, addEventListener() {} },
    window: {}, console, FormData,
    fetch: async url => { calls.push(url); return {ok: true, json: async () => response}; }
});
vm.runInContext(fs.readFileSync(__dirname + "/../../TESTFILES/ATTACKER-V2/web/static/app.js", "utf8"), context);
const text = node => [node.textContent, ...node.children.map(text)].join("\n");
const descendants = node => [node, ...node.children.flatMap(descendants)];
async function main() {
    response = {reports: []};
    await vm.runInContext("refreshReports()", context);
    assert.match(text(elements.get("reportTable")), /No incident reports/);
    const id = "MRN-test";
    response = {reports: [{id, report_type: "standalone_phase", phase_id: "03", status: "failed", started: "2026-11-01", summary: {hosts: 2, compromised: 1, exfiltration: 1, impact: 0}}]};
    await vm.runInContext("refreshReports()", context);
    assert.equal(calls.at(-1), "/api/reports");
    assert.equal(elements.get("reportIncidentCount").textContent, "1");
    assert.equal(elements.get("reportCompromisedCount").textContent, "1");
    assert.match(text(elements.get("reportTable")), /Standalone phase 03/);
    const button = elements.get("reportTable").children[0].children.at(-1).children[0];
    response = {
        incident: {id, scenario: "full-incident", status: "failed"},
        inventory: {hosts: [{ip: "192.168.1.20", hostname: "<img src=x onerror=alert(1)>"}]},
        compromised_hosts: {hosts: [{ip: "192.168.1.20", access: "ssh"}]},
        phases: [{id: "03", name: "Initial Access", status: "failure", mitre: {techniques: [{id: "T1078", name: "Valid Accounts"}, {id: "T1110.001", name: "Password Guessing", url: "javascript:attack()"}]},
                  events: [{event: "ACCESS_FAILED", protocol: "ssh", outcome: "failure", message: "<script>attack()</script>"}]}],
        evidence: {staging: {hosts: [{file: "/tmp/sample"}]}}, warnings: ["Unavailable impact"]
    };
    await button.listeners.click();
    assert.equal(calls.at(-1), "/api/reports/MRN-test");
    const detail = text(elements.get("reportDetail"));
    for (const expected of ["full-incident", "Valid Accounts", "ACCESS_FAILED", "ssh", "<script>attack()</script>", "Unavailable impact", "/tmp/sample"])
        assert.ok(detail.includes(expected), expected);
    let links = descendants(elements.get("reportDetail")).filter(node => node.href);
    assert.ok(links.some(link => link.href === "https://attack.mitre.org/techniques/T1078/"));
    assert.ok(links.some(link => link.href === "https://attack.mitre.org/techniques/T1110/001/"));
    assert.ok(links.some(link => link.href === "/api/reports/MRN-test?raw=1"));
    assert.ok(!links.some(link => link.href.startsWith("javascript:")));
    response.report_type = "standalone_phase";
    response.phase_id = "03";
    response.phases[0].analysis = {
        what_happened: "Recorded phase status: failure", findings: ["ACCESS_FAILED"], evidence: [{path: "/logs/truth", line: 5}],
        detection: ["Wazuh Linux auth/journal"], investigation_tasks: ["Correlate timestamps"], prevention: ["MFA"],
        guidance_notice: "Educational recommendations, not evidence"
    };
    await vm.runInContext("openReport('MRN-test')", context);
    for (const expected of ["Standalone phase 03", "What happened", "Findings", "Evidence references", "Detection in the CyberLab", "Investigation tasks", "Prevention / Mitigation", "Wazuh", "Educational recommendations", "/logs/truth"])
        assert.ok(text(elements.get("reportDetail")).includes(expected), expected);
    context.fetch = async () => ({ok: false, status: 404});
    await vm.runInContext("openReport('MRN-missing')", context);
    assert.match(text(elements.get("reportDetail")), /Could not load report/);
    await vm.runInContext("refreshReports()", context);
    assert.match(text(elements.get("reportTable")), /Could not load reports/);
    console.log("Reports UI passed: list, detail, counters, evidence, text-only rendering, empty and error states.");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
