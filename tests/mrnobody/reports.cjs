const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const elements = new Map();
function element(tag = "div") {
    return {
        tag, children: [], listeners: {}, attributes: {}, textContent: "", value: "",
        appendChild(child) { this.children.push(child); return child; },
        replaceChildren() { this.children = []; },
        addEventListener(type, callback) { this.listeners[type] = callback; },
        setAttribute(name, value) { this.attributes[name] = value; },
        classList: { add() {}, remove() {}, toggle() {} },
        set innerHTML(value) { throw new Error("Evidence must not be rendered as HTML"); }
    };
}
for (const id of ["reportTable", "reportDetail", "reportIncidentCount", "reportCompromisedCount", "reportExfilCount", "reportImpactCount",
    "reportTypeFilter", "reportStatusFilter", "reportPhaseFilter", "reportSearch", "reportFilterNotice"])
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
    assert.match(text(elements.get("reportTable")), /Standalone Attack Technique 03/);
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
    const reportRoot = elements.get("reportDetail");
    const switchView = label => descendants(reportRoot).find(n => n.tag === "button" && n.textContent === label).listeners.click();
    const beforeSwitch = calls.length;
    assert.ok(descendants(reportRoot).some(n => n.textContent === "Investigation View" && n.attributes["aria-pressed"] === "true"));
    for (const hidden of ["ACCESS_FAILED", "<script>attack()</script>", "/tmp/sample", "Technical ground-truth events"])
        assert.ok(!text(reportRoot).includes(hidden), hidden);
    assert.ok(descendants(reportRoot).some(n => n.href === "/api/reports/MRN-test/export/html?view=investigation"));
    assert.ok(descendants(reportRoot).some(n => n.href === "/api/reports/MRN-test/export/pdf?view=investigation"));
    switchView("Ground Truth View");
    assert.equal(calls.length, beforeSwitch);
    assert.ok(descendants(reportRoot).some(n => n.href === "/api/reports/MRN-test/export/pdf?view=ground-truth"));
    const detail = text(elements.get("reportDetail"));
    for (const expected of ["full-incident", "Valid Accounts", "ACCESS_FAILED", "ssh", "<script>attack()</script>", "Unavailable impact", "/tmp/sample"])
        assert.ok(detail.includes(expected), expected);
    let links = descendants(elements.get("reportDetail")).filter(node => node.href);
    assert.ok(links.some(link => link.href === "https://attack.mitre.org/techniques/T1078/"));
    assert.ok(links.some(link => link.href === "https://attack.mitre.org/techniques/T1110/001/"));
    assert.ok(links.some(link => link.href === "/api/reports/MRN-test?raw=1"));
    assert.ok(!links.some(link => link.href.startsWith("javascript:")));
    // Real reports are immutable. Use another ID for the standalone snapshot.
    response = {...response, incident: {...response.incident, id: "MRN-standalone"}};
    response.report_type = "standalone_phase";
    response.phase_id = "03";
    response.phases[0].analysis = {
        what_happened: "Recorded phase status: failure", findings: ["ACCESS_FAILED"], evidence: [{path: "/logs/truth", line: 5}],
        detection: ["Wazuh Linux auth/journal"], investigation_tasks: ["Correlate timestamps"], prevention: ["MFA"],
        guidance_notice: "Educational recommendations, not evidence"
    };
    await vm.runInContext("openReport('MRN-standalone')", context);
    switchView("Ground Truth View");
    for (const expected of ["Standalone Attack Technique 03", "What happened", "Findings", "Evidence references", "Detection in the CyberLab", "Investigation tasks", "Prevention / Mitigation", "Wazuh", "Educational recommendations", "/logs/truth"])
        assert.ok(text(elements.get("reportDetail")).includes(expected), expected);

    for (const [result, status] of [['Custom PowerShell command failed', 'skipped'], ['Custom PowerShell completed with nonfatal stderr/warnings', 'success']]) {
        response = {incident:{id:'MRN-p10-' + status, status:'complete'}, phases:[{id:'10', status, action_outcome:result,
            action_evidence:['target=192.168.2.200 protocol=winrm-http exit_code=0 stderr_bytes=906 command=custom_powershell_content_omitted <script>unsafe</script>']}]};
        await vm.runInContext("openReport('MRN-p10-" + status + "')", context);
        for (const label of ['Investigation View', 'Ground Truth View']) {
            switchView(label);
            assert.ok(text(reportRoot).includes(result));
            assert.ok(text(reportRoot).includes('stderr_bytes=906'));
            assert.equal(descendants(reportRoot).filter(n=>n.tag === 'script').length, 0);
        }
    }
    const phase = (id, status, name = `Phase ${id}`) => ({id, name, status,
        started: `2026-11-01T12:${id}:00Z`, ended: `2026-11-01T12:${id}:30Z`,
        mitre: {techniques: [{id: "T1078", name: "Valid Accounts"}, "T1110.001", {id: "javascript:attack()"}]},
        analysis: {what_happened: `Facts ${id}`, findings: [`Finding ${id}`], detection: [`Detect ${id}`],
            investigation_tasks: [`Investigate ${id}`], prevention: [`Prevent ${id}`], evidence: [{path: "/truth", line: 12}]},
        events: [{event: "ACCESS_FAILED", target: "attempt-only", outcome: "failure", message: "<svg onload=attack()>"}]
    });
    const dashboard = {
        incident: {id: "MRN-dashboard", status: "interrupted", started: "start", ended: "end"},
        summary: {hosts: 2, compromised: 1, exfiltration: 2, impact: 1},
        inventory: {hosts: [{ip: "host-one", hostname: "<img onerror=attack()>"}, {ip: "discovered-only", compromised: true}]},
        compromised_hosts: {hosts: [{ip: "host-one"}]},
        phases: [phase("07", "not_run"), phase("03", "failure"), phase("01", "success"), phase("06", "interrupted"),
            phase("08", "skipped"), phase("02", "success"), phase("05", "success"), phase("04", "success")],
        mitre_summary: [{id: "T1078", name: "Valid Accounts", url: "javascript:attack()", phases: ["03", "03"]}],
        evidence: {
            web_targets: {targets: [{ip: "host-one"}]}, staging: {hosts: [{ip: "host-one", staged: true}, {ip: "no-stage", staged: false}]},
            exfiltration: {transfers: [{source: "host-one", destination: "receiver", successful: true},
                {source: "failed-transfer", destination: "receiver", successful: false}]},
            impact: {hosts: [{ip: "host-one", impacted: true}, {ip: "no-impact", impacted: false}]}
        }, warnings: ["Missing snapshot"]
    };
    response = dashboard;
    await vm.runInContext("openReport('MRN-dashboard')", context);
    switchView("Ground Truth View");
    const root = elements.get("reportDetail");
    const nodes = () => descendants(root);
    assert.match(text(root), /Incident overview/);
    const metrics = nodes().filter(n => n.className === "report-metric");
    assert.deepEqual(metrics.map(n => n.children[0].textContent), ["2", "1", "2", "1", "2"]);
    const timeline = nodes().filter(n => n.className?.includes("report-timeline-step"));
    assert.deepEqual(timeline.map(n => n.children[0].textContent.split(" · ")[0]), ["01", "02", "03", "08", "04", "05", "06", "07"]);
    for (const status of ["success", "failure", "skipped", "interrupted", "not_run"])
        assert.ok(timeline.some(n => n.className.includes(`report-status-${status}`)));
    assert.match(text(timeline[2]), /12:03:00Z/);
    const analysis = () => nodes().find(n => n.id === "reportPhaseAnalysis");
    assert.match(text(analysis()), /Facts 01/);
    timeline[2].listeners.click();
    assert.equal(timeline[2].attributes["aria-pressed"], "true");
    assert.equal(timeline[0].attributes["aria-pressed"], "false");
    assert.match(text(analysis()), /Facts 03/);
    assert.ok(!text(analysis()).includes("Facts 01"));
    const switchCalls = calls.length;
    switchView("Investigation View");
    assert.ok(!text(analysis()).includes("Facts 03"));
    assert.ok(!text(root).includes("Technical ground-truth events"));
    assert.ok(!text(root).includes("Actual compromised hosts"));
    assert.match(text(analysis()), /Investigate 03/);
    switchView("Ground Truth View");
    assert.match(text(analysis()), /Facts 03/);
    assert.equal(calls.length, switchCalls);
    for (const heading of ["What happened", "Findings", "Detection", "Investigation", "Prevention / Mitigation", "Evidence references"])
        assert.ok(text(analysis()).includes(heading));
    const mitreGrid = nodes().find(n => n.className === "report-mitre-grid");
    assert.equal(mitreGrid.children.length, 2);
    assert.match(text(mitreGrid), /Mapped Attack Techniques:/);
    assert.ok(!text(mitreGrid).includes("Mapped phases:"));
    const summaryLinks = descendants(mitreGrid).filter(n => n.href);
    assert.deepEqual(summaryLinks.map(n => n.href), ["https://attack.mitre.org/techniques/T1078/", "https://attack.mitre.org/techniques/T1110/001/"]);
    assert.ok(summaryLinks.every(n => n.rel === "noopener noreferrer"));
    assert.equal((text(mitreGrid).match(/03/g) || []).length, 2); // once per technique, despite duplicate summary metadata
    const technical = nodes().filter(n => n.tag === "details");
    assert.ok(technical.length >= 8);
    assert.ok(technical.every(n => !n.open));
    assert.ok(technical.some(n => text(n.children[0]) === "Technical ground-truth events"));
    assert.ok(technical.some(n => text(n.children[0]) === "Raw technical evidence and JSON"));
    assert.match(text(root), /<img onerror=attack\(\)>/);
    assert.match(text(root), /<svg onload=attack\(\)>/);
    assert.ok(!nodes().some(n => ["script", "img", "svg"].includes(n.tag)));
    context.dashboard = dashboard;
    const assetStates = JSON.parse(vm.runInContext("JSON.stringify(reportAssets(dashboard).map(a => ({ip:a.ip, states:[...a.states]})))", context));
    assert.deepEqual(assetStates.find(a => a.ip === "host-one").states, ["discovered", "targeted", "compromised", "staged", "exfiltrated", "impacted"]);
    assert.deepEqual(assetStates.find(a => a.ip === "discovered-only").states, ["discovered"]);
    assert.deepEqual(assetStates.find(a => a.ip === "attempt-only").states, ["targeted"]);
    assert.deepEqual(assetStates.find(a => a.ip === "failed-transfer").states, ["targeted"]);
    for (const ip of ["receiver", "no-stage", "no-impact"]) assert.ok(!assetStates.some(a => a.ip === ip));
    assert.match(text(root), /exfiltration.transfers \(successful\)/);

    // Missing fields remain readable and distinct from a known zero.
    response = {incident: {id: "MRN-historical"}, phases: null, evidence: null, inventory: null};
    await vm.runInContext("openReport('MRN-historical')", context);
    assert.match(text(root), /No technique records available/);
    assert.match(text(root), /No recorded evidence/);
    assert.match(text(root), /No technique mappings recorded/);
    assert.equal(nodes().filter(n => n.className === "report-metric")[0].children[0].textContent, "Unavailable");
    assert.ok(nodes().filter(n => n.className?.includes("report-timeline-step")).every(n => n.disabled));
    response = {incident: {id: "MRN-empty"}, inventory: {hosts: []}, phases: [{id: "03", name: "Historical phase", status: "failed"}]};
    await vm.runInContext("openReport('MRN-empty')", context);
    switchView("Ground Truth View");
    assert.match(text(root), /Historical report/);
    assert.equal(nodes().filter(n => n.className === "report-metric")[0].children[0].textContent, "0");

    // Client-side controls use the unchanged list/detail APIs, fetching details only when needed.
    response = {reports: [
        {id: "MRN-dashboard", status: "interrupted"},
        {id: "MRN-standalone", status: "failed", report_type: "standalone_phase", phase_id: "03"},
        {id: "MRN-broken", status: "complete"}
    ]};
    await vm.runInContext("refreshReports()", context);
    context.fetch = async url => { calls.push(url); return {ok: false, status: 404}; };
    const filter = async (id, value) => {
        elements.get(id).value = value;
        await elements.get(id).listeners[id === "reportSearch" ? "input" : "change"]();
    };
    await filter("reportTypeFilter", "standalone_phase");
    assert.match(text(elements.get("reportTable")), /MRN-standalone/);
    assert.ok(!text(elements.get("reportTable")).includes("MRN-dashboard"));
    await filter("reportStatusFilter", "complete");
    assert.match(text(elements.get("reportTable")), /No reports match/);
    await filter("reportStatusFilter", "");
    await filter("reportPhaseFilter", "08");
    assert.match(text(elements.get("reportTable")), /No reports match/);
    await filter("reportPhaseFilter", "03");
    assert.match(text(elements.get("reportTable")), /MRN-standalone/);
    await filter("reportTypeFilter", "");
    await filter("reportPhaseFilter", "");
    const before = calls.length;
    await filter("reportSearch", "MRN-dashboard");
    assert.match(text(elements.get("reportTable")), /MRN-dashboard/);
    assert.ok(!calls.slice(before).includes("/api/reports/MRN-dashboard"));
    context.fetch = async url => { calls.push(url); return {ok: false, status: 404}; };
    await filter("reportSearch", "HOST-ONE");
    assert.match(text(elements.get("reportTable")), /MRN-dashboard/);
    assert.match(text(elements.get("reportFilterNotice")), /1 reports could not be searched/);
    await filter("reportSearch", "<img onerror");
    assert.match(text(elements.get("reportTable")), /MRN-dashboard/);
    await filter("reportSearch", "no-such-host");
    assert.match(text(elements.get("reportTable")), /No reports match/);

    // Latest user selection wins when responses arrive out of order.
    let resolveSlow;
    context.fetch = async url => ({ok: true, json: () => url.endsWith("MRN-slow") ? new Promise(r => {resolveSlow = r;}) : Promise.resolve({incident:{id:"MRN-fast"}})});
    const slow = vm.runInContext("openReport('MRN-slow')", context);
    await vm.runInContext("openReport('MRN-fast')", context);
    resolveSlow({incident: {id: "MRN-slow"}});
    await slow;
    assert.match(text(root), /MRN-fast/);
    assert.ok(!text(root).includes("MRN-slow"));
    context.fetch = async () => ({ok: false, status: 404});
    await vm.runInContext("openReport('MRN-missing')", context);
    assert.match(text(elements.get("reportDetail")), /Could not load report/);
    await vm.runInContext("refreshReports()", context);
    assert.match(text(elements.get("reportTable")), /Could not load reports/);
    assert.equal(elements.get("reportIncidentCount").textContent, "Unavailable");
    context.windowsReport = {incident:{id:'MRN-windows'}, phases:[
        {id:'09', name:'AD Privilege Escalation', status:'success', mitre:{techniques:[{id:'T1098.007'}]}},
        {id:'10', name:'Custom PowerShell', status:'failure', mitre:{techniques:[{id:'T1059.001'}]}}
    ]};
    root.replaceChildren();
    vm.runInContext("renderReport(document.getElementById('reportDetail'), windowsReport, 'MRN-windows')", context);
    const windowsTimeline=descendants(root).filter(n=>n.className?.includes('report-timeline-step'));
    assert.ok(windowsTimeline.some(n=>text(n).includes('09 · AD Privilege Escalation')));
    assert.ok(windowsTimeline.some(n=>text(n).includes('10 · Custom PowerShell')));
    assert.ok(descendants(root).some(n=>n.href==='https://attack.mitre.org/techniques/T1059/001/'));
    context.skippedPhase = {id:'09', name:'AD Privilege Escalation', status:'skipped',
        prerequisite_outcome:'No Active Directory Domain Controller discovered',
        prerequisite_evidence:['target=192.168.2.200 domain=WORKGROUP dc=unknown account=not_attempted group=not_attempted']};
    for (const groundTruth of [false, true]) {
        root.replaceChildren();
        vm.runInContext(`renderReportPhase(document.getElementById('reportDetail'), skippedPhase, ${groundTruth})`, context);
        for (const expected of ['skipped','No Active Directory Domain Controller discovered','192.168.2.200','domain=WORKGROUP','dc=unknown','account=not_attempted','group=not_attempted'])
            assert.ok(text(root).includes(expected));
    }
    context.newPhaseReport = {incident:{id:'MRN-new'},phases:['01','02','15','03','13','14','18','16','04','17','05','06','07'].map(id=>({id,name:'Phase '+id,status:'success'}))};
    root.replaceChildren();vm.runInContext("renderReport(document.getElementById('reportDetail'), newPhaseReport, 'MRN-new')",context);
    const newIds=descendants(root).filter(n=>n.className?.includes('report-timeline-step')).map(n=>n.children[0].textContent.split(' · ')[0]);
    for(const [a,b] of [['14','18'],['18','16'],['02','15'],['15','03'],['13','16'],['16','17'],['17','05'],['05','06']])assert.ok(newIds.indexOf(a)<newIds.indexOf(b));
    assert.equal(vm.runInContext("reportStatus('partial')", context),'partial');
    context.p04report = {incident:{id:'MRN-p04'}, summary:{hosts:0,compromised:0,involved_hosts:2},
        phases:[{id:'04', name:'Internal Discovery',status:'success',
            discovery_overview:'1 sources / 1 targets / 3 open TCP results',
            discovery_findings:['source=192.168.1.20 target=192.168.1.1 transport=ssh ping=reachable 22=open 80=open 443=open 445=closed 3389=closed 5985=closed 5986=closed <img onerror=attack()>'],
            events:[{event:'INTERNAL_DISCOVERY_TCP',source:'192.168.1.20',target:'192.168.1.1'}]}],
        evidence_availability:{impact:'not applicable / not produced by standalone P04'}};
    context.p04assets = vm.runInContext('reportAssets(p04report)',context);
    assert.deepEqual([...context.p04assets.find(a=>a.ip==='192.168.1.20').states],['remote execution source']);
    assert.deepEqual([...context.p04assets.find(a=>a.ip==='192.168.1.1').states],['scanned target','targeted']);
    for(const mode of ['investigation','ground-truth']) {
        root.replaceChildren();
        vm.runInContext("renderReport(document.getElementById('reportDetail'),p04report,'MRN-p04','"+mode+"')",context);
        for(const token of ['192.168.1.20','192.168.1.1','Remote execution source','Scanned target'])assert.ok(text(root).toLowerCase().includes(token.toLowerCase()));
    }
    for(const groundTruth of [false,true]) {
        root.replaceChildren();
        vm.runInContext("renderReportPhase(document.getElementById('reportDetail'),p04report.phases[0],"+groundTruth+")",context);
        assert.equal(text(root).includes('ping=reachable'),groundTruth);
        if(groundTruth)for(const token of ['192.168.1.20','192.168.1.1','22=open','80=open','443=open','445=closed','3389=closed','5985=closed','5986=closed'])assert.ok(text(root).includes(token));
        assert.ok(!descendants(root).some(n=>n.tag==='img'));
    }
    console.log("Reports UI passed: overview, canonical timeline/status/navigation, P09/P10, MITRE dedupe/trusted links, evidence-based assets, filters/host search, collapsed raw evidence, historical/empty/error states, response races and text-safe rendering.");
}
main().catch(error => { console.error(error); process.exitCode = 1; });

