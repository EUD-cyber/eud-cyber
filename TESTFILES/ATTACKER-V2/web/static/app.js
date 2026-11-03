"use strict";

/*
============================================================
 Nordic Manufacturing A/S
 MrNobody Incident Platform

 Web GUI Controller
============================================================
*/


// ==========================================================
// ELEMENTS
// ==========================================================

const startButton =
    document.getElementById("startButton");

const stopButton =
    document.getElementById("stopButton");

const refreshInventoryButton =
    document.getElementById("refreshInventoryButton");

const refreshLogButton =
    document.getElementById("refreshLogButton");

const systemStatus =
    document.getElementById("systemStatus");

const incidentId =
    document.getElementById("incidentId");

const messageBox =
    document.getElementById("messageBox");

const campaignLog =
    document.getElementById("campaignLog");

const inventoryTable =
    document.getElementById("inventoryTable");

const phaseGrid =
    document.getElementById("phaseGrid");

const phaseDetail =
    document.getElementById("phaseDetail");

const updateButton =
    document.getElementById("updateButton");

// ==========================================================
// POLLING
// ==========================================================

const STATUS_INTERVAL = 2000;
const INVENTORY_INTERVAL = 3000;
const LOG_INTERVAL = 2000;

let statusTimer = null;
let inventoryTimer = null;
let logTimer = null;

let campaignWasRunning = false;
let selectedScenario = null;


// ==========================================================
// API
// ==========================================================

async function apiGet(url) {

    const response = await fetch(
        url,
        {
            cache: "no-store"
        }
    );

    if (!response.ok) {

        throw new Error(
            `HTTP ${response.status}`
        );
    }

    return await response.json();
}


async function apiPost(url, data = {}) {

    const response = await fetch(
        url,
        {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify(data)
        }
    );

    const result =
        await response.json();

    if (!response.ok) {

        throw new Error(
            result.message ||
            result.error ||
            `HTTP ${response.status}`
        );
    }

    return result;
}

async function apiPostForm(url, formData) {

    const response = await fetch(
        url,
        {
            method: "POST",
            body: formData
        }
    );

    const result =
        await response.json();

    if (!response.ok) {

        throw new Error(
            result.message ||
            result.error ||
            `HTTP ${response.status}`
        );
    }

    return result;
}

// ==========================================================
// MESSAGES
// ==========================================================

function showMessage(
    message,
    type = "info"
) {

    if (!messageBox) {
        return;
    }

    messageBox.textContent =
        message;

    messageBox.className =
        `message-box message-${type}`;

    messageBox.classList.remove(
        "hidden"
    );
}


function hideMessage() {

    if (!messageBox) {
        return;
    }

    messageBox.classList.add(
        "hidden"
    );
}


// ==========================================================
// CONFIGURATION
// ==========================================================

async function loadConfiguration() {

    try {

        const config =
            await apiGet(
                "/api/config"
            );


        // --------------------------------------------------
        // General
        // --------------------------------------------------

        const incidentIp =
            document.getElementById(
                "incidentIp"
            );

        const webPorts =
            document.getElementById(
                "webPorts"
            );

        const exfilPort =
            document.getElementById(
                "exfilPort"
            );


        // --------------------------------------------------
        // Linux / SSH
        // --------------------------------------------------

        const sshUser =
            document.getElementById(
                "sshUser"
            );

        const sshPort =
            document.getElementById(
                "sshPort"
            );


        // --------------------------------------------------
        // Windows / RDP
        // --------------------------------------------------

        const rdpUser =
            document.getElementById(
                "rdpUser"
            );

        const rdpPort =
            document.getElementById(
                "rdpPort"
            );


        // --------------------------------------------------
        // Populate general defaults
        // --------------------------------------------------

        if (incidentIp) {

            incidentIp.value =
                config.incident_ip ||
                "192.168.1.254";
        }


        if (webPorts) {

            webPorts.value =
                config.web_ports ||
                "80,443,3010,8080,8443";
        }


        if (exfilPort) {

            exfilPort.value =
                config.exfil_port ||
                "9090";
        }


        // --------------------------------------------------
        // Populate Linux defaults
        // --------------------------------------------------

        if (sshUser) {

            sshUser.value =
                config.ssh_username ||
                "ubuntu";
        }


        if (sshPort) {

            sshPort.value =
                config.ssh_port ||
                "22";
        }


        // --------------------------------------------------
        // Populate Windows defaults
        // --------------------------------------------------

        if (rdpUser) {

            rdpUser.value =
                config.rdp_username ||
                "Administrator";
        }


        if (rdpPort) {

            rdpPort.value =
                config.rdp_port ||
                "3389";
        }

    }

    catch (error) {

        console.error(
            "Configuration error:",
            error
        );

        showMessage(
            "Unable to load campaign configuration.",
            "error"
        );
    }
}


// ==========================================================
// SYSTEM STATUS
// ==========================================================

function setSystemStatus(status) {

    if (!systemStatus) {
        return;
    }

    const normalized =
        String(status || "idle")
            .toLowerCase();

    systemStatus.className =
        "status-badge";

    switch (normalized) {

        case "running":

            systemStatus.textContent =
                "RUNNING";

            systemStatus.classList.add(
                "status-running"
            );

            break;


        case "complete":

            systemStatus.textContent =
                "COMPLETE";

            systemStatus.classList.add(
                "status-complete"
            );

            break;


        case "failed":

            systemStatus.textContent =
                "FAILED";

            systemStatus.classList.add(
                "status-failed"
            );

            break;


        case "stopped":

            systemStatus.textContent =
                "STOPPED";

            systemStatus.classList.add(
                "status-stopped"
            );

            break;


        default:

            systemStatus.textContent =
                "IDLE";

            systemStatus.classList.add(
                "status-idle"
            );
    }
}

// ==========================================================
// PHASE DISCOVERY
// ==========================================================

/* Registry-driven product views. These projections never change execution state. */
const MrnUI = (() => {
    let techniques = [], selected = null, dashboardPending = false, dashboardLoaded = 0, executionStatuses = {};
    const byId = id => document.getElementById(id);
    function node(parent, tag, text, cls) {
        const el = document.createElement(tag);
        if (text !== undefined && text !== null) el.textContent = String(text);
        if (cls) el.className = cls;
        if (parent) parent.appendChild(el);
        return el;
    }
    const education = item => item.education || {};
    const tactics = item => education(item).tactics || String(item.mitre?.tactic || '').split(/[,|]/).map(x => x.trim()).filter(Boolean);
    const all = get => [...new Set(techniques.flatMap(get))].sort();
    const filters = {techniqueTactic: tactics, techniquePlatform: x => education(x).platforms || [], techniqueMode: x => education(x).supported_modes || [], techniqueReadiness: x => [education(x).readiness || 'Unknown']};
    const tacticIds = {'Reconnaissance':'TA0043','Resource Development':'TA0042','Initial Access':'TA0001','Execution':'TA0002','Persistence':'TA0003','Privilege Escalation':'TA0004','Stealth':'TA0005','Defense Evasion':'TA0005','Defense Impairment':'TA0112','Credential Access':'TA0006','Discovery':'TA0007','Lateral Movement':'TA0008','Collection':'TA0009','Command and Control':'TA0011','Exfiltration':'TA0010','Impact':'TA0040'};
    function badge(parent, text, type = 'platform') {
        const tone = type === 'tactic' ? /Impact|Impairment|Access/.test(text) ? 'red' : /Discovery|Collection/.test(text) ? 'yellow' : 'purple' : 'neutral';
        return node(parent, 'span', text, `tech-badge badge-${tone}`);
    }
    function action(parent, text, callback, cls = 'button') {
        const b = node(parent, 'button', text, cls); b.type = 'button'; b.addEventListener('click', callback); return b;
    }
    function external(parent, text, href) {
        const a = node(parent, 'a', text); a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer'; return a;
    }
    function select(item, focus = false) {
        const values = Object.fromEntries(Object.keys(filters).map(key => [key, byId(key)?.value || '']));
        if (!matches(item, byId('techniqueSearch')?.value || '', values)) {
            for (const key of Object.keys(filters)) if (byId(key)) byId(key).value = '';
            if (byId('techniqueSearch')) byId('techniqueSearch').value = '';
        }
        selected = item.id;
        renderPhaseDetail(item);
        renderList();
        if (focus) byId('phaseDetail')?.focus();
    }
    function matches(item, query, values) {
        const e = education(item);
        const haystack = [item.id, `P${item.id}`, item.name, e.description, ...tactics(item), ...(item.mitre?.techniques || [])].join(' ').toLowerCase();
        return (!query || haystack.includes(query.trim().toLowerCase())) && Object.entries(filters).every(([key, get]) => !values[key] || get(item).includes(values[key]));
    }
    function renderList() {
        const root = byId('phaseGrid'); if (!root) return;
        const scroll = root.scrollTop;
        root.replaceChildren();
        const values = Object.fromEntries(Object.keys(filters).map(key => [key, byId(key)?.value || '']));
        const items = techniques.filter(item => matches(item, byId('techniqueSearch')?.value || '', values));
        const count = byId('techniqueResultCount'); if (count) count.textContent = `${items.length} of ${techniques.length} Attack Techniques`;
        if (!items.length) node(root, 'p', 'No Attack Techniques match these filters. Clear a filter or try another search.', 'empty-state');
        items.forEach(item => {
            const e = education(item);
            const card = action(root, '', () => select(item), 'phase-card technique-card' + (selected === item.id ? ' phase-selected' : ''));
            card.dataset.phase = item.id; card.setAttribute('aria-pressed', String(selected === item.id));
            node(card, 'span', `P${item.id}`, 'phase-number');
            const info = node(card, 'span', undefined, 'phase-info');
            node(info, 'strong', item.name);
            const badges = node(info, 'span', undefined, 'tech-badges');
            tactics(item).forEach(t => badge(badges, t, 'tactic'));
            (e.platforms || []).forEach(p => badge(badges, p));
            node(info, 'span', e.description || 'Description not yet documented.', 'tech-description');
            node(info, 'span', e.readiness || 'Unknown', 'readiness-label');
            const state = executionStatuses[item.id];
            const label = {running:'Running',complete:'Complete',failed:'Failed',skipped:'Skipped',disabled:'Skipped',partial:'Partial',interrupted:'Interrupted'}[state] || 'Not run';
            node(card, 'span', label, 'phase-status');
            if (['running','complete','failed','skipped','partial','interrupted'].includes(state)) card.classList.add(`phase-${state}`);
        });
        root.scrollTop = scroll;
    }
    function applyTactic(tactic) {
        for (const key of Object.keys(filters)) if (byId(key)) byId(key).value = '';
        if (byId('techniqueSearch')) byId('techniqueSearch').value = '';
        if (byId('techniqueTactic')) byId('techniqueTactic').value = tactic;
        showPage('phases'); renderList(); byId('techniqueTactic')?.focus();
    }
    function coverage() {
        const counts = byId('catalogTactics');
        if (counts) {
            counts.replaceChildren();
            action(counts, `All tactics · ${techniques.length}`, () => applyTactic(''), 'tactic-count');
        }
        const root = byId('mitreCoverage'); if (root) root.replaceChildren();
        const total = byId('mitreSummary'); if (total) {
            total.replaceChildren();
            for (const [label,value] of [['MrNobody Attack Techniques', techniques.length], ['Mapped tactics', all(tactics).length], ['Unique ATT&CK techniques / sub-techniques', all(x => x.mitre?.techniques || []).length]]) {
                const metric = node(total,'div',undefined,'report-metric'); node(metric,'strong',value); node(metric,'span',label);
            }
        }
        all(tactics).forEach(tactic => {
            const mapped = techniques.filter(item => tactics(item).includes(tactic));
            if (counts) action(counts, `${tactic} · ${mapped.length}`, () => applyTactic(tactic), 'tactic-count');
            if (!root) return;
            const section = node(root, 'section', undefined, 'mitre-tactic');
            const head = node(section, 'div', undefined, 'panel-header'); node(head,'h2',tactic); badge(head,`${mapped.length} mapped`);
            if (tacticIds[tactic]) external(section, `${tacticIds[tactic]} · Official tactic ↗`, `https://attack.mitre.org/tactics/${tacticIds[tactic]}/`);
            node(section,'p',`${new Set(mapped.flatMap(x => x.mitre?.techniques || [])).size} associated ATT&CK techniques / sub-techniques`, 'muted');
            mapped.forEach(item => action(section, `P${item.id} · ${item.name}`, () => {showPage('phases'); select(item,true);}, 'mapped-technique'));
            action(section,'Explore tactic →',()=>applyTactic(tactic),'button button-small');
        });
        if (root && !techniques.length) node(root, 'p', 'No installed technique mappings are available.');
    }
    function setCatalogue(items) {
        techniques = Array.isArray(items) ? items : [];
        for (const [id, get] of Object.entries(filters)) {
            const select = byId(id); if (!select) continue;
            const previous = select.value;
            while (select.options.length > 1) select.remove(1);
            all(get).forEach(value => {const option = node(select, 'option', value); option.value = value;});
            select.value = previous;
            if (!select.dataset.bound) {select.addEventListener('change', renderList); select.dataset.bound = 'true';}
        }
        const search = byId('techniqueSearch');
        if (search && !search.dataset.bound) {search.addEventListener('input',renderList); search.dataset.bound = 'true';}
        renderList(); coverage();
        if (!selected && techniques.length) select(techniques[0]);
        const reportFilter = byId('reportPhaseFilter');
        if (reportFilter) {
            const previous = reportFilter.value;
            // Keep historical IDs even when their runtime script is no longer installed.
            const entries = new Map(REPORT_PHASES);
            techniques.forEach(item => entries.set(item.id,item.name));
            reportFilter.replaceChildren(); node(reportFilter,'option','All Attack Techniques').value = '';
            [...entries].sort(([a],[b])=>a.localeCompare(b)).forEach(([id,name])=>{node(reportFilter,'option',`P${id} · ${name}`).value=id;});
            reportFilter.value = previous;
        }
    }
    function detail(parent, item) {
        const e = education(item);
        node(parent,'p',e.description || 'Description not yet documented.','technique-lead');
        const badges = node(parent,'div',undefined,'tech-badges');
        badge(badges,e.readiness || 'Unknown'); tactics(item).forEach(t=>badge(badges,t,'tactic')); (e.platforms || []).forEach(p=>badge(badges,p));
        node(parent,'p','Installed describes registry availability. Target readiness is checked at execution time.','muted');
        const grid = node(parent,'div',undefined,'technique-sections');
        const section = (title,text) => {const s=node(grid,'section',undefined,'technique-section'); node(s,'h3',title); if(text)node(s,'p',text); return s;};
        section('What does it do?', e.description || 'Not yet documented.');
        const detect = section('What should students detect?');
        if (e.detection_focus?.length) {const ul=node(detect,'ul');e.detection_focus.forEach(t=>node(ul,'li',t));} else node(detect,'p','Detection focus not yet documented.');
        section('Teaching purpose', e.teaching_purpose || 'Not yet documented.');
        const mitre = section('MITRE ATT&CK');
        tactics(item).forEach(t => {const p=node(mitre,'p');badge(p,t,'tactic');if(tacticIds[t])external(p,' Official tactic ↗',`https://attack.mitre.org/tactics/${tacticIds[t]}/`);});
        (e.technique_details || []).forEach(t => {if(/^T\d{4}(?:\.\d{3})?$/.test(t.id))external(node(mitre,'p'),`${t.id} · ${t.name || 'ATT&CK technique'} ↗`,`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`);});
        if (!e.technique_details?.length) node(mitre,'p','No detailed ATT&CK mappings documented.');
        const execution=section('Execution');
        const dl=node(execution,'dl',undefined,'overview-fields');
        const pair=(label,value)=>{node(dl,'dt',label);node(dl,'dd',value || 'Not documented');};
        pair('Supported modes',(e.supported_modes || []).join(' · '));
        pair('Platform',(e.platforms || []).join(' · '));pair('Target type',e.target_type);
        pair('Prerequisites',e.prerequisites);
        pair('Auto dependencies',(e.dependencies || []).map(id=>'P'+id).join(' → ') || 'None declared');
        pair('Runtime state',(item.campaign_state || []).join(' · ') || 'None declared');
        pair('Required fixed-target fields',(e.required_fields || []).map(key=>e.configuration?.[key]?.label || phaseFieldLabel(key)).join(' · ') || 'None declared');
        pair('Cleanup / restore',e.cleanup);
        node(execution,'p','Optional techniques can be skipped by Full Incident when their inputs or prerequisites are absent.','muted');
        const related=techniques.filter(t=>t.id!==item.id && ((e.dependencies || []).includes(t.id) || tactics(t).some(x=>tactics(item).includes(x))));
        if(related.length){const group=section('Related Attack Techniques');related.forEach(t=>action(group,`P${t.id} · ${t.name}`,()=>select(t,true),'mapped-technique'));}
        node(parent,'h3','Standalone configuration');
        node(parent,'p','Runtime credentials are used only for this execution. Review prerequisites and cleanup behavior before running.','muted');
    }
    const setText = (id,text) => {const el=byId(id);if(el)el.textContent=text;};
    async function get(url) {const response=await fetch(url);if(!response.ok)throw new Error('Unavailable');return response.json();}
    async function refreshDashboard(force=false) {
        if(dashboardPending || (!force && Date.now()-dashboardLoaded<30000))return;
        dashboardPending=true;
        try {
            await Promise.allSettled([
                get('/api/health').then(health=>{
                    setText('dashboardHealth',health.status==='ok'?'Online':health.status || 'Unknown');
                    const root=byId('settingsRuntime');if(root){root.replaceChildren();const dl=node(root,'dl',undefined,'overview-fields');for(const [label,value] of [['Service',health.service],['Version',health.version],['API health',health.status],['Transport',window.location?.protocol === 'https:' ? 'HTTPS (current browser connection)' : 'HTTP (current browser connection)']]){node(dl,'dt',label);node(dl,'dd',value || 'Unavailable');}}
                }).catch(()=>{setText('dashboardHealth','Unavailable');setText('settingsRuntime','Application health unavailable. Retry by opening Settings again.');}),
                get('/api/scenarios').then(data=>setText('dashboardScenarioCount',data.scenarios.length)).catch(()=>setText('dashboardScenarioCount','Unavailable')),
                get('/api/schedules').then(data=>{setText('dashboardScheduleCount',data.schedules.length);setText('dashboardScheduleEnabled',`${data.schedules.filter(x=>x.enabled).length} enabled`);}).catch(()=>{setText('dashboardScheduleCount','Unavailable');setText('dashboardScheduleEnabled','Schedule status unavailable');}),
                get('/api/reports').then(data=>{
                    const root=byId('recentIncidents');if(!root)return;root.replaceChildren();
                    const reports=(data.reports || []).slice(0,5);
                    if(!reports.length)node(root,'p','No incidents recorded yet. Start a scenario to collect evidence.','empty-state');
                    reports.forEach(r=>{const row=node(root,'div',undefined,'recent-incident');action(row,r.id,()=>{showPage('reports');openReport(r.id);},'mapped-technique');badge(row,r.status || 'Unknown');node(row,'span',r.started ? new Date(r.started).toLocaleString() : 'Time unavailable','muted');});
                }).catch(()=>setText('recentIncidents','Incident history unavailable. Open Reports to retry.'))
            ]);
        } finally {dashboardLoaded=Date.now();dashboardPending=false;}
    }
    return {setCatalogue, renderList, detail, matches, refreshDashboard, tactics, node, badge, setExecutionStatuses: value => {executionStatuses = value || {};}};
})();
window.MrnUI = MrnUI;

function renderPhases(phases) { MrnUI.setCatalogue(phases); }

async function loadPhases() {

    if (!phaseGrid) {
        return;
    }

    try {

        const data =
            await apiGet(
                "/api/phases"
            );

        const phases =
            data.phases || [];

        renderPhases(
            phases
        );


const dashboardPhaseCount =
    document.getElementById(
        "dashboardPhaseCount"
    );

if (dashboardPhaseCount) {

    dashboardPhaseCount.textContent =
        phases.length;
}

    }

    catch (error) {

        console.error(
            "Attack Technique discovery error:",
            error
        );

        phaseGrid.innerHTML = `
            <div class="phase-card">
                <div class="phase-info">
                    <strong>Unable to load attack techniques</strong>
                    <span>Check /api/phases</span>
                </div>
            </div>
        `;
    }
}

// ==========================================================
// SCENARIOS
// ==========================================================

function renderScenarios(scenarios) {
    scenarios = Array.isArray(scenarios) ? scenarios.filter(scenario => !scenario.custom) : [];

    const scenarioGrid =
        document.getElementById(
            "scenarioGrid"
        );

    const scenarioDetail =
        document.getElementById(
            "scenarioDetail"
        );


    if (!scenarioGrid) {
        return;
    }


    scenarioGrid.innerHTML = "";


    if (
        !Array.isArray(scenarios) ||
        scenarios.length === 0
    ) {

        scenarioGrid.innerHTML = `
            <div class="phase-card">
                <div class="phase-info">
                    <strong>No scenarios available</strong>
                    <span>No scenario definitions were discovered.</span>
                </div>
            </div>
        `;

        return;
    }


    scenarios.filter(scenario => !scenario.custom).forEach(scenario => {

        const card =
            document.createElement(
                "div"
            );

        card.className =
            "phase-card";


        const info =
            document.createElement(
                "div"
            );

        info.className =
            "phase-info";


        const name =
            document.createElement(
                "strong"
            );

        name.textContent =
            scenario.name;


        const description =
            document.createElement(
                "span"
            );

        description.textContent =
            scenario.description || (scenario.custom ? "Custom scenario" : "Built-in scenario");


        info.appendChild(
            name
        );

        info.appendChild(
            description
        );


        const status =
            document.createElement(
                "div"
            );

        status.className =
            "phase-status";

        status.textContent =
            `${scenario.phases?.length || 0} ATTACK TECHNIQUES`;


        card.appendChild(
            info
        );

        card.appendChild(
            status
        );


        card.tabIndex = 0;
        card.setAttribute("role", "button");
        card.addEventListener("keydown", event => {if (["Enter", " "].includes(event.key)) {event.preventDefault(); card.click();}});
        const extra = document.createElement("span"); extra.className = "scenario-flow";
        extra.textContent = (scenario.phases || []).map(id => "P" + id).join(" → ") || "No Attack Techniques defined";
        info.appendChild(extra);
        const meta = document.createElement("span");
        const profile = scenario.profile;
        meta.textContent = `${scenario.custom ? "Custom" : "Built-in"} · ${scenario.target_mode === "fixed" ? "Fixed Targets" : "Auto Discovery"}${profile?.mode ? " · " + profile.mode : ""}${profile?.duration ? " · target " + profile.duration + " s" : ""}`;
        info.appendChild(meta);
        if (Number.isInteger(scenario.schedule_count)) {
            const scheduled = document.createElement("span");
            scheduled.textContent = `${scenario.schedule_count} scheduled jobs · ${scenario.enabled_schedule_count || 0} enabled`;
            info.appendChild(scheduled);
        }
        card.addEventListener(
            "click",
            () => {

                document
                    .querySelectorAll(
                        "#scenarioGrid .phase-card"
                    )
                    .forEach(item => {

                        item.classList.remove(
                            "phase-selected"
                        );
                    });


                card.classList.add(
                    "phase-selected"
                );


                renderScenarioDetail(
                    scenario
                );
            }
        );


        scenarioGrid.appendChild(
            card
        );
    });


    if (
        scenarios.length === 1 &&
        scenarioDetail
    ) {

        renderScenarioDetail(
            scenarios[0]
        );
    }
}


function renderScenarioDetail(
    scenario
) {
    const originalScenario = scenario;
    scenario = {...scenario, ...Object.fromEntries(["name","id","description","script"].map(key => [key, String(scenario[key] || "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"})[c])]))};

    const scenarioDetail =
        document.getElementById(
            "scenarioDetail"
        );


    if (!scenarioDetail) {
        return;
    }


    const phases =
        Array.isArray(
            scenario.phases
        )
            ? scenario.phases
            : [];


    scenarioDetail.innerHTML = `
        <div class="panel-header">

            <h2>
                ${scenario.name}
            </h2>

            <span class="panel-tag">
                ${scenario.id}
            </span>

        </div>

        <p>
            ${scenario.description || ""}
        </p>

        <p class="muted">
            Script:
            <strong>${scenario.script}</strong>
        </p>

        <p class="muted">
            Attack Technique order:
            <strong>
                ${phases.length
                    ? phases.map(
                        phase => `P${phase}`
                    ).join(" → ")
                    : "No attack techniques defined"}
            </strong>
        </p>
    `;

    const runButton = document.createElement("button");
    runButton.type = "button";
    runButton.className = "button button-start";
    runButton.textContent = "RUN";
    runButton.addEventListener("click", () => {
        configureScenario(originalScenario);
    });
    scenarioDetail.appendChild(runButton);

}


function configureScenario(scenario) {
    if (scenario?.custom && window.MrnPlanning && !scenario.phases?.includes("08")) {
        window.MrnPlanning.runCustom(scenario.id).catch(error => showMessage(error.message, "error"));
        return;
    }
    selectedScenario = scenario;

    if (startButton) {
        startButton.textContent = scenario
            ? `START ${scenario.name}`
            : "START FULL INCIDENT";
    }

    let resetButton = document.getElementById("resetScenarioButton");
    if (!resetButton && startButton) {
        resetButton = document.createElement("button");
        resetButton.id = "resetScenarioButton";
        resetButton.type = "button";
        resetButton.className = "button button-small";
        resetButton.textContent = "USE DEFAULT SCENARIO";
        resetButton.addEventListener("click", () => {
            configureScenario(null);
        });
        startButton.parentElement.appendChild(resetButton);
    }
    if (resetButton) {
        resetButton.hidden = !scenario;
    }

    showPage("campaigns");
    showMessage(
        scenario
            ? `Configure ${scenario.name}, then press START to run it.`
            : "Full Incident selected. Review the configuration before starting.",
        "info"
    );
}


async function loadScenarios() {

    try {

        const data =
            await apiGet(
                "/api/scenarios"
            );


        renderScenarios(
            data.scenarios || []
        );

    }

    catch (error) {

        console.error(
            "Scenario discovery error:",
            error
        );


        const scenarioGrid =
            document.getElementById(
                "scenarioGrid"
            );


        if (scenarioGrid) {

            scenarioGrid.innerHTML = `
                <div class="phase-card">
                    <div class="phase-info">
                        <strong>Unable to load scenarios</strong>
                        <span>Check /api/scenarios</span>
                    </div>
                </div>
            `;
        }
    }
}


function phaseFieldLabel(parameter) {

    const labels = {
        auto: "Automatic Discovery",
        subnet: "Subnet",
        source: "Source Host",
        target: "Target Host",
        port: "Port",
        protocol: "Protocol",
        username: "Username",
        password: "Password",
        powershell: "P10 remote command (PowerShell / Bash) (runtime only, never saved)",
        timeout: "Action timeout (seconds, 5–300)",
        dns_behavior: "DNS behavior", dns_endpoint: "Private lab DNS endpoint (UDP 53)", dns_domain: "Reserved lab domain (.test/.internal/.localhost)", dns_pattern: "Query label pattern (mrn-{seq})", dns_interval: "DNS interval (seconds)", dns_jitter: "DNS jitter (fraction 0-0.5)", dns_count: "DNS query count (1-40)", dns_duration: "DNS duration ceiling (3-240 seconds)",
        file: "File",
        platform: "Execution platform",
        method: "Method",
        behavior: "Native tool behavior",
        transport: "Beacon transport",
        beacon_interval: "Beacon interval (seconds)",
        beacon_jitter: "Beacon jitter (fraction, 0–0.5)",
        beacon_count: "Number of beacons (1–20)",
        uri_profile: "Benign URI profile",
    };

    return labels[parameter] || parameter;
}


function phaseFieldPlaceholder(parameter) {

    const placeholders = {
        subnet: "192.168.1.0/24",
        source: "192.168.1.20",
        target: "192.168.1.20",
        port: "22",
        protocol: "ssh",
        username: "ubuntu",
        password: "Password",
    };

    return placeholders[parameter] || "";
}


function renderPhaseDetail(phase) {

    if (!phaseDetail) {
        return;
    }

    phaseDetail.innerHTML = "";

    phaseDetail.classList.remove(
        "hidden"
    );


    const header =
        document.createElement("div");

    header.className =
        "panel-header";


    const title =
        document.createElement("h2");

    title.textContent =
        `P${phase.id} · ${phase.name}`;


    const mitre =
        document.createElement("span");

    mitre.className =
        "panel-tag";

    const techniques =
        Array.isArray(
            phase.mitre?.techniques
        )
            ? phase.mitre.techniques.join(", ")
            : "";

    mitre.textContent =
        techniques
            ? `${phase.mitre?.tactic || "MITRE"} · ${techniques}`
            : phase.mitre?.tactic || "No MITRE mapping";


    header.appendChild(title);
    header.appendChild(mitre);

    phaseDetail.appendChild(header);
    MrnUI.detail(phaseDetail, phase);


    const form =
        document.createElement("div");

    form.className =
        "form-grid";


    const parameters =
        Array.isArray(
            phase.parameters
        )
            ? phase.parameters
            : [];


    parameters.forEach(parameter => {

        const group =
            document.createElement("div");

        group.className =
            "form-group";


        const label =
            document.createElement("label");

        label.textContent =
            phaseFieldLabel(parameter);


        let input;


        if (parameter === "auto") {

            input =
                document.createElement("input");

            input.type =
                "checkbox";

        } else if (["10", "11"].includes(phase.id) && ["platform", "method", "action", "protocol"].includes(parameter)) {
            input = document.createElement("select");
            const choices = {platform: ["auto", "windows", "linux"], method: ["auto", "scheduled-task", "service", "cron", "systemd"], action: ["create", "cleanup"], protocol: ["", "ssh", "winrm-http", "winrm-https"]}[parameter];
            choices.forEach(value => {const option = document.createElement("option"); option.value = value; option.textContent = value || "Choose transport"; input.appendChild(option);});
        } else if (phase.id === "13" && ["behavior", "protocol"].includes(parameter)) {
            input = document.createElement("select");
            const choices = parameter === "behavior" ? ["encoded-powershell", "certutil-decode", "bits-job"] : ["winrm-http", "winrm-https"];
            choices.forEach(value => {const option = document.createElement("option"); option.value = value; option.textContent = value; input.appendChild(option);});
        } else if (["12", "14", "18"].includes(phase.id) && ["platform", "method", "protocol", "transport", "uri_profile", "dns_behavior"].includes(parameter)) {
            input = document.createElement("select");
            const choices = {platform: ["auto", "windows", "linux"], method: ["read-test-file", "metadata"], protocol: ["", "ssh", "winrm-http", "winrm-https"], transport: ["http", "https"], uri_profile: ["heartbeat", "status"], dns_behavior: ["standard", "low-and-slow", "encoded-marker"]}[parameter];
            choices.forEach(value => {const option = document.createElement("option"); option.value = value; option.textContent = value || "Choose transport"; input.appendChild(option);});
        } else if (["15", "16", "17", "18"].includes(phase.id) && ["web_profile", "protocol", "platform", "behavior", "dataset", "action"].includes(parameter)) {
            input = document.createElement("select");
            const choices = {web_profile: ["sqli", "traversal"], protocol: phase.id === "15" ? ["http", "https"] : ["", "ssh", "winrm-http", "winrm-https"], platform: ["auto", "windows", "linux"], behavior: ["config-toggle", "log-rename"], dataset: ["finance", "engineering"], action: ["run", "cleanup"]}[parameter];
            choices.forEach(value => {const option = document.createElement("option"); option.value = value; option.textContent = value || "Choose transport"; input.appendChild(option);});
        } else if (parameter === "powershell") {
            input = document.createElement("textarea");
            input.rows = 5; input.maxLength = 16384; input.autocomplete = "off";
        } else {

            input =
                document.createElement("input");

            input.type =
                parameter === "password"
                    ? "password"
                    : parameter === "file"
                        ? "file"
                        : parameter === "port"
                            ? "number"
                            : "text";

            input.placeholder =
                phaseFieldPlaceholder(
                    parameter
                );
        }


        if (["beacon_interval", "beacon_jitter", "beacon_count"].includes(parameter)) {
            input.type = "number"; input.value = {beacon_interval: 5, beacon_jitter: 0, beacon_count: 5}[parameter];
            input.min = parameter === "beacon_jitter" ? 0 : 1;
            input.max = {beacon_interval: 60, beacon_jitter: .5, beacon_count: 20}[parameter];
            input.step = parameter === "beacon_count" ? 1 : "any";
        }
        if (parameter === "web_path") input.value = "/mrn-lab";
        if (parameter === "archive_name") input.value = "collection";
        input.dataset.parameter =
            parameter;

        input.id =
            `phase-${phase.id}-${parameter}`;


        label.htmlFor = input.id;
        group.appendChild(label);
        group.appendChild(input);

        form.appendChild(group);
    });


    phaseDetail.appendChild(form);
    if (["10", "11", "12", "14", "16", "17", "18"].includes(phase.id)) {
        const platform = document.getElementById(`phase-${phase.id}-platform`);
        const adapt = () => {
            const mode = platform?.value || "auto";
            for (const key of ["protocol", "method"]) {
                const input = document.getElementById(`phase-${phase.id}-${key}`);
                if (!input || phase.id === "12" && key === "method") continue;
                for (const option of input.options) {
                    option.hidden = !!option.value && option.value !== "auto" && mode !== "auto" && (["ssh", "cron", "systemd"].includes(option.value)) !== (mode === "linux");
                    option.disabled = option.hidden;
                }
                if (input.selectedOptions[0]?.disabled) input.value = key === "method" ? "auto" : "";
            }
        };
        platform?.addEventListener("change", adapt); adapt();
    }


    const controls =
        document.createElement("div");

    controls.className =
        "campaign-controls";


    const runButton =
        document.createElement("button");

    runButton.type =
        "button";

    runButton.className =
        "button button-start";

    runButton.textContent =
        `RUN P${phase.id}`;


    const dryRunButton =
        document.createElement("button");

    dryRunButton.type =
        "button";

    dryRunButton.className =
        "button button-small";

    dryRunButton.textContent =
        "DRY RUN";


    runButton.disabled = !phase.standalone;
    dryRunButton.disabled = !phase.standalone;
    controls.appendChild(runButton);
    controls.appendChild(dryRunButton);

    phaseDetail.appendChild(controls);


    runButton.addEventListener(
        "click",
        () => {
            runStandalonePhase(
                phase,
                false
            );
        }
    );


    dryRunButton.addEventListener(
        "click",
        () => {
            runStandalonePhase(
                phase,
                true
            );
        }
    );
    }

// ==========================================================
// RUN STANDALONE PHASE
// ==========================================================

async function runStandalonePhase(
    phase,
    dryRun = false
) {

    if (!phase) {
        return;
    }


    const data = {
        dry_run: dryRun,
    };


    const parameters =
        Array.isArray(
            phase.parameters
        )
            ? phase.parameters
            : [];


    for (const parameter of parameters) {

        const input =
            document.getElementById(
                `phase-${phase.id}-${parameter}`
            );

        if (!input) {
            continue;
        }


        // --------------------------------------------------
        // Boolean parameters
        // --------------------------------------------------

        if (parameter === "auto") {

            data.auto =
                input.checked === true;

            continue;
        }


        // --------------------------------------------------
        // File parameters
        // --------------------------------------------------

        if (parameter === "file") {

            if (
                input.files &&
                input.files.length > 0
            ) {

                showMessage(
                    "File upload for standalone Attack Techniques " +
                    "will be added in the next step.",
                    "info"
                );

                return;
            }

            continue;
        }


        // --------------------------------------------------
        // Normal parameters
        // --------------------------------------------------

        const value =
            String(
                input.value || ""
            ).trim();

        if (value) {

            data[parameter] =
                value;
        }
    }


    const action =
        dryRun
            ? "dry run"
            : "run";


    if (!dryRun) {

        const confirmed =
            window.confirm(
                `Run P${phase.id} · ${phase.name}?`
            );

        if (!confirmed) {
            return;
        }
    }


    showMessage(
        `${dryRun ? "Dry running" : "Starting"} ` +
        `P${phase.id} · ${phase.name}...`,
        "info"
    );


    try {

        const result =
            await apiPost(
                `/api/phase/${phase.id}/run`,
                data
            );


        showMessage(
            result.message ||
            `Attack Technique ${phase.id} started.`,
            "success"
        );


        for (const key of ["password", "powershell"]) {
            const input = document.getElementById(`phase-${phase.id}-${key}`); if (input) input.value = "";
        }
        await refreshLog();

        console.log(
            "Attack Technique execution:",
            result
        );

    }

    catch (error) {

        console.error(
            "Attack Technique execution error:",
            error
        );


        showMessage(
            error.message,
            "error"
        );
    }
}

document.addEventListener("DOMContentLoaded", () => {
    for (const id of ["campaignPowershell", "campaignBash"]) document.getElementById(id)?.addEventListener("input", updateCampaignP10Review);
    updateCampaignP10Review();
    const toggle = document.getElementById("powershellEnabled");
    const fields = document.getElementById("campaignPowershellFields");
    if (toggle && fields) toggle.addEventListener("change", () => {
        fields.hidden = !toggle.checked;
        if (!toggle.checked) {document.getElementById("campaignPowershell").value = ""; document.getElementById("campaignBash").value = "";}
        updateCampaignP10Review();
    });
});

// ==========================================================
// PHASE STATUS
// ==========================================================

function updatePhases(phases) {
    window.MrnUI?.setExecutionStatuses(phases);

    const cards =
        document.querySelectorAll(
            "#phaseGrid .phase-card"
        );

    cards.forEach(card => {

        const phase =
            card.dataset.phase;

        const statusElement =
            card.querySelector(
                ".phase-status"
            );

        if (!statusElement) {
            return;
        }

        const status =
            phases?.[phase] ||
            "pending";

        card.classList.remove(
            "phase-running",
            "phase-complete",
            "phase-failed",
            "phase-skipped", "phase-partial", "phase-interrupted"
        );

        switch (status) {
            case "partial":
            case "interrupted":
                statusElement.textContent = status.toUpperCase();
                card.classList.add(`phase-${status}`);
                break;

            case "skipped":
            case "disabled":
                statusElement.textContent = "SKIPPED";
                card.classList.add("phase-skipped");
                break;

            case "running":

                statusElement.textContent =
                    "RUNNING";

                card.classList.add(
                    "phase-running"
                );

                break;


            case "complete":

                statusElement.textContent =
                    "COMPLETE";

                card.classList.add(
                    "phase-complete"
                );

                break;


            case "failed":

                statusElement.textContent =
                    "FAILED";

                card.classList.add(
                    "phase-failed"
                );

                break;


            default:

                statusElement.textContent =
                    "NOT RUN";
        }
    });
}


// ==========================================================
// STATUS
// ==========================================================

async function refreshStatus() {

    try {

        const data =
            await apiGet(
                "/api/status"
            );
        if (window.MrnOverview) window.MrnOverview.refresh();

        const running =
            Boolean(
                data.process_running ??
                data.running
            );

        setSystemStatus(
            data.status
        );

const dashboardCampaignStatus =
    document.getElementById(
        "dashboardCampaignStatus"
    );

if (dashboardCampaignStatus) {

    dashboardCampaignStatus.textContent =
        String(
            data.status || "idle"
        ).toUpperCase();


    dashboardCampaignStatus.classList.remove(
        "dashboard-good",
        "dashboard-running",
        "dashboard-warning",
        "dashboard-danger"
    );


    switch (
        String(
            data.status || "idle"
        ).toLowerCase()
    ) {

        case "running":

            dashboardCampaignStatus.classList.add(
                "dashboard-running"
            );

            break;


        case "complete":

            dashboardCampaignStatus.classList.add(
                "dashboard-good"
            );

            break;


        case "failed":

            dashboardCampaignStatus.classList.add(
                "dashboard-danger"
            );

            break;


        case "stopped":

            dashboardCampaignStatus.classList.add(
                "dashboard-warning"
            );

            break;
    }
}

        // --------------------------------------------------
        // INCIDENT ID
        // --------------------------------------------------

        const id =
            data.state?.incident_id ||
            data.incident_id;

        if (incidentId && !window.MrnOverview) {

            if (id) {

                incidentId.textContent =
                    id;

            } else {

                incidentId.textContent =
                    "No active incident";
            }
        }


        // --------------------------------------------------
        // ATTACK TECHNIQUES
        // --------------------------------------------------

        if (data.state?.phases) {

            updatePhases(
                data.state.phases
            );

        } else if (data.phases) {

            updatePhases(
                data.phases
            );
        }


        // --------------------------------------------------
        // BUTTONS
        // --------------------------------------------------

        if (startButton) {

            startButton.disabled =
                running;
        }

        if (stopButton) {

            stopButton.disabled =
                !running;
        }


        // --------------------------------------------------
        // CAMPAIGN FINISHED
        // --------------------------------------------------

        if (
            campaignWasRunning &&
            !running
        ) {

            await refreshInventory();
            await refreshLog();

            if (
                data.status ===
                "complete"
            ) {

                showMessage(
                    "MrNobody Incident Platform campaign completed.",
                    "success"
                );
            }
        }

        campaignWasRunning =
            running;

    }

    catch (error) {

        setSystemStatus(
            "failed"
        );

        console.error(
            "Status error:",
            error
        );
    }
}


// ==========================================================
// START CAMPAIGN
// ==========================================================

function campaignP10Summary(powershell, bash) {
    return `P10: PowerShell ${powershell.trim() ? "configured" : "not configured"} / Bash ${bash.trim() ? "configured" : "not configured"}${!powershell.trim() && !bash.trim() ? " - skipped (NOT_CONFIGURED)" : ""}`;
}
function updateCampaignP10Review() {
    const summary = document.getElementById("campaignP10Review");
    if (summary) summary.textContent = campaignP10Summary(document.getElementById("campaignPowershell")?.value || "", document.getElementById("campaignBash")?.value || "");
}

async function startCampaign() {

    // Keep the selected scenario stable throughout this submission.
    const scenario = selectedScenario;
    const powershell = document.getElementById("campaignPowershell")?.value || "";
    const bash = document.getElementById("campaignBash")?.value || "";
    const powershellEnabled = !!document.getElementById("powershellEnabled")?.checked;

    hideMessage();



    // ------------------------------------------------------
    // General
    // ------------------------------------------------------

    const incidentIp =
        document
            .getElementById(
                "incidentIp"
            )
            ?.value
            .trim() || "";


    const webPorts =
        document
            .getElementById(
                "webPorts"
            )
            ?.value
            .trim() || "";


    const exfilPort =
        Number(
            document
                .getElementById(
                    "exfilPort"
                )
                ?.value
        );


    // ------------------------------------------------------
    // Linux / SSH
    // ------------------------------------------------------

    const sshUser =
        document
            .getElementById(
                "sshUser"
            )
            ?.value
            .trim() || "";


    const sshPassword =
        document
            .getElementById(
                "sshPassword"
            )
            ?.value || "";


    const sshPort =
        Number(
            document
                .getElementById(
                    "sshPort"
                )
                ?.value
        );


    // ------------------------------------------------------
    // Windows / RDP
    // ------------------------------------------------------

    const rdpUser =
        document
            .getElementById(
                "rdpUser"
            )
            ?.value
            .trim() || "";


    const rdpPassword =
        document
            .getElementById(
                "rdpPassword"
            )
            ?.value || "";


    const rdpPort =
        Number(
            document
                .getElementById(
                    "rdpPort"
                )
                ?.value
        );

    // ------------------------------------------------------
    // Wordlist Authentication
    // ------------------------------------------------------

    const wordlistEnabled =
        document
            .getElementById(
                "wordlistEnabled"
            )
            ?.checked === true;


    const wordlistUsers =
        document
            .getElementById(
                "wordlistUsers"
            )
            ?.value
            .trim() || "";


    const wordlistSource = document.getElementById("wordlistSource")?.value || "upload";
    const wordlistPath = document.getElementById("wordlistPath")?.value.trim() || "";

    const wordlistFile =
        document
            .getElementById(
                "wordlistFile"
            )
            ?.files?.[0] || null;

    // ------------------------------------------------------
    // CLIENT VALIDATION - GENERAL
    // ------------------------------------------------------

    if (!incidentIp) {

        showMessage(
            "IncidentVM IP is required.",
            "error"
        );

        return;
    }


    if (!webPorts) {

        showMessage(
            "At least one web/proxy port is required.",
            "error"
        );

        return;
    }


    // ------------------------------------------------------
    // CLIENT VALIDATION - LINUX
    // ------------------------------------------------------

    if (!sshUser) {

        showMessage(
            "Linux SSH username is required.",
            "error"
        );

        return;
    }


    if (!sshPassword) {

        showMessage(
            "Linux SSH password is required.",
            "error"
        );

        return;
    }


    if (
        !Number.isInteger(sshPort) ||
        sshPort < 1 ||
        sshPort > 65535
    ) {

        showMessage(
            "Valid Linux SSH port is required.",
            "error"
        );

        return;
    }


    // ------------------------------------------------------
    // CLIENT VALIDATION - WINDOWS
    // ------------------------------------------------------

    if (!rdpUser) {

        showMessage(
            "Windows username is required.",
            "error"
        );

        return;
    }


    if (!rdpPassword) {

        showMessage(
            "Windows password is required.",
            "error"
        );

        return;
    }


    if (
        !Number.isInteger(rdpPort) ||
        rdpPort < 1 ||
        rdpPort > 65535
    ) {

        showMessage(
            "Valid Windows RDP port is required.",
            "error"
        );

        return;
    }


        // ------------------------------------------------------
    // CLIENT VALIDATION - WORDLIST
    // ------------------------------------------------------

    if (wordlistEnabled) {

        if (!wordlistUsers) {

            showMessage(
                "At least one wordlist username is required.",
                "error"
            );

            return;
        }


        if (wordlistSource === "server" && !wordlistPath.startsWith("/")) {
            showMessage("Enter an absolute wordlist path on the MrNobody server.", "error"); return;
        }
        if (!["upload", "server"].includes(wordlistSource)) {
            showMessage("Choose a wordlist source.", "error"); return;
        }
        if (wordlistSource === "upload" && !wordlistFile) {

            showMessage(
                "A password wordlist file is required.",
                "error"
            );

            return;
        }
    }

    // ------------------------------------------------------
    // CLIENT VALIDATION - EXFIL
    // ------------------------------------------------------

    if (
        !Number.isInteger(exfilPort) ||
        exfilPort < 1 ||
        exfilPort > 65535
    ) {

        showMessage(
            "Valid exfiltration port is required.",
            "error"
        );

        return;
    }


    // ------------------------------------------------------
    // CONFIRM
    // ------------------------------------------------------

    const confirmed =
    window.confirm(
        (scenario
            ? `Start ${scenario.name}?\n\n`
            : "Start the Full Incident scenario?\n\n") +
        "The campaign will dynamically discover hosts " +
        "and execute the configured simulation attack techniques.\n\n" +
        "Linux targets will use SSH credentials.\n" +
        "Windows targets will use RDP credentials.\n" +
        campaignP10Summary(powershellEnabled ? powershell : "", powershellEnabled ? bash : "") + "\n" +
        (
            wordlistEnabled
                ? "Wordlist authentication is ENABLED."
                : "Wordlist authentication is DISABLED."
        )
    );

    if (!confirmed) {
        return;
    }


    if (startButton) {

        startButton.disabled =
            true;
    }


    showMessage(
        "Starting campaign...",
        "info"
    );


    try {

        const formData =
        new FormData();


        // --------------------------------------------------
        // General
        // --------------------------------------------------

        formData.append(
            "incident_ip",
            incidentIp
        );

        formData.append(
            "web_ports",
            webPorts
        );


        // --------------------------------------------------
        // Linux / SSH
        // --------------------------------------------------

        formData.append(
            "ssh_username",
            sshUser
        );

        formData.append(
            "ssh_password",
            sshPassword
        );

        formData.append(
            "ssh_port",
            String(sshPort)
        );


        // --------------------------------------------------
        // Windows / RDP
        // --------------------------------------------------
        formData.append("powershell_enabled", powershellEnabled ? "1" : "0");
        if (powershellEnabled || scenario?.id !== "full-incident" && scenario?.phases?.includes("10")) {
            formData.append("powershell_windows", powershell);
            formData.append("bash", bash);
        }

        formData.append(
            "rdp_username",
            rdpUser
        );

        formData.append(
            "rdp_password",
            rdpPassword
        );

        formData.append(
            "rdp_port",
            String(rdpPort)
        );


        // --------------------------------------------------
        // Wordlist Authentication
        // --------------------------------------------------

        formData.append(
            "wordlist_enabled",
            wordlistEnabled ? "1" : "0"
        );

        formData.append(
            "wordlist_users",
            wordlistUsers
        );

        if (
            wordlistEnabled && wordlistSource === "upload" &&
            wordlistFile
        ) {

            formData.append(
                "wordlist_file",
                wordlistFile
            );
        }


        // --------------------------------------------------
        // Exfiltration
        // --------------------------------------------------
        if (wordlistEnabled && wordlistSource === "server") formData.append("wordlist_path", wordlistPath);

        formData.append(
            "exfil_port",
            String(exfilPort)
        );


        const result =
            await apiPostForm(
                scenario
                    ? `/api/scenario/${encodeURIComponent(scenario.id)}/start`
                    : "/api/start",
                formData
            );


        // --------------------------------------------------
        const powershellField = document.getElementById("campaignPowershell");
        if (powershellField) powershellField.value = "";
        const bashField = document.getElementById("campaignBash");
        if (bashField) bashField.value = "";
        updateCampaignP10Review();
        // Remove passwords immediately after successful
        // submission.
        // --------------------------------------------------

        const sshPasswordField =
            document.getElementById(
                "sshPassword"
            );

        if (sshPasswordField) {

            sshPasswordField.value =
                "";
        }


        const rdpPasswordField =
            document.getElementById(
                "rdpPassword"
            );

        if (rdpPasswordField) {

            rdpPasswordField.value =
                "";
        }


        if (
            incidentId &&
            result.incident_id
        ) {

            incidentId.textContent =
                result.incident_id;
        }


        setSystemStatus(
            "running"
        );


        campaignWasRunning =
            true;


        showMessage(
            result.incident_id
                ? `Campaign ${result.incident_id} started.`
                : (result.message || "MrNobody Incident Platform started."),
            "success"
        );


        await refreshStatus();
        await refreshInventory();
        await refreshLog();

    }

    catch (error) {

        if (startButton) {

            startButton.disabled =
                false;
        }


        showMessage(
            error.message,
            "error"
        );
    }
}


// ==========================================================
// STOP CAMPAIGN
// ==========================================================

async function stopCampaign() {

    const confirmed =
        window.confirm(
            "Stop the running incident campaign?"
        );


    if (!confirmed) {
        return;
    }


    if (stopButton) {

        stopButton.disabled =
            true;
    }


    showMessage(
        "Stopping campaign...",
        "info"
    );


    try {

        await apiPost(
            "/api/stop"
        );


        setSystemStatus(
            "stopped"
        );


        showMessage(
            "Campaign stopped.",
            "success"
        );


        await refreshStatus();
        await refreshInventory();
        await refreshLog();

    }

    catch (error) {

        showMessage(
            error.message,
            "error"
        );

        await refreshStatus();
    }
}


// ==========================================================
// INVENTORY COUNTERS
// ==========================================================

function setCount(
    id,
    value
) {

    const element =
        document.getElementById(
            id
        );

    if (element) {

        element.textContent =
            Number(value || 0);
    }
}


function arrayFromState(
    state,
    key
) {

    if (!state) {
        return [];
    }

    if (
        Array.isArray(
            state[key]
        )
    ) {

        return state[key];
    }

    return [];
}


// ==========================================================
// INVENTORY
// ==========================================================

async function refreshInventory() {

    try {

        const data =
            await apiGet(
                "/api/inventory"
            );


        const networks =
            data.networks?.networks
                ? data.networks.networks
                : [];


        const hosts =
            data.discovered?.hosts
                ? data.discovered.hosts
                : (
                    Array.isArray(data.hosts)
                        ? data.hosts
                        : []
                );


        const webTargets =
            data.web?.targets
                ? data.web.targets
                : [];


        const compromised =
            data.compromised?.hosts
                ? data.compromised.hosts
                : hosts.filter(
                    host =>
                        host.compromised === true
                );


        const transfers =
            data.exfiltration?.transfers
                ? data.exfiltration.transfers
                : [];


        const impacted =
            data.impact?.hosts
                ? data.impact.hosts
                : [];


        // --------------------------------------------------
        // COUNTERS
        // --------------------------------------------------

        setCount(
            "networkCount",
            networks.length
        );

        setCount(
            "hostCount",
            hosts.length
        );

        setCount(
            "webCount",
            webTargets.length
        );

        setCount(
            "compromisedCount",
            compromised.length
        );

        setCount(
            "exfilCount",
            transfers.length
        );

        setCount(
            "impactCount",
            impacted.length
        );


        renderInventory(
            hosts,
            compromised,
            impacted
        );

    }

    catch (error) {

        console.error(
            "Inventory error:",
            error
        );
    }
}


// ==========================================================
// INVENTORY TABLE
// ==========================================================

function renderInventory(
    hosts,
    compromised,
    impacted
) {

    if (!inventoryTable) {
        return;
    }


    inventoryTable.innerHTML =
        "";


    if (!hosts.length) {

        const row =
            document.createElement(
                "tr"
            );

        const cell =
            document.createElement(
                "td"
            );

        cell.colSpan =
            6;

        cell.className =
            "empty-table";

        cell.textContent =
            "No discovery data available.";

        row.appendChild(
            cell
        );

        inventoryTable.appendChild(
            row
        );

        return;
    }


    const compromisedIps =
        new Set(
            compromised.map(
                host =>
                    typeof host === "string"
                        ? host
                        : host.ip
            )
        );


    const impactedIps =
        new Set(
            impacted.map(
                host =>
                    typeof host === "string"
                        ? host
                        : host.ip
            )
        );


    hosts.forEach(host => {

        const row =
            document.createElement(
                "tr"
            );


        // --------------------------------------------------
        // IP
        // --------------------------------------------------

        addCell(
            row,
            host.ip || "-"
        );


        // --------------------------------------------------
        // NETWORK
        // --------------------------------------------------

        addCell(
            row,
            host.network || "-"
        );


        // --------------------------------------------------
        // INTERFACE
        // --------------------------------------------------

        addCell(
            row,
            host.interface || "-"
        );


        // --------------------------------------------------
        // WEB
        // --------------------------------------------------

        addStatusCell(
            row,
            host.web_candidate
                ? "YES"
                : "NO",
            host.web_candidate
                ? "good"
                : "neutral"
        );


        // --------------------------------------------------
        // COMPROMISED
        // --------------------------------------------------

        const isCompromised =
            compromisedIps.has(
                host.ip
            ) ||
            host.compromised === true;


        addStatusCell(
            row,
            isCompromised
                ? "YES"
                : "NO",
            isCompromised
                ? "danger"
                : "neutral"
        );


        // --------------------------------------------------
        // STATUS
        // --------------------------------------------------

        let status =
            "DISCOVERED";

        let statusClass =
            "neutral";


        if (
            impactedIps.has(
                host.ip
            )
        ) {

            status =
                "IMPACTED";

            statusClass =
                "danger";

        } else if (
            isCompromised
        ) {

            status =
                "COMPROMISED";

            statusClass =
                "warning";

        } else if (
            host.web_candidate
        ) {

            status =
                "WEB TARGET";

            statusClass =
                "good";
        }


        addStatusCell(
            row,
            status,
            statusClass
        );


        inventoryTable.appendChild(
            row
        );
    });
}


// ==========================================================
// TABLE HELPERS
// ==========================================================

function addCell(
    row,
    value
) {

    const cell =
        document.createElement(
            "td"
        );

    cell.textContent =
        value;

    row.appendChild(
        cell
    );
}


function addStatusCell(
    row,
    value,
    type
) {

    const cell =
        document.createElement(
            "td"
        );


    const badge =
        document.createElement(
            "span"
        );


    badge.className =
        `table-badge table-${type}`;


    badge.textContent =
        value;


    cell.appendChild(
        badge
    );


    row.appendChild(
        cell
    );
}


// ==========================================================
// CAMPAIGN LOG
// ==========================================================

// One shared request updates visible panels; navigation refreshes newly opened pages.
// Hidden panels keep their content and scroll position. The backend
// streams campaign, standalone Attack Technique and update output into the same log.
let logRefreshInFlight = false;

async function refreshLog() {
    if (logRefreshInFlight) return;
    logRefreshInFlight = true;
    try {
        const data = await apiGet("/api/log");
        document.querySelectorAll("[data-live-log]").forEach(panel => {
            if (panel.clientHeight === 0) return;
            const wasNearBottom =
                panel.scrollHeight - panel.scrollTop - panel.clientHeight < 100;
            panel.textContent = data.log || "Waiting for output...";
            if (wasNearBottom) panel.scrollTop = panel.scrollHeight;
        });
        document.querySelectorAll("[data-log-status]").forEach(status => {
            status.textContent = "Live · refreshes every 2 seconds";
        });
    } catch (error) {
        document.querySelectorAll("[data-log-status]").forEach(status => {
            status.textContent = "Unable to refresh output. Retrying automatically; you can also press REFRESH.";
        });
        console.error("Log error:", error);
    } finally {
        logRefreshInFlight = false;
    }
}


// ==========================================================
// POLLING
// ==========================================================

function startPolling() {

    MrnUI.refreshDashboard();
    if (!statusTimer) {

        statusTimer =
            setInterval(
                refreshStatus,
                STATUS_INTERVAL
            );
    }


    if (!inventoryTimer) {

        inventoryTimer =
            setInterval(
                () => { refreshInventory(); MrnUI.refreshDashboard(); },
                INVENTORY_INTERVAL
            );
    }


    if (!logTimer) {

        logTimer =
            setInterval(
                refreshLog,
                LOG_INTERVAL
            );
    }
}

async function runUpdate() {

    const confirmed =
        window.confirm(
            "Run MrNobody update?"
        );

    if (!confirmed) {
        return;
    }

    if (updateButton) {
        updateButton.disabled = true;
    }

    showMessage(
        "Starting MrNobody update...",
        "info"
    );

    try {

        const result =
            await apiPost(
                "/api/update"
            );

        showMessage(
            result.message ||
            "MrNobody update started.",
            "success"
        );

        await refreshLog();

        setTimeout(
            async () => {
                await loadPhases();
                await refreshLog();

                if (updateButton) {
                    updateButton.disabled = false;
                }
            },
            3000
        );

    }

    catch (error) {

        showMessage(
            error.message,
            "error"
        );

        if (updateButton) {
            updateButton.disabled = false;
        }
    }
}

// ==========================================================
// PAGE NAVIGATION
// ==========================================================

function showPage(pageName) {
    if (["dashboard", "system"].includes(pageName)) MrnUI.refreshDashboard(true);
    const primaryPage = {builder: "scenarios", campaigns: "scenarios", inventory: "system"}[pageName] || pageName;

    if (pageName === "reports") refreshReports();

    if (pageName) refreshLog();

    if (!pageName) {
        return;
    }


    const pages =
        document.querySelectorAll(
            ".app-page"
        );


    pages.forEach(page => {

        page.classList.remove(
            "app-page-active"
        );
    });


    const targetPage =
        document.getElementById(
            `page-${pageName}`
        );


    if (targetPage) {

        targetPage.classList.add(
            "app-page-active"
        );
    }


    const navItems =
        document.querySelectorAll(
            ".nav-item"
        );


    navItems.forEach(item => {

        item.classList.toggle("nav-active", item.dataset.page === primaryPage);
        if (item.dataset.page === primaryPage) item.setAttribute("aria-current", "page");
        else item.removeAttribute("aria-current");
    });
}

// Ground truth is rendered as text: evidence can contain host-supplied markup.
function reportNode(tag, text, parent) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (parent) parent.appendChild(node);
    return node;
}

function reportTable(parent, headers, rows) {
    const container = reportNode("div", null, parent);
    container.className = "table-container";
    const table = reportNode("table", null, container);
    table.className = "inventory-table";
    const heading = reportNode("tr", null, reportNode("thead", null, table));
    headers.forEach(text => reportNode("th", text, heading));
    const body = reportNode("tbody", null, table);
    rows.forEach(values => {
        const row = reportNode("tr", null, body);
        values.forEach(value => reportNode("td", value ?? "Unavailable", row));
    });
    if (!rows.length) {
        const cell = reportNode("td", "No recorded evidence.", reportNode("tr", null, body));
        cell.colSpan = headers.length;
    }
}

function reportType(report) {
    return report.report_type === "standalone_phase" ? `Standalone Attack Technique ${report.phase_id || ""}` : "Campaign";
}

const REPORT_PHASES = [
    ["01", "Discovery"], ["02", "Web"], ["15", "Application Security"], ["03", "Initial Access"], ["08", "Credential Access"], ["09", "AD Privilege Escalation"], ["10", "Custom Remote Command"], ["11", "Persistence"], ["12", "Credential Access"], ["13", "Windows Native Tools / LOLBins"], ["14", "Command & Control"], ["18", "Advanced C2 / DNS Activity"], ["16", "Defense Evasion Simulation"], ["04", "Internal Discovery"], ["17", "Collection / Archive"], ["05", "Staging"], ["06", "Exfiltration"], ["07", "Impact"]
];
const reportArray = value => Array.isArray(value) ? value : [];
let reportHistory = [];
const reportCache = new Map();
let reportFilterVersion = 0;
let reportOpenVersion = 0;
let reportRefreshVersion = 0;

function reportStatus(value) {
    const status = ({complete: "success", failed: "failure", disabled: "skipped",
        pending: "not_run", running: "interrupted"})[value] || value;
    return ["success", "partial", "failure", "skipped", "interrupted", "not_run"].includes(status) ? status : "unknown";
}

function reportBadge(parent, value) {
    const badge = reportNode("span", value || "Unknown", parent);
    badge.className = `report-status report-status-${reportStatus(value)}`;
    return badge;
}

function reportTechniques(report) {
    const unique = new Map();
    const add = (technique, phaseIds = []) => {
        if (typeof technique === "string") technique = {id: technique};
        if (!technique || !/^T\d{4}(?:\.\d{3})?$/.test(technique.id)) return;
        const existing = unique.get(technique.id) || {id: technique.id, name: technique.name, phases: []};
        if (!existing.name) existing.name = technique.name;
        existing.phases = [...new Set([...existing.phases, ...phaseIds])];
        unique.set(technique.id, existing);
    };
    reportArray(report.mitre_summary).forEach(t => add(t, reportArray(t.phases)));
    reportArray(report.phases).forEach(p => reportArray(p.mitre?.techniques).forEach(t => add(t, [p.id])));
    return [...unique.values()];
}

function reportMitre(parent, techniques) {
    const cards = reportNode("div", null, parent);
    cards.className = "report-mitre-grid";
    techniques.forEach(technique => {
        const card = reportNode("div", null, cards);
        card.className = "report-mitre-card";
        const link = reportNode("a", `${technique.id}${technique.name ? " · " + technique.name : ""}`, card);
        // Construct trusted URLs, never use host-supplied hrefs.
        link.href = `https://attack.mitre.org/techniques/${technique.id.replace(".", "/")}/`;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        reportNode("p", `Mapped phases: ${reportArray(technique.phases).join(", ") || "Unrecorded"}`, card);
    });
    if (!techniques.length) reportNode("p", "No technique mappings recorded.", cards);
}

function reportAssets(report) {
    const assets = new Map();
    const mark = (host, state, reference) => {
        if (typeof host === "string") host = {ip: host};
        if (!host || typeof host.ip !== "string" || !host.ip.trim()) return;
        const asset = assets.get(host.ip) || {ip: host.ip, hostname: "", states: new Set(), references: new Set()};
        if (host.hostname) asset.hostname = host.hostname;
        asset.states.add(state);
        asset.references.add(reference);
        assets.set(host.ip, asset);
    };
    const state = report.evidence || {};
    reportArray((report.inventory || state.inventory)?.hosts).forEach(h => mark(h, "discovered", "inventory.hosts"));
    reportArray(state.web_targets?.targets).forEach(h => mark(h, "targeted", "web_targets.targets"));
    reportArray((report.compromised_hosts || state.compromised)?.hosts).forEach(h => {
        if (h.compromised !== false) mark(h, "compromised", "compromised_hosts.hosts");
    });
    reportArray(state.staging?.hosts).forEach(h => {
        if (h.staged !== false) mark(h, "staged", "staging.hosts");
    });
    reportArray(state.exfiltration?.transfers).forEach(t => {
        mark({ip: t.source}, "targeted", "exfiltration.transfers (source)");
        if (t.successful === true) mark({ip: t.source}, "exfiltrated", "exfiltration.transfers (successful)");
    });
    reportArray(state.impact?.hosts).forEach(h => {
        if (h.impacted !== false) mark(h, "impacted", "impact.hosts");
    });
    // Only explicit action events establish targets/outcomes. Do not treat a
    // receiver as exfiltrated, an open port as compromise, or metadata as activity.
    const events = [...reportArray(report.events), ...reportArray(report.phases).flatMap(p => reportArray(p.events))];
    events.forEach(e => {
        const name = e.event || "";
        const ref = `${name} · ${e.evidence?.path || "ground truth"}${e.evidence?.line ? ":" + e.evidence.line : ""}`;
        if (/^(WEB_|ACCESS_|WORDLIST_|STAGING_|IMPACT_|INTERNAL_DISCOVERY)/.test(name) && e.target)
            mark({ip: e.target}, "targeted", ref);
        if (name === "HOST_DISCOVERED" || name === "Discovered") mark({ip: e.target}, "discovered", ref);
        if (/^EXFIL_/.test(name)) mark({ip: e.source || e.fields?.source}, "targeted", ref);
        if (name === "ACCESS_SUCCESS") mark({ip: e.target}, "compromised", ref);
        if (name === "STAGING_SUCCESS") mark({ip: e.target}, "staged", ref);
        if (name === "EXFIL_SUCCESS") mark({ip: e.source || e.fields?.source}, "exfiltrated", ref);
        if (name === "IMPACT_SUCCESS") mark({ip: e.target}, "impacted", ref);
    });
    return [...assets.values()];
}

function reportMetric(parent, label, value) {
    const card = reportNode("div", null, parent);
    card.className = "report-metric";
    reportNode("strong", value ?? "Unavailable", card);
    reportNode("span", label, card);
}

async function fetchReport(id) {
    if (!reportCache.has(id)) {
        const pending = apiGet(`/api/reports/${encodeURIComponent(id)}`);
        reportCache.set(id, pending);
        pending.catch(() => { if (reportCache.get(id) === pending) reportCache.delete(id); });
    }
    return reportCache.get(id);
}

function reportFilterValue(id) {
    return document.getElementById(id)?.value || "";
}

async function filterReports() {
    const table = document.getElementById("reportTable");
    if (!table) return;
    const version = ++reportFilterVersion;
    const type = reportFilterValue("reportTypeFilter");
    const status = reportFilterValue("reportStatusFilter");
    const phase = reportFilterValue("reportPhaseFilter");
    const query = reportFilterValue("reportSearch").trim().toLowerCase();
    const candidates = reportHistory.filter(r => (!type || (r.report_type || "campaign") === type) && (!status || r.status === status));
    table.replaceChildren();
    reportNode("td", "Filtering reports…", reportNode("tr", null, table)).colSpan = 7;
    let unavailable = 0;
    const results = new Array(candidates.length);
    let next = 0;
    // Bound detail requests for larger histories. Reuse immutable report snapshots.
    await Promise.all(Array.from({length: Math.min(4, candidates.length)}, async () => {
        while (next < candidates.length && version === reportFilterVersion) {
            const index = next++;
            const row = candidates[index];
            const idMatch = String(row.id || "").toLowerCase().includes(query);
            let detail;
            if ((phase && row.report_type !== "standalone_phase") || (query && !idMatch)) {
                try { detail = await fetchReport(row.id); }
                catch { unavailable++; continue; }
            }
            const phaseMatch = !phase || (row.report_type === "standalone_phase" ? row.phase_id === phase :
                reportArray(detail?.phases).some(p => p.id === phase));
            const textMatch = !query || idMatch || reportAssets(detail || {}).some(a =>
                `${a.ip} ${a.hostname}`.toLowerCase().includes(query));
            if (phaseMatch && textMatch) results[index] = row;
        }
    }));
    if (version !== reportFilterVersion) return;
    const reports = results.filter(Boolean);
    table.replaceChildren();
    reports.forEach(report => {
        const row = reportNode("tr", null, table);
        const identity = reportNode("td", report.id, row);
        if (report.scenario_name || report.scenario) reportNode("small", report.scenario_name || report.scenario, identity).className = "report-list-meta";
        if (report.techniques?.length) reportNode("small", report.techniques.map(t => `P${t.id} · ${t.name}`).join(" → "), identity).className = "report-list-meta";
        [reportType(report), report.status, report.started, report.summary?.hosts, report.summary?.compromised]
            .forEach(value => reportNode("td", value ?? "Unavailable", row));
        const button = reportNode("button", "Open report", reportNode("td", null, row));
        button.type = "button";
        button.addEventListener("click", () => openReport(report.id));
    });
    if (!reports.length) {
        reportNode("td", reportHistory.length ? "No reports match these filters." :
            "No incident reports available. Run a Full Incident campaign or an individual Attack Technique to create one.",
        reportNode("tr", null, table)).colSpan = 7;
    }
    const notice = document.getElementById("reportFilterNotice");
    if (notice) notice.textContent = `${reports.length} of ${reportHistory.length} reports shown.${unavailable ? ` ${unavailable} reports could not be searched; refresh to retry.` : ""}`;
}

async function refreshReports() {
    const table = document.getElementById("reportTable");
    if (!table) return;
    const version = ++reportRefreshVersion;
    ++reportFilterVersion;
    try {
        const data = await apiGet("/api/reports");
        if (version !== reportRefreshVersion) return;
        reportHistory = reportArray(data.reports);
        for (const [id, key] of [["reportIncidentCount", null], ["reportCompromisedCount", "compromised"],
                                 ["reportExfilCount", "exfiltration"], ["reportImpactCount", "impact"]]) {
            const node = document.getElementById(id);
            if (node) node.textContent = String(key ? reportHistory.reduce((n, r) => n + (Number(r.summary?.[key]) || 0), 0) : reportHistory.length);
        }
        await filterReports();
    } catch (error) {
        if (version !== reportRefreshVersion) return;
        ++reportFilterVersion;
        reportHistory = [];
        table.replaceChildren();
        reportNode("td", `Could not load reports: ${error.message}`, reportNode("tr", null, table)).colSpan = 7;
        for (const id of ["reportIncidentCount", "reportCompromisedCount", "reportExfilCount", "reportImpactCount"]) {
            const node = document.getElementById(id);
            if (node) node.textContent = "Unavailable";
        }
        const notice = document.getElementById("reportFilterNotice");
        if (notice) notice.textContent = "History unavailable. Refresh to retry.";
    }
}

function renderReportPhase(parent, phase, groundTruth = true) {
    const analysis = phase.analysis || {};
    const section = reportNode("section", null, parent);
    section.className = "report-phase-detail";
    reportNode("h3", `${phase.id} · ${phase.name}`, section);
    reportBadge(section, phase.status);
    if (phase.action_outcome) {
        reportNode('p', phase.action_outcome, section);
        reportArray(phase.action_evidence).forEach(detail => reportNode('p', detail, section));
    }
    if (phase.prerequisite_outcome) {
        reportNode('p', phase.prerequisite_outcome, section);
        reportArray(phase.prerequisite_evidence).forEach(detail => reportNode('p', detail, section));
    }
    reportNode("p", `${phase.started || "No recorded start"} → ${phase.ended || "No recorded end"}`, section);
    reportNode("h4", "What happened — recorded facts", section);
    reportNode("p", (groundTruth ? analysis.what_happened : "Review collected logs to establish source, target, method and outcome. Attack Technique status describes the run, not the success of each action.") || "Historical report: no educational analysis recorded. Review the available evidence.", section);
    for (const [key, label] of [["findings", "Findings"], ["detection", "Detection in the CyberLab"],
        ["investigation_tasks", "Investigation tasks"], ["prevention", "Prevention / Mitigation"]]) {
        reportNode("h4", label, section);
        const list = reportNode("ul", null, section);
        const items = key === "findings" && !groundTruth ? ["Compare host and network evidence before concluding which actions succeeded."] : reportArray(analysis[key]);
        (items.length ? items : ["Unavailable in this report."]).forEach(item => reportNode("li", item, list));
    }
    reportNode("p", analysis.guidance_notice || "Educational guidance is separate from recorded evidence.", section).className = "muted";
    if (groundTruth) {
    reportNode("h4", "Evidence references", section);
    const refs = reportArray(analysis.evidence);
    refs.forEach(e => reportNode("p", `${e.path} · line ${e.line}`, section));
    if (!refs.length) reportNode("p", "No evidence references recorded.", section);
    }
    reportNode("h4", "MITRE ATT&CK — technique metadata", section);
    reportMitre(section, reportTechniques({phases: [phase]}));
    if (!groundTruth) return;
    const raw = reportNode("details", null, section);
    reportNode("summary", "Technical ground-truth events", raw);
    reportTable(raw, ["Timestamp", "Action", "Source", "Target", "Protocol / method", "Outcome", "Evidence"],
        reportArray(phase.events).map(e => [e.timestamp, e.event, e.source, e.target,
            [e.protocol, e.method].filter(Boolean).join(" / "), e.outcome, e.message]));
}

function renderReport(detail, report, id, mode = "investigation", selectedPhase = null) {
    const groundTruth = mode === "ground-truth";
    const controls = reportNode("div", null, detail);
    controls.className = "report-view-controls";
    controls.setAttribute("role", "group");
    controls.setAttribute("aria-label", "Report view");
    for (const [value, label] of [["investigation", "Investigation View"], ["ground-truth", "Ground Truth View"]]) {
        const toggle = reportNode("button", label, controls);
        toggle.type = "button";
        toggle.setAttribute("aria-pressed", String(mode === value));
        toggle.addEventListener("click", () => {
            detail.replaceChildren();
            renderReport(detail, report, id, value, selectedPhase);
        });
    }
    const exports = reportNode("div", null, detail);
    exports.className = "report-export-controls";
    for (const [label, suffix] of [["Download HTML", `/export/html?view=${mode}`], ["Download PDF", `/export/pdf?view=${mode}`], ["Open raw JSON", "?raw=1"]]) {
        const link = reportNode("a", label, exports);
        link.href = `/api/reports/${encodeURIComponent(id)}${suffix}`;
        if (label === "Open raw JSON") { link.target = "_blank"; link.rel = "noopener noreferrer"; }
    }
    reportNode("p", groundTruth ? "Ground Truth View: recorded answers and technical evidence." : "Investigation View: investigate independently, then switch freely to Ground Truth View to compare answers. Exports follow this selection.", detail);

    const incident = report.incident || {};
    const assets = reportAssets(report);
    const techniques = reportTechniques(report);
    reportNode("h2", "Incident overview", detail);
    reportNode("h3", incident.id || id, detail);
    reportNode("p", `${reportType(report)} · ${incident.scenario_name || incident.scenario || "Unknown scenario"}`, detail);
    if (report.execution) reportNode("p", `Profile: ${report.execution.profile?.mode || "normal"} · Target duration: ${report.execution.profile?.duration || 0}s · Scenario ID: ${incident.scenario}`, detail);
    reportBadge(detail, incident.status);
    reportNode("p", `Started: ${incident.started || "Unavailable"} · Ended: ${incident.ended || "Unavailable"}`, detail);
    const metrics = reportNode("div", null, detail);
    metrics.className = "report-metrics";
    for (const [label, key, evidence] of [["Hosts discovered", "hosts", report.inventory || report.evidence?.inventory],
        ["Compromised hosts", "compromised", report.compromised_hosts || report.evidence?.compromised],
        ["Exfiltration transfers recorded", "exfiltration", report.evidence?.exfiltration],
        ["Impacted hosts", "impact", report.evidence?.impact]]) {
        const count = report.summary?.[key] ?? (evidence ? reportArray(key === "exfiltration" ? evidence.transfers : evidence.hosts).length : null);
        reportMetric(metrics, label, count);
    }
    reportMetric(metrics, "MITRE techniques mapped", techniques.length);
    reportNode("h3", "Attack timeline", detail);
    reportNode("p", "Select a recorded Attack Technique to read its analysis. Status describes the technique run; it does not confirm every action succeeded.", detail);
    const timeline = reportNode("div", null, detail);
    timeline.className = "report-timeline";
    const phases = reportArray(report.phases);
    const phaseDetail = reportNode("div", null);
    phaseDetail.id = "reportPhaseAnalysis";
    phaseDetail.setAttribute("aria-live", "polite");
    const buttons = [];
    const selectPhase = (phase, selected) => {
        buttons.forEach(b => b.setAttribute("aria-pressed", String(b === selected)));
        phaseDetail.replaceChildren();
        selectedPhase = phase.id;
        renderReportPhase(phaseDetail, phase, groundTruth);
    };
    const ordered = [...REPORT_PHASES.filter(([phaseId]) => !["09", "10", "11", "12", "13", "14", "15", "16", "17", "18"].includes(phaseId) || phases.some(p => p.id === phaseId)).map(([phaseId, name]) => phases.find(p => p.id === phaseId) ||
        {id: phaseId, name, status: "not_run", absent: true}), ...phases.filter(p => !REPORT_PHASES.some(([phaseId]) => p.id === phaseId))];
    ordered.forEach(phase => {
        const button = reportNode("button", null, timeline);
        button.type = "button";
        button.className = `report-timeline-step report-status-${reportStatus(phase.status)}`;
        button.setAttribute("aria-controls", "reportPhaseAnalysis");
        button.setAttribute("aria-pressed", "false");
        reportNode("strong", `${phase.id} · ${phase.name}`, button);
        reportBadge(button, phase.status);
        reportNode("small", `${phase.started || "No recorded start"} → ${phase.ended || "No recorded end"}`, button);
        if (phase.absent) reportNode("small", "No technique record in this report", button);
        button.disabled = !!phase.absent;
        button.addEventListener("click", () => selectPhase(phase, button));
        buttons.push(button);
    });
    reportNode("h3", "MITRE ATT&CK summary", detail);
    reportNode("p", "Attack Technique metadata mappings describe relevant techniques; they do not prove every technique executed or succeeded. Verify the evidence below.", detail);
    reportMitre(detail, techniques);
    reportNode("h3", "Affected assets", detail);
    if (groundTruth) {
    reportNode("p", "Recorded states only. — means no supporting evidence, not proof the host was unaffected. Successful transfers mark their source, not the receiver. Snapshot membership records compromise, staging and impact unless explicitly false.", detail);
    const states = ["discovered", "targeted", "compromised", "staged", "exfiltrated", "impacted"];
    reportTable(detail, ["Host", "Hostname", ...states.map(s => s[0].toUpperCase() + s.slice(1)), "Evidence source"],
        assets.map(a => [a.ip, a.hostname || "Unavailable", ...states.map(s => a.states.has(s) ? "Recorded" : "—"), [...a.references].join("; ")]));
    } else {
        reportNode("p", "Review the discovered inventory and correlate logs to determine which assets were affected. Confirm compromise, staging, transfer and impact in Ground Truth View after investigating.", detail);
        const inventory = report.inventory || report.evidence?.inventory;
        reportTable(detail, ["Host", "Hostname"], reportArray(inventory?.hosts).map(a => [a.ip || a.host, a.hostname || "Unavailable"]));
    }
    reportNode("h3", "Attack Technique analysis", detail);
    detail.appendChild(phaseDetail);
    const previous = ordered.findIndex(p => !p.absent && p.id === selectedPhase);
    const first = previous >= 0 ? previous : ordered.findIndex(p => !p.absent);
    if (first >= 0) selectPhase(ordered[first], buttons[first]);
    else reportNode("p", "No technique records available.", phaseDetail);
    if (groundTruth) {
    const raw = reportNode("details", null, detail);
    raw.className = "report-raw";
    reportNode("summary", "Raw technical evidence and JSON", raw);
    const download = reportNode("a", "Open raw JSON", raw);
    download.href = `/api/reports/${encodeURIComponent(id)}?raw=1`;
    download.target = "_blank";
    download.rel = "noopener noreferrer";
    for (const key of ["inventory", "compromised_hosts", "evidence", "events", "sources", "campaign"]) {
        const section = reportNode("details", null, raw);
        reportNode("summary", key, section);
        reportNode("pre", JSON.stringify(report[key] ?? "Unavailable", null, 2), section);
    }
    }
    if (reportArray(report.warnings).length) {
        reportNode("h3", "Evidence availability", detail);
        report.warnings.forEach(warning => reportNode("p", warning, detail));
    }
}

async function openReport(id) {
    const detail = document.getElementById("reportDetail");
    if (!detail) return;
    const version = ++reportOpenVersion;
    detail.replaceChildren();
    reportNode("p", "Loading report…", detail);
    try {
        const report = await fetchReport(id);
        if (version !== reportOpenVersion) return;
        detail.replaceChildren();
        renderReport(detail, report, id);
    } catch (error) {
        if (version !== reportOpenVersion) return;
        detail.replaceChildren();
        reportNode("p", `Could not load report: ${error.message}`, detail);
    }
}

for (const id of ["reportTypeFilter", "reportStatusFilter", "reportPhaseFilter", "reportSearch"]) {
    document.getElementById(id)?.addEventListener(id === "reportSearch" ? "input" : "change", filterReports);
}



function initializeNavigation() {

    const navItems =
        document.querySelectorAll(
            ".nav-item"
        );


    navItems.forEach(item => {

        item.addEventListener(
            "click",
            () => {

                showPage(
                    item.dataset.page
                );
            }
        );
    });
}

function initializeDashboardActions() {

    const actionButtons =
        document.querySelectorAll(
            "[data-page-link]"
        );


    actionButtons.forEach(button => {

        button.addEventListener(
            "click",
            () => {

                showPage(
                    button.dataset.pageLink
                );
            }
        );
    });
}

// ==========================================================
// EVENT HANDLERS
// ==========================================================

const wordlistEnabledField =
    document.getElementById(
        "wordlistEnabled"
    );

const wordlistUsersField =
    document.getElementById(
        "wordlistUsers"
    );

const wordlistFileField =
    document.getElementById(
        "wordlistFile"
    );


function updateWordlistFields() {
    const enabledP08 = wordlistEnabledField?.checked === true;
    const fields = document.getElementById("wordlistFields");
    const source = document.getElementById("wordlistSource");
    const path = document.getElementById("wordlistPath");
    const server = source?.value === "server";
    if (fields) {fields.hidden = !enabledP08; fields.classList.toggle("hidden", !enabledP08);}
    if (source) source.disabled = !enabledP08;
    if (path) path.disabled = !enabledP08 || !server;
    const uploadFields = document.getElementById("wordlistUploadFields");
    const serverFields = document.getElementById("wordlistServerFields");
    if (uploadFields) uploadFields.hidden = server;
    if (serverFields) serverFields.hidden = !server;

    const enabled =
        wordlistEnabledField?.checked === true;

    if (wordlistUsersField) {

        wordlistUsersField.disabled =
            !enabled;
    }

    if (wordlistFileField) {

        wordlistFileField.disabled =
            !enabled || server;
    }
}

if (updateButton) {

    updateButton.addEventListener(
        "click",
        runUpdate
    );
}

document.getElementById("wordlistSource")?.addEventListener("change", updateWordlistFields);

if (wordlistEnabledField) {

    wordlistEnabledField.addEventListener(
        "change",
        updateWordlistFields
    );

    updateWordlistFields();
}

if (startButton) {

    startButton.addEventListener(
        "click",
        startCampaign
    );
}


if (stopButton) {

    stopButton.addEventListener(
        "click",
        stopCampaign
    );
}


if (refreshInventoryButton) {

    refreshInventoryButton.addEventListener(
        "click",
        refreshInventory
    );
}


document.querySelectorAll("[data-refresh-log]").forEach(button => {
    button.addEventListener("click", refreshLog);
});

if (refreshLogButton) {

    refreshLogButton.addEventListener(
        "click",
        refreshLog
    );
}


// ==========================================================
// INITIALIZE
// ==========================================================

async function initialize() {

    setSystemStatus(
        "idle"
    );

    initializeNavigation();
    initializeDashboardActions();

    try {

        /*
         * Configuration must be loaded before the other
         * GUI components so the form receives defaults
         * from Flask/defaults.conf.
         */

        await loadConfiguration();
        await loadPhases();
        await loadScenarios();
        MrnUI.refreshDashboard();

        await refreshStatus();
        await refreshInventory();
        await refreshLog();

    }

    catch (error) {

        console.error(
            "Initialization error:",
            error
        );
    }


    startPolling();
}


document.addEventListener(
    "DOMContentLoaded",
    initialize
);




// MRN_EXECUTION_OVERVIEW
/* Read-only Dashboard projection. Refresh is driven by the existing status poll. */
(() => {
    'use strict';
    let pending = false;
    const duration = seconds => {
        if (!Number.isFinite(seconds)) return 'Unavailable';
        const hours = Math.floor(seconds / 3600), minutes = Math.floor(seconds % 3600 / 60);
        return [hours && `${hours} h`, minutes && `${minutes} min`, !hours && !minutes && `${Math.floor(seconds)} s`].filter(Boolean).join(' ');
    };
    function node(parent, tag, text, cls) {
        const value = document.createElement(tag);
        if (text !== undefined) value.textContent = String(text);
        if (cls) value.className = cls;
        parent.appendChild(value);
        return value;
    }
    function render(data) {
        const root = document.getElementById('executionOverview');
        if (!root) return;
        root.replaceChildren();
        const id = document.getElementById('incidentId');
        if (id) id.textContent = data.incident_id || 'No active incident';
        if (typeof setSystemStatus === 'function') setSystemStatus(data.status);
        const card = document.getElementById('dashboardCampaignStatus');
        if (card) {
            card.textContent = String(data.status || 'idle').toUpperCase();
            card.classList.remove('dashboard-good', 'dashboard-running', 'dashboard-warning', 'dashboard-danger');
            const cls = {running: 'dashboard-running', complete: 'dashboard-good', partial: 'dashboard-warning', failed: 'dashboard-danger', interrupted: 'dashboard-warning'}[data.status];
            if (cls) card.classList.add(cls);
        }
        const execution = data.execution;
        if (!execution) {node(root, 'p', 'No active execution', 'muted'); return;}
        const status = data.active ? 'Running' : data.status === 'complete' ? 'Last execution · Complete' : `Last execution · ${data.status}`;
        node(root, 'p', status, 'overview-status');
        if (!data.active) node(root, 'p', 'No active execution', 'muted');
        const fields = node(root, 'dl', undefined, 'overview-fields');
        const pair = (label, value) => {node(fields, 'dt', label); node(fields, 'dd', value);};
        pair({campaign: 'Built-in campaign', custom: 'Custom scenario', phase: 'Standalone Attack Technique'}[execution.type] || 'Execution', `${execution.name || execution.id} · ${execution.id}`);
        pair('Execution profile', {normal: 'Normal', slow: 'Slow', custom: 'Custom'}[execution.profile?.mode] || 'Normal');
        pair('Started', data.started ? new Date(data.started).toLocaleString() : 'Unavailable');
        pair(data.active ? 'Elapsed' : 'Recorded elapsed', duration(data.elapsed_seconds));
        if (data.planned_seconds) pair('Target / planned duration', `${duration(data.planned_seconds)} · best-effort`);
        pair('Triggered by', execution.trigger === 'scheduler' ? `Scheduler · ${execution.schedule_id || 'reference unavailable'}` : 'Manual');
        if (data.current_phase) pair('Current attack technique', `P${data.current_phase.id} · ${data.current_phase.name}`);
        else if (data.active) pair('Current attack technique', 'Preparing / waiting for attack technique state');
        if (data.next_phase) pair('Next planned attack technique', `P${data.next_phase.id} · ${data.next_phase.name}`);
        const progress = data.progress;
        if (progress?.total) {
            node(root, 'p', `${progress.percent}% · ${progress.complete}/${progress.total} executable attack techniques complete`);
            const bar = node(root, 'progress'); bar.max = 100; bar.value = progress.percent;
            bar.setAttribute('aria-label', 'Progress by completed attack techniques');
        }
        node(root, 'p', 'Progress reflects attack technique states. Timing and planned windows are best-effort; actual runtime may extend.', 'muted');
        const timeline = node(root, 'ol', undefined, 'overview-timeline');
        (data.timeline || []).forEach(phase => {
            const row = node(timeline, 'li');
            node(row, 'span', `P${phase.id} · ${phase.name}`);
            const allowed = ['complete', 'partial', 'running', 'pending', 'skipped', 'failed', 'interrupted'];
            const state = allowed.includes(phase.status) ? phase.status : 'pending';
            node(row, 'span', state, `overview-phase overview-${state}`);
            if (phase.action_result === 'command_error') node(row, 'small', 'Custom remote command failed', 'muted');
            if (phase.action_result === 'success_with_warning') node(row, 'small', 'Completed with nonfatal stderr/warnings', 'muted');
            if (execution.profile?.mode !== 'normal' && (phase.start_offset !== undefined || phase.duration !== undefined)) {
                node(row, 'small', [phase.start_offset !== undefined && `Planned start +${duration(phase.start_offset)}`, phase.duration !== undefined && `activity window ${duration(phase.duration)}`].filter(Boolean).join(' · '), 'muted');
            }
        });
        if (data.logs?.length) {
            const details = node(root, 'details'); node(details, 'summary', 'Recent lifecycle log');
            details.open = true; node(details, 'pre', data.logs.join('\n'), 'overview-log');
        }
        if (data.report_id && /^(?:MRN|H3)-[A-Za-z0-9_-]+$/.test(data.report_id)) {
            const link = node(root, 'button', 'Open incident report', 'button'); link.type = 'button';
            link.addEventListener('click', () => {showPage('reports'); openReport(data.report_id);});
        }
    }
    async function refresh() {
        if (pending) return;
        pending = true;
        try {
            const response = await fetch('/api/execution-status');
            if (!response.ok) throw new Error('Status unavailable');
            render(await response.json());
        } catch (_) {
            const root = document.getElementById('executionOverview');
            if (root) {root.replaceChildren(); node(root, 'p', 'Execution status unavailable · retrying on next refresh', 'muted');}
        } finally {pending = false;}
    }
    window.MrnOverview = {refresh, render};
})();
