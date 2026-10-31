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

function renderPhases(phases) {

    if (!phaseGrid) {
        return;
    }

    phaseGrid.innerHTML = "";

    if (!Array.isArray(phases) || phases.length === 0) {

        phaseGrid.innerHTML = `
            <div class="phase-card">
                <div class="phase-info">
                    <strong>No phases available</strong>
                    <span>No attack metadata was discovered.</span>
                </div>
            </div>
        `;

        return;
    }


    phases.forEach(phase => {

        const card =
            document.createElement("div");

        card.className =
            "phase-card";

        card.dataset.phase =
            phase.id;


        const number =
            document.createElement("div");

        number.className =
            "phase-number";

        number.textContent =
            phase.id;


        const info =
            document.createElement("div");

        info.className =
            "phase-info";


        const name =
            document.createElement("strong");

        name.textContent =
            phase.name;


        const details =
            document.createElement("span");

        const tactic =
            phase.mitre?.tactic || "No MITRE tactic";

        const techniques =
            Array.isArray(
                phase.mitre?.techniques
            )
                ? phase.mitre.techniques.join(", ")
                : "";

        details.textContent =
            techniques
                ? `${tactic} · ${techniques}`
                : tactic;


        const status =
            document.createElement("div");

        status.className =
            "phase-status";

        status.textContent =
            "PENDING";


        info.appendChild(name);
        info.appendChild(details);

        card.appendChild(number);
        card.appendChild(info);
        card.appendChild(status);

        card.addEventListener(
            "click",
            () => {

                document
                    .querySelectorAll(
                        ".phase-card"
                    )
                    .forEach(item => {
                        item.classList.remove(
                            "phase-selected"
                        );
                    });

                card.classList.add(
                    "phase-selected"
                );

                renderPhaseDetail(
                    phase
                );
            }
        );

        phaseGrid.appendChild(card);
            });
}


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
            "Phase discovery error:",
            error
        );

        phaseGrid.innerHTML = `
            <div class="phase-card">
                <div class="phase-info">
                    <strong>Unable to load phases</strong>
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


    scenarios.forEach(scenario => {

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
            scenario.description ||
            scenario.script;


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
            `${scenario.phases?.length || 0} PHASES`;


        card.appendChild(
            info
        );

        card.appendChild(
            status
        );


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
            Phase order:
            <strong>
                ${phases.length
                    ? phases.map(
                        phase => `P${phase}`
                    ).join(" → ")
                    : "No phases defined"}
            </strong>
        </p>
    `;

    const runButton = document.createElement("button");
    runButton.type = "button";
    runButton.className = "button button-start";
    runButton.textContent = "RUN";
    runButton.addEventListener("click", () => {
        configureScenario(scenario);
    });
    scenarioDetail.appendChild(runButton);

}


function configureScenario(scenario) {
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
        file: "File",
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


        input.dataset.parameter =
            parameter;

        input.id =
            `phase-${phase.id}-${parameter}`;


        group.appendChild(label);
        group.appendChild(input);

        form.appendChild(group);
    });


    phaseDetail.appendChild(form);


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
                    "File upload for standalone phases " +
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
            `Phase ${phase.id} started.`,
            "success"
        );


        await refreshLog();

        console.log(
            "Phase execution:",
            result
        );

    }

    catch (error) {

        console.error(
            "Phase execution error:",
            error
        );


        showMessage(
            error.message,
            "error"
        );
    }
}

// ==========================================================
// PHASE STATUS
// ==========================================================

function updatePhases(phases) {

    const cards =
        document.querySelectorAll(
            ".phase-card"
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
            "phase-failed"
        );

        switch (status) {

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
                    "PENDING";
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

        if (incidentId) {

            if (id) {

                incidentId.textContent =
                    id;

            } else {

                incidentId.textContent =
                    "No active incident";
            }
        }


        // --------------------------------------------------
        // PHASES
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

async function startCampaign() {

    // Keep the selected scenario stable throughout this submission.
    const scenario = selectedScenario;

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


        if (!wordlistFile) {

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
        "and execute the configured simulation phases.\n\n" +
        "Linux targets will use SSH credentials.\n" +
        "Windows targets will use RDP credentials.\n" +
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
            wordlistEnabled &&
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
// streams campaign, standalone phase and update output into the same log.
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
                refreshInventory,
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

        item.classList.toggle(
            "nav-active",
            item.dataset.page === pageName
        );
    });
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

    const enabled =
        wordlistEnabledField?.checked === true;

    if (wordlistUsersField) {

        wordlistUsersField.disabled =
            !enabled;
    }

    if (wordlistFileField) {

        wordlistFileField.disabled =
            !enabled;
    }
}

if (updateButton) {

    updateButton.addEventListener(
        "click",
        runUpdate
    );
}

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


