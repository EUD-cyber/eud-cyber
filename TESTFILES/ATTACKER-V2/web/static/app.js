"use strict";

/*
============================================================
 Nordic Manufacturing A/S
 H3 Incident Campaign V2

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

    messageBox.textContent =
        message;

    messageBox.className =
        `message-box message-${type}`;

    messageBox.classList.remove(
        "hidden"
    );
}


function hideMessage() {

    messageBox.classList.add(
        "hidden"
    );
}


// ==========================================================
// SYSTEM STATUS
// ==========================================================

function setSystemStatus(status) {

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
            Boolean(data.running);

        setSystemStatus(
            data.status
        );


        // --------------------------------------------------
        // INCIDENT ID
        // --------------------------------------------------

        const id =
            data.state?.incident_id ||
            data.incident_id;

        if (id) {

            incidentId.textContent =
                id;

        } else {

            incidentId.textContent =
                "No active incident";
        }


        // --------------------------------------------------
        // PHASES
        // --------------------------------------------------

        if (data.state?.phases) {

            updatePhases(
                data.state.phases
            );
        }


        // --------------------------------------------------
        // BUTTONS
        // --------------------------------------------------

        startButton.disabled =
            running;

        stopButton.disabled =
            !running;


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
                    "H3 Incident Campaign completed.",
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

    hideMessage();


    const incidentIp =
        document
            .getElementById(
                "incidentIp"
            )
            .value
            .trim();


    const webPorts =
        document
            .getElementById(
                "webPorts"
            )
            .value
            .trim();


    const sshUser =
        document
            .getElementById(
                "sshUser"
            )
            .value
            .trim();


    const sshPassword =
        document
            .getElementById(
                "sshPassword"
            )
            .value;


    const sshPort =
        Number(
            document
                .getElementById(
                    "sshPort"
                )
                .value
        );


    const exfilPort =
        Number(
            document
                .getElementById(
                    "exfilPort"
                )
                .value
        );


    // ------------------------------------------------------
    // CLIENT VALIDATION
    // ------------------------------------------------------

    if (!sshPassword) {

        showMessage(
            "SSH password is required.",
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
    // CONFIRM
    // ------------------------------------------------------

    const confirmed =
        window.confirm(
            "Start the full H3 Incident Campaign?\n\n" +
            "The campaign will dynamically discover hosts " +
            "and execute all seven simulation phases."
        );


    if (!confirmed) {
        return;
    }


    startButton.disabled =
        true;


    showMessage(
        "Starting campaign...",
        "info"
    );


    try {

        const result =
            await apiPost(
                "/api/start",
                {
                    incident_ip:
                        incidentIp,

                    web_ports:
                        webPorts,

                    ssh_user:
                        sshUser,

                    ssh_password:
                        sshPassword,

                    ssh_port:
                        sshPort,

                    exfil_port:
                        exfilPort
                }
            );


        // --------------------------------------------------
        // Remove password from browser field immediately
        // after successful submission.
        // --------------------------------------------------

        document
            .getElementById(
                "sshPassword"
            )
            .value = "";


        incidentId.textContent =
            result.incident_id;


        setSystemStatus(
            "running"
        );


        campaignWasRunning =
            true;


        showMessage(
            `Campaign ${result.incident_id} started.`,
            "success"
        );


        await refreshStatus();
        await refreshInventory();
        await refreshLog();

    }

    catch (error) {

        startButton.disabled =
            false;


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


    stopButton.disabled =
        true;


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


        // --------------------------------------------------
        // NETWORKS
        // --------------------------------------------------

        const networks =
            arrayFromState(
                data.networks,
                "networks"
            );


        // --------------------------------------------------
        // DISCOVERED HOSTS
        // --------------------------------------------------

        const hosts =
            arrayFromState(
                data.discovered,
                "hosts"
            );


        // --------------------------------------------------
        // WEB TARGETS
        // --------------------------------------------------

        const webTargets =
            arrayFromState(
                data.web,
                "targets"
            );


        // --------------------------------------------------
        // COMPROMISED
        // --------------------------------------------------

        const compromised =
            arrayFromState(
                data.compromised,
                "hosts"
            );


        // --------------------------------------------------
        // EXFIL
        // --------------------------------------------------

        const transfers =
            arrayFromState(
                data.exfiltration,
                "transfers"
            );


        // --------------------------------------------------
        // IMPACT
        // --------------------------------------------------

        const impacted =
            arrayFromState(
                data.impact,
                "hosts"
            );


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
                host => host.ip
            )
        );


    const impactedIps =
        new Set(
            impacted.map(
                host => host.ip
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
            );

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

async function refreshLog() {

    try {

        const data =
            await apiGet(
                "/api/log"
            );


        if (!data.log) {

            campaignLog.textContent =
                "Waiting for campaign...";

            return;
        }


        const wasNearBottom =
            (
                campaignLog.scrollHeight -
                campaignLog.scrollTop -
                campaignLog.clientHeight
            ) < 100;


        campaignLog.textContent =
            data.log;


        if (wasNearBottom) {

            campaignLog.scrollTop =
                campaignLog.scrollHeight;
        }

    }

    catch (error) {

        console.error(
            "Log error:",
            error
        );
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


// ==========================================================
// EVENT HANDLERS
// ==========================================================

startButton.addEventListener(
    "click",
    startCampaign
);


stopButton.addEventListener(
    "click",
    stopCampaign
);


refreshInventoryButton.addEventListener(
    "click",
    refreshInventory
);


refreshLogButton.addEventListener(
    "click",
    refreshLog
);


// ==========================================================
// INITIALIZE
// ==========================================================

async function initialize() {

    setSystemStatus(
        "idle"
    );


    try {

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