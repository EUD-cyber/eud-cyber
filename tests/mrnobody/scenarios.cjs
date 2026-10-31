const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const elements = new Map();
function element(id = "") {
    const item = {
        id, value: "", checked: false, children: [], listeners: {},
        classList: {add() {}, remove() {}, toggle() {}},
        addEventListener(type, callback) { this.listeners[type] = callback; },
        appendChild(child) {
            this.children.push(child);
            if (child.id) elements.set(child.id, child);
        }
    };
    return item;
}
for (const id of ["startButton", "scenarioDetail", "messageBox", "incidentIp",
                  "webPorts", "exfilPort", "sshUser", "sshPassword", "sshPort",
                  "rdpUser", "rdpPassword", "rdpPort"]) {
    elements.set(id, element(id));
}
elements.get("startButton").parentElement = element();
const context = vm.createContext({
    document: {
        getElementById: id => elements.get(id) || null,
        querySelectorAll: () => [],
        createElement: () => element(),
        addEventListener() {}
    },
    window: {confirm: () => true},
    FormData, console,
    fetch: () => { throw new Error("Real network calls are forbidden"); }
});
vm.runInContext(fs.readFileSync(__dirname + "/../../TESTFILES/ATTACKER-V2/web/static/app.js", "utf8"), context);
vm.runInContext(`
    var submissions = [];
    var pageShown;
    showPage = name => { pageShown = name; };
    apiPostForm = async (url, form) => {
        submissions.push({url, form});
        return {message: "Selected scenario started."};
    };
    refreshStatus = refreshInventory = refreshLog = async () => {};
`, context);
async function main() {
    const values = {
        incidentIp: "192.168.1.254", webPorts: "80,443", exfilPort: "9090",
        sshUser: "ubuntu", sshPassword: "ssh-test", sshPort: "22",
        rdpUser: "Administrator", rdpPassword: "rdp-test", rdpPort: "3389"
    };
    for (const [key, value] of Object.entries(values)) elements.get(key).value = value;
    vm.runInContext('renderScenarioDetail({id: "custom id", name: "Custom", phases: []})', context);
    elements.get("scenarioDetail").children.at(-1).listeners.click();
    assert.equal(context.pageShown, "campaigns");
    assert.equal(elements.get("startButton").textContent, "START Custom");
    assert.equal(context.submissions.length, 0); // RUN opens configuration before submission.
    await vm.runInContext("startCampaign()", context);
    assert.equal(context.submissions.length, 1);
    assert.equal(context.submissions[0].url, "/api/scenario/custom%20id/start");
    assert.equal(context.submissions[0].form.get("ssh_password"), "ssh-test");
    assert.equal(context.submissions[0].form.get("rdp_password"), "rdp-test");
    assert.equal(elements.get("sshPassword").value, "");
    assert.equal(elements.get("rdpPassword").value, "");
    elements.get("resetScenarioButton").listeners.click();
    assert.equal(elements.get("startButton").textContent, "START FULL H3 INCIDENT");
    await vm.runInContext("startCampaign()", context);
    assert.equal(context.submissions.length, 1); // Shared validation rejects missing passwords.
    elements.get("sshPassword").value = "ssh-test";
    elements.get("rdpPassword").value = "rdp-test";
    await vm.runInContext("startCampaign()", context);
    assert.equal(context.submissions[1].url, "/api/start");
    console.log("JavaScript syntax and isolated frontend checks passed; no network requests sent.");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
