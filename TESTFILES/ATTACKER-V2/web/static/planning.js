/* The builder and scheduler share one structured execution model. */
(() => {
    "use strict";
    let capabilities = [], scenarios = [], custom = [], schedules = [];
    let draft = null, step = 0, editingSchedule = null;
    const steps = ["Scenario basics", "Target mode", "Phase selection / order", "Phase configuration", "Execution profile / timing", "Schedule", "Review / Save / Run"];
    const byId = id => document.getElementById(id);
    const copy = value => JSON.parse(JSON.stringify(value));
    function node(tag, text, parent, className) {
        const result = document.createElement(tag);
        if (text !== undefined) result.textContent = text;
        if (className) result.className = className;
        if (parent) parent.appendChild(result);
        return result;
    }
    function button(parent, text, action) {
        const b = node("button", text, parent, "button"); b.type = "button";
        b.addEventListener("click", () => Promise.resolve().then(action).catch(error => message(error.message)));
        return b;
    }
    function message(text) { byId("planningMessage").textContent = text; }
    async function api(url, method = "GET", data) {
        const response = await fetch(url, {method, headers: {"Content-Type": "application/json"}, body: data === undefined ? undefined : JSON.stringify(data)});
        const value = await response.json();
        if (!response.ok) throw new Error(value.message || value.status || "Request failed");
        return value;
    }
    function field(parent, label, value, change, options) {
        const wrap = node("label", undefined, parent, "planning-field");
        node("span", label, wrap);
        const input = node(options ? "select" : "input", undefined, wrap);
        if (options) options.forEach(option => { const o = node("option", option.label || option, input); o.value = option.value === undefined ? option : option.value; });
        input.value = value ?? "";
        input.addEventListener("change", () => change(input.value));
        return input;
    }
    function credentials(parent) {
        node("p", "Credentials are supplied only when running or arming a schedule. They are never saved in scenario definitions.", parent, "muted");
        const ssh = field(parent, "Linux / SSH password", "", () => {}); ssh.type = "password"; ssh.autocomplete = "new-password";
        const rdp = field(parent, "Windows / RDP / WinRM password", "", () => {}); rdp.type = "password"; rdp.autocomplete = "new-password";
        return () => ({ssh_password: ssh.value, rdp_password: rdp.value});
    }
    function newDraft(definition) {
        draft = definition ? copy(definition) : {version: 1, name: "Custom Incident", description: "", target_mode: "auto", phases: [], profile: {mode: "normal", duration: 0}};
        draft.schedule = {mode: "now", at: "", interval: 86400};
        step = 0; renderBuilder(); showPage("builder");
    }
    function profileForm(parent, value, rerender) {
        field(parent, "Execution profile", value.mode, mode => {value.mode = mode; value.duration = mode === "slow" ? 14400 : 0; rerender();}, [
            {value: "normal", label: "Normal"}, {value: "slow", label: "Slow Campaign"}, {value: "custom", label: "Custom Timing"}
        ]);
        if (value.mode === "slow") field(parent, "Campaign duration (seconds; 14400 = 4 hours)", value.duration, v => {value.duration = Number(v);}).type = "number";
        if (value.mode === "slow") node("p", "Discovery spreads host probes across its time slot. Web discovery spaces host/port checks. Other phases use absolute start offsets. Work can run longer than the target duration.", parent, "muted");
    }
    function parameterForm(parent, phase, mode) {
        const cap = capabilities.find(c => c.id === phase.id);
        if (!cap) return;
        if (mode === "auto") {
            node("p", "Uses the inventory produced by earlier phases. Credentials and global campaign options are supplied at execution time.", parent, "muted");
            return;
        }
        Object.entries(cap.fields).forEach(([key, spec]) => {
            const opts = spec.options ? [{value: "", label: "Choose protocol"}, ...spec.options] : undefined;
            const input = field(parent, spec.label, phase.parameters[key], v => {if (v === "") delete phase.parameters[key]; else phase.parameters[key] = spec.type === "port" ? Number(v) : v;}, opts);
            if (spec.type === "port") { input.type = "number"; input.min = "1"; input.max = "65535"; }
        });
        if (cap.credentials) node("p", "Password will be requested when running. It is not part of this definition.", parent, "muted");
        if (cap.wordlist) node("p", "Wordlist is supplied through the existing campaign upload form or the service credential file at execution time.", parent, "muted");
    }
    function timingForm(parent, phase, profile) {
        if (profile.mode !== "custom") return;
        const labels = {start_offset: "Start offset (seconds)", duration: "Target activity duration (seconds)", delay_min: "Minimum action delay (seconds)", delay_max: "Maximum action delay (seconds)", jitter: "Jitter fraction (0–1)"};
        const cap = capabilities.find(c => c.id === phase.id);
        for (const key of cap.timing) {
            const input = field(parent, labels[key], phase.timing[key], v => {if (v === "") delete phase.timing[key]; else phase.timing[key] = Number(v);});
            input.type = "number"; input.min = "0"; input.step = "any";
        }
    }
    function scheduleForm(parent, value) {
        field(parent, "When", value.mode, v => {value.mode = v; renderBuilder();}, [
            {value: "now", label: "Run Now / save only"}, {value: "once", label: "Run Once"}, {value: "recurring", label: "Recurring"}
        ]);
        if (value.mode !== "now") {
            field(parent, "Start date / time (your browser timezone)", value.at, v => {value.at = v;}).type = "datetime-local";
            node("p", `Timezone: ${Intl.DateTimeFormat().resolvedOptions().timeZone}. The server stores an explicit UTC instant.`, parent, "muted");
        }
        if (value.mode === "recurring") field(parent, "Repeat every (seconds; 86400 = daily)", value.interval, v => {value.interval = Number(v);}).type = "number";
    }
    function definition() {
        const value = copy(draft); delete value.schedule;
        if (value.profile.mode !== "custom") value.phases.forEach(p => {p.timing = {};});
        return value;
    }
    async function saveDraft(run) {
        const value = definition();
        const saved = await api(value.id ? `/api/custom-scenarios/${value.id}` : "/api/custom-scenarios", value.id ? "PUT" : "POST", value);
        draft.id = saved.id;
        const execution = {type: "custom", id: saved.id};
        if (draft.schedule.mode !== "now") {
            const id = await saveSchedule(execution, draft.schedule);
            message(`Scenario and schedule saved (${id}). Supply credentials on Schedules if needed.`);
            await refresh(); showPage("schedules");
        } else if (run) {
            const result = await api("/api/executions/run", "POST", {execution, credentials: readBuilderCredentials()});
            message(result.status); await refresh();
        } else { message("Scenario saved."); await refresh(); showPage("scenarios"); }
    }
    let readBuilderCredentials = () => ({});
    function renderBuilder() {
        const parent = byId("builderBody"); parent.replaceChildren();
        if (!draft) return newDraft();
        node("h2", `${step + 1}. ${steps[step]}`, parent);
        node("p", steps.map((s, i) => `${i === step ? "●" : "○"} ${s}`).join(" → "), parent, "muted planning-steps");
        if (step === 0) {
            field(parent, "Name", draft.name, v => {draft.name = v;});
            field(parent, "Description", draft.description, v => {draft.description = v;});
        } else if (step === 1) {
            field(parent, "Targets", draft.target_mode, v => {
                draft.target_mode = v; draft.phases.forEach(p => {p.parameters = {};}); renderBuilder();
            }, [{value: "auto", label: "Auto Discovery"}, {value: "fixed", label: "Custom / Fixed Targets"}]);
            node("p", "Auto Discovery uses fresh campaign inventories and checks phase dependencies. Fixed Targets requires private lab addresses and phase-specific settings.", parent);
        } else if (step === 2) {
            const options = capabilities.filter(c => !draft.phases.some(p => p.id === c.id));
            const select = field(parent, "Add phase", "", () => {}, [{value: "", label: "Select a phase"}, ...options.map(c => ({value: c.id, label: `P${c.id} · ${c.name}`}))]);
            button(parent, "Add", () => {if (select.value) draft.phases.push({id: select.value, enabled: true, parameters: {}, timing: {}}); renderBuilder();});
            draft.phases.forEach((phase, index) => {
                const row = node("div", undefined, parent, "planning-row");
                const input = node("input", undefined, row); input.type = "checkbox"; input.checked = phase.enabled;
                input.addEventListener("change", () => {phase.enabled = input.checked;});
                node("span", `P${phase.id} · ${capabilities.find(c => c.id === phase.id)?.name}`, row);
                for (const [label, delta] of [["↑", -1], ["↓", 1]]) button(row, label, () => {
                    const next = index + delta; if (next >= 0 && next < draft.phases.length) [draft.phases[index], draft.phases[next]] = [draft.phases[next], draft.phases[index]];
                    renderBuilder();
                });
                button(row, "Remove", () => {draft.phases.splice(index, 1); renderBuilder();});
            });
        } else if (step === 3 || step === 4) {
            if (step === 4) profileForm(parent, draft.profile, renderBuilder);
            draft.phases.filter(p => p.enabled).forEach(phase => {
                const panel = node("div", undefined, parent, "panel"); node("h3", `P${phase.id} · ${capabilities.find(c => c.id === phase.id)?.name}`, panel);
                if (step === 3) parameterForm(panel, phase, draft.target_mode);
                else timingForm(panel, phase, draft.profile);
            });
        } else if (step === 5) scheduleForm(parent, draft.schedule);
        else {
            node("pre", JSON.stringify(definition(), null, 2), parent, "planning-review");
            node("p", `Schedule: ${draft.schedule.mode}${draft.schedule.at ? " · " + draft.schedule.at : ""}`, parent);
            readBuilderCredentials = credentials(parent);
            button(parent, draft.schedule.mode === "now" ? "Save" : "Save scenario + schedule", () => saveDraft(false));
            if (draft.schedule.mode === "now") button(parent, "Save + Run Now", () => saveDraft(true));
            if (draft.phases.some(p => p.enabled && p.id === "08")) node("p", "For a wordlist campaign, save first, then use RUN in Scenarios to upload the wordlist through the existing execution form.", parent, "muted");
        }
        const navigation = node("div", undefined, parent, "planning-row");
        if (step > 0) button(navigation, "Back", () => {step--; renderBuilder();});
        if (step < steps.length - 1) button(navigation, "Next", () => {step++; renderBuilder();});
    }
    async function saveSchedule(execution, value, id) {
        if (!value.at) throw new Error("Choose a start date/time");
        const result = await api(id ? `/api/schedules/${id}` : "/api/schedules", id ? "PUT" : "POST", {
            version: 1, execution, at: new Date(value.at).toISOString(), interval: value.mode === "recurring" ? value.interval : 0, enabled: true
        });
        return result.id;
    }
    function library() {
        const parent = byId("customLibrary"); parent.replaceChildren();
        button(parent, "Create custom scenario", () => newDraft());
        custom.forEach(item => {
            const row = node("div", undefined, parent, "planning-row"); node("strong", item.name, row);
            button(row, "Edit", () => newDraft(item));
            button(row, "Duplicate", () => {const value = copy(item); delete value.id; value.name += " (copy)"; newDraft(value);});
            button(row, "Schedule", () => {showPage("schedules"); scheduleEditor({type: "custom", id: item.id});});
            button(row, "Delete", async () => {if (!confirm(`Delete ${item.name}?`)) return; await api(`/api/custom-scenarios/${item.id}`, "DELETE"); await refresh();});
        });
    }
    function scheduleEditor(initial, existing) {
        editingSchedule = existing || null;
        const parent = byId("scheduleEditor"); parent.replaceChildren();
        node("h2", existing ? "Edit schedule" : "Schedule an execution", parent);
        const spec = copy(initial || {type: "campaign", id: scenarios.find(s => !s.custom)?.id || "full-incident", profile: {mode: "normal", duration: 0}});
        const entries = [...scenarios.map(s => ({value: `${s.custom ? "custom" : "campaign"}:${s.id}`, label: `${s.custom ? "Custom" : "Campaign"} · ${s.name}`})), ...capabilities.filter(c => c.standalone).map(c => ({value: `phase:${c.id}`, label: `Phase P${c.id} · ${c.name}`}))];
        field(parent, "Execution", `${spec.type}:${spec.id}`, value => {const [type, id] = value.split(":"); scheduleEditor({type, id, profile: {mode: "normal", duration: 0}}, existing);}, entries);
        if (spec.type !== "custom") {
            spec.profile ||= {mode: "normal", duration: 0};
            profileForm(parent, spec.profile, () => scheduleEditor(spec, existing));
        } else node("p", "Uses the profile saved in the custom scenario.", parent);
        if (spec.type === "phase") {
            spec.target_mode = spec.id === "01" ? (spec.target_mode || "auto") : "fixed";
            if (spec.id === "01") field(parent, "Targets", spec.target_mode, value => {spec.target_mode = value; spec.parameters = {}; scheduleEditor(spec, existing);}, [{value: "auto", label: "Auto Discovery"}, {value: "fixed", label: "Fixed subnets"}]);
            const phase = {id: spec.id, parameters: spec.parameters ||= {}, timing: spec.timing ||= {}};
            parameterForm(parent, phase, spec.target_mode); timingForm(parent, phase, spec.profile);
        }
        const when = {mode: existing?.interval ? "recurring" : "once", at: existing ? localDate(existing.next_run || existing.at) : "", interval: existing?.interval || 86400};
        field(parent, "Run Once or Recurring", when.mode, v => {when.mode = v;}, [{value: "once", label: "Run Once"}, {value: "recurring", label: "Recurring"}]);
        field(parent, "Start date/time (browser timezone)", when.at, v => {when.at = v;}).type = "datetime-local";
        field(parent, "Repeat interval (seconds, used for Recurring)", when.interval, v => {when.interval = Number(v);}).type = "number";
        const read = credentials(parent);
        if (existing) button(parent, "Supply credentials without changing schedule", async () => {
            await api(`/api/schedules/${existing.id}/arm`, "POST", read());
            message("Temporary credentials supplied until service restart."); parent.replaceChildren(); await refresh();
        });
        button(parent, existing ? "Save changes" : "Save schedule", async () => {
            const id = await saveSchedule(spec, when, editingSchedule?.id);
            const secret = read(); if (Object.values(secret).some(Boolean)) await api(`/api/schedules/${id}/arm`, "POST", secret);
            message("Schedule saved. Temporary credentials expire on service restart."); await refresh(); parent.replaceChildren();
        });
        button(parent, "Run Now", async () => {const result = await api("/api/executions/run", "POST", {execution: spec, credentials: read()}); message(result.status);});
    }
    function localDate(iso) {const d = new Date(iso); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);}
    function scheduleTable() {
        const parent = byId("scheduleList"); parent.replaceChildren();
        button(parent, "New schedule / Run Now", () => scheduleEditor());
        if (!schedules.length) node("p", "No schedules saved.", parent);
        schedules.forEach(item => {
            const row = node("div", undefined, parent, "panel");
            const e = item.execution;
            const scenario = scenarios.find(s => s.id === e.id);
            const executionProfile = e.profile || scenario?.profile || {mode: "normal"};
            node("h3", `${e.type} · ${scenario?.name || capabilities.find(c => c.id === e.id)?.name || e.id}`, row);
            node("p", `${item.enabled ? "Enabled" : "Disabled"} · Next: ${item.enabled ? new Date(item.next_run).toLocaleString() : "—"} · ${executionProfile.mode} ${executionProfile.duration ? executionProfile.duration + "s" : ""} · ${item.interval ? "Every " + item.interval + "s" : "Run Once"}`, row);
            node("p", `Last dispatch: ${item.last_status} · Temporary credentials: ${item.credentials_ready ? "available" : "not supplied"}`, row, "muted");
            button(row, "Run Now", async () => {message((await api(`/api/schedules/${item.id}/run`, "POST", {})).status); await refresh();});
            button(row, "Edit / supply credentials", () => scheduleEditor(e, item));
            button(row, item.enabled ? "Disable" : "Enable", async () => {await api(`/api/schedules/${item.id}/${item.enabled ? "disable" : "enable"}`, "POST", {}); await refresh();});
            button(row, "Delete", async () => {if (!confirm("Delete this schedule?")) return; await api(`/api/schedules/${item.id}`, "DELETE"); await refresh();});
        });
    }
    async function refresh() {
        const [caps, all, saved, planned] = await Promise.all([api("/api/planning/capabilities"), api("/api/scenarios"), api("/api/custom-scenarios"), api("/api/schedules")]);
        capabilities = caps.phases; scenarios = all.scenarios; custom = saved.scenarios; schedules = planned.schedules;
        library(); scheduleTable();
        if (typeof loadScenarios === "function") await loadScenarios();
    }
    document.addEventListener("DOMContentLoaded", () => {
        byId("newCustomScenario").addEventListener("click", () => newDraft());
        document.querySelectorAll('[data-page="schedules"], [data-page="scenarios"]').forEach(b => b.addEventListener("click", () => refresh().catch(e => message(e.message))));
        refresh().catch(error => message(error.message));
    });
    // Expose pure helpers for DOM-based regression tests and existing GUI hooks.
    window.MrnPlanning = {newDraft, refresh, localDate};
})();
