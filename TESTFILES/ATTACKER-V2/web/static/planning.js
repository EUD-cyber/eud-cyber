/* The builder and scheduler share one structured execution model. */
(() => {
    "use strict";
    let capabilities = [], scenarios = [], custom = [], schedules = [];
    let readiness = {}, schemaVersion = 1, maxScenarioBytes = 128 * 1024;
    let draft = null, step = 0, editingSchedule = null;
    let autoAdded = new Set(), inherited = new Set(), commonTarget = "";
    let readWordlist = () => null;
    const capFor = id => capabilities.find(c => c.id === id);
    const dependencies = id => capFor(id)?.dependencies || [];
    const enabled = () => draft.phases.filter(p => p.enabled !== false);
    const phase = id => ({id, enabled: true, parameters: {}, timing: {}});
    function ensureAuto() {
        if (draft.target_mode !== "auto") return;
        const result = [], seen = new Set();
        const visit = id => {
            if (seen.has(id)) return;
            dependencies(id).forEach(visit);
            let item = draft.phases.find(p => p.id === id);
            if (!item) {item = phase(id); autoAdded.add(id);}
            item.enabled = true; if (!["10", "11", "12", "13", "14", "15", "16", "17", "18"].includes(id)) item.parameters = {};
            seen.add(id); result.push(item);
        };
        visit("01"); enabled().forEach(p => visit(p.id));
        draft.phases.filter(p => !seen.has(p.id)).forEach(p => {if (!["10", "11", "12", "13", "14", "15", "16", "17", "18"].includes(p.id)) p.parameters = {}; result.push(p);});
        const edges = [["14","18"],["18","16"],["18","04"],["18","17"],["18","05"],["18","06"],["18","07"],["02","15"],["15","03"],["10","16"],["11","16"],["12","16"],["13","16"],["14","16"],["16","17"],["17","05"],["17","06"],["17","07"],["16","05"],["16","06"],["16","07"]];
        for (let pass = 0; pass < result.length; pass++) for (const [a,b] of edges) {
            const i = result.findIndex(p => p.id === a), j = result.findIndex(p => p.id === b);
            if (i >= 0 && j >= 0 && i > j) result.splice(j, 0, result.splice(i, 1)[0]);
        }
        draft.phases = result;
    }
    function required(id) {
        return draft.target_mode === "auto" && (id === "01" || enabled().some(p => dependencies(p.id).includes(id)));
    }
    function validOrder(phases) {
        const ids = phases.filter(p => p.enabled !== false).map(p => p.id);
        const edges = [["14","18"],["18","16"],["18","04"],["18","17"],["18","05"],["18","06"],["18","07"],["02","15"],["15","03"],["10","16"],["11","16"],["12","16"],["13","16"],["14","16"],["16","17"],["17","05"],["17","06"],["17","07"],["16","05"],["16","06"],["16","07"]];
        if (edges.some(([a,b]) => ids.includes(a) && ids.includes(b) && ids.indexOf(a) > ids.indexOf(b))) return false;
        if (draft.target_mode !== "auto") return true;
        const prior = new Set();
        return phases.filter(p => p.enabled !== false).every(p => {
            const valid = (prior.size > 0 || p.id === "01") && dependencies(p.id).every(id => prior.has(id));
            prior.add(p.id); return valid;
        });
    }
    function move(index, delta, apply = false) {
        const next = index + delta, values = [...draft.phases];
        if (next < 0 || next >= values.length) return false;
        [values[index], values[next]] = [values[next], values[index]];
        if (!validOrder(values) || (draft.target_mode === "auto" && values[0].id !== "01")) return false;
        if (apply) draft.phases = values;
        return true;
    }
    function setCommon(value) {
        commonTarget = value.trim();
        draft.phases.forEach(p => {
            if (!capFor(p.id)?.fields.target) return;
            if (inherited.has(p.id) || !p.parameters.target) {
                if (commonTarget) {p.parameters.target = commonTarget; inherited.add(p.id);}
                else {delete p.parameters.target; inherited.delete(p.id);}
            }
        });
    }
    function durationText(seconds) {
        seconds = Number(seconds) || 0;
        const hours = Math.floor(seconds / 3600), minutes = Math.floor(seconds % 3600 / 60), rest = Math.round(seconds % 60 * 100) / 100;
        return [hours && `${hours} h`, minutes && `${minutes} min`, rest && `${rest} s`].filter(Boolean).join(" ") || "0 s";
    }
    function durationForm(parent, label, seconds, change) {
        const group = node("div", undefined, parent, "planning-row");
        let value = Number(seconds) || 0;
        const units = [["Hours", 3600], ["Minutes", 60], ["Seconds", 1]];
        const inputs = units.map(([unit, divisor]) => {
            const amount = divisor === 3600 ? Math.floor(value / divisor) : divisor === 60 ? Math.floor(value % 3600 / 60) : value % 60;
            const input = field(group, `${label} · ${unit}`, amount, () => change(inputs.some(input => Number(input.value) < 0 || !Number.isFinite(Number(input.value))) ? NaN : inputs.reduce((n, input, i) => n + Number(input.value) * units[i][1], 0)));
            input.type = "number"; input.min = "0"; input.step = "any"; return input;
        });
    }
    function recurrenceForm(parent, value) {
        const units = {minute: 60, hour: 3600, day: 86400, week: 604800};
        let unit = Object.keys(units).reverse().find(u => value.interval % units[u] === 0) || "minute";
        const amount = field(parent, "Repeat every", value.interval / units[unit], v => {value.interval = Number(v) * units[unit];});
        amount.type = "number"; amount.min = "1"; amount.step = "any";
        field(parent, "Repeat unit", unit, v => {unit = v; value.interval = Number(amount.value) * units[unit];}, Object.keys(units));
    }
    function scheduleError(value) {
        if (!["now", "once", "recurring"].includes(value.mode)) return "Choose a schedule mode.";
        if (value.mode === "now") return "";
        const date = new Date(value.at);
        if (!value.at || !Number.isFinite(date.getTime())) return "Choose a valid local start date and time.";
        if (date.getTime() <= Date.now()) return "Choose a start date and time in the future.";
        if (value.mode === "recurring" && (!Number.isInteger(value.interval) || value.interval < 60 || value.interval > 31536000)) return "Repeat interval must be between 1 minute and 365 days, in whole seconds.";
        return "";
    }
    function privateAddress(value, network = false) {
        const parts = String(value).split('/'), octets = parts[0].split('.');
        if (octets.length !== 4 || octets.some(x => !/^(0|[1-9]\d{0,2})$/.test(x) || Number(x) > 255)) return false;
        const [a,b] = octets.map(Number);
        return (a === 10 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168) &&
            (network ? parts.length <= 2 && (parts.length === 1 || /^\d+$/.test(parts[1]) && Number(parts[1]) >= 24 && Number(parts[1]) <= 32) : parts.length === 1);
    }
    function presetWarnings() {
        if (!draft?.preset) return [];
        return enabled().flatMap(p => p.id === "09" && draft.target_mode !== "fixed" ? ["P09: use Fixed Targets and select a lab DC with AD management rights."] : p.id === "18" && !p.parameters.dns_endpoint ? ["P18: enter a private non-forwarding lab DNS endpoint."] : p.id === "15" && !p.parameters.target ? ["P15: enter the fingerprinted MrNobody Web Lab target and review its base path/profile."] : []);
    }
    function stepError(index) {
        if (index === 0) {
            if (!draft.name?.trim() || draft.name.length > 160 || /[\x00-\x1f]/.test(draft.name)) return "Enter a name of 1–160 characters without control characters.";
            if (draft.description && (!draft.description.trim() || draft.description.length > 2000 || /[\x00-\x1f]/.test(draft.description))) return "Description must be at most 2000 characters without control characters.";
        }
        if (index === 1 && !["auto", "fixed"].includes(draft.target_mode)) return "Choose Auto Discovery or Fixed Targets.";
        if (index === 2 && (!enabled().length || !validOrder(draft.phases))) return "Enable at least one Attack Technique in a valid dependency order.";
        if (index === 3) {
            if (presetWarnings().length) return presetWarnings()[0];
            if (commonTarget && !privateAddress(commonTarget)) return "Common Target must be a private lab IPv4 address.";
            for (const p of enabled()) {
                const cap = capFor(p.id), params = p.parameters;
                for (const key of draft.target_mode === "fixed" ? cap.required_fields || [] : []) if (!params[key]) return `P${p.id}: enter ${cap.fields[key]?.label || key}.`;
                const platform = params.platform || "auto";
                const effective = params.protocol === "ssh" ? "linux" : params.protocol ? "windows" : platform;
                if (["10", "11", "12", "14", "16", "17", "18"].includes(p.id) && platform !== "auto" && platform !== effective) return `P${p.id}: platform and protocol must match.`;
                const methodPlatform = {"scheduled-task":"windows", service:"windows", cron:"linux", systemd:"linux"}[params.method];
                if (p.id === "11" && methodPlatform && effective !== "auto" && effective !== methodPlatform) return "P11: method and platform must match.";
                if (p.id === "18") {
                    const behavior = params.dns_behavior || "standard";
                    const interval = Number(params.dns_interval ?? (behavior === "low-and-slow" ? 60 : 5)), jitter = Number(params.dns_jitter ?? 0), count = Number(params.dns_count ?? 3), duration = Number(params.dns_duration ?? 240);
                    if (!Number.isFinite(interval) || interval < 1 || interval > 180 || behavior === "low-and-slow" && interval < 30 || !Number.isFinite(jitter) || jitter < 0 || jitter > .5 || !Number.isInteger(count) || count < 1 || count > 40 || !Number.isFinite(duration) || duration < 3 || duration > 240 || (count-1)*interval*(1+jitter)+count*3 > duration) return "P18: DNS interval/count/jitter must fit the 3-240 second duration ceiling; low-and-slow requires at least 30 seconds between queries.";
                    if (params.dns_domain && (params.dns_domain.length > 120 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\.)+(?:test|internal|localhost)$/.test(params.dns_domain))) return "P18: use a reserved lab domain ending .test, .internal or .localhost.";
                    if (params.dns_pattern && !/^[a-z0-9-]{1,20}\{seq\}[a-z0-9-]{0,20}$/.test(params.dns_pattern)) return "P18: query pattern requires one {seq} placeholder and lowercase letters/digits/hyphens.";
                }
                if (p.id === "14") {
                    const interval = Number(params.beacon_interval ?? 5), jitter = Number(params.beacon_jitter ?? 0), count = Number(params.beacon_count ?? 5);
                    if (!Number.isFinite(interval) || interval < 1 || interval > 60 || !Number.isFinite(jitter) || jitter < 0 || jitter > .5 || !Number.isInteger(count) || count < 1 || count > 20 || (count - 1) * interval * (1 + jitter) + count * 3 > 240) return "P14: interval 1-60 seconds, jitter 0-50%, count 1-20; total bounded execution must fit 240 seconds.";
                }
                for (const [key, value] of Object.entries(params)) {
                    const spec = cap.fields[key];
                    if (!spec) return `P${p.id}: unsupported field ${key}.`;
                    if (spec.type === "ipv4" && !privateAddress(value)) return `P${p.id}: ${spec.label} must be a private lab IPv4 address.`;
                    if (spec.type === "networks" && !String(value).split(',').every(v => privateAddress(v.trim(), true))) return `P${p.id}: enter private lab subnets of /24 or smaller.`;
                    if (spec.type === "timeout" && (!Number.isInteger(Number(value)) || value < 5 || value > 300)) return `P${p.id}: timeout must be 5–300 seconds.`;
                    if (spec.type === "port" && (!Number.isInteger(Number(value)) || value < 1 || value > 65535)) return `P${p.id}: port must be 1–65535.`;
                    if (spec.options && !spec.options.includes(value)) return `P${p.id}: choose a supported protocol.`;
                    if (key === "artifact" && !/^[a-z0-9][a-z0-9-]{0,31}$/.test(value)) return "P11: invalid artifact suffix.";
                    if (key === "username" && !/^[A-Za-z0-9_.@\\-]{1,128}$/.test(value)) return `P${p.id}: enter a valid username.`;
                    if (key === "web_path" && !/^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(value)) return "P15: use a simple absolute base path.";
                    if (key === "file" && value !== "@staged" && !/^(?:\/tmp\/\.nordic-(?:MRN|H3)-[A-Za-z0-9_-]+\/nordic-data-(?:MRN|H3)-[A-Za-z0-9_-]+\.txt|C:\\NordicIncident\\(?:MRN|H3)-[A-Za-z0-9_-]+\\staging\\nordic-data-(?:MRN|H3)-[A-Za-z0-9_-]+\.txt)$/.test(value)) return `P${p.id}: use @staged or a synthetic staging file path.`;
                }
            }
        }
        if (index === 4) {
            const {mode, duration} = draft.profile;
            if (!["normal", "slow", "custom"].includes(mode) || !Number.isFinite(duration) || duration < (mode === "slow" ? 60 : 0) || duration > 86400 || mode === "normal" && duration !== 0) return "Choose a valid profile and target duration (Slow: 1 minute–24 hours).";
            if (mode === "custom") for (const p of enabled()) {
                for (const [key, value] of Object.entries(p.timing)) if (!capFor(p.id).timing.includes(key) || !Number.isFinite(value) || value < 0 || value > (key === "jitter" ? 1 : 86400)) return `P${p.id}: timing must be 0–24 hours and jitter 0–100%.`;
                if ((p.timing.delay_max ?? p.timing.delay_min ?? 0) < (p.timing.delay_min || 0)) return `P${p.id}: maximum delay must be at least minimum delay.`;
            }
        }
        if (index === 5) return scheduleError(draft.schedule);
        return "";
    }
    function dataHint(id) {
        return {"01": "Discovers hosts on configured lab networks.", "02": "Uses hosts discovered by P01.", "03": "Uses hosts discovered by P01.", "04": "Uses compromised hosts from P03 as source and target.", "05": "Uses compromised hosts from P03.", "06": "Uses compromised hosts from P03 and staged data from P05.", "07": "Uses compromised hosts from P03.", "09": "Requires Windows access from P03. Select a lab DC with AD management rights; P03 authentication alone does not grant them.", "10": "Uses P03 Windows/WinRM or Linux/SSH access. Auto chooses a compatible host; optional target override filters established access.", "11": "Uses P03 access. Auto chooses Scheduled Task on Windows or cron on Linux. Cleanup uses the same target, username, method and artifact suffix.", "08": "Uses discovery from P01 and access results from P03; wordlist is supplied only at execution."}[id] || "";
    }
    function scheduleSummary(value) {
        return value.mode === "now" ? "Run now / save only" : `${value.mode === "recurring" ? "Repeat every " + intervalText(value.interval) : "Run once"} · ${new Date(value.at).toLocaleString()} · ${Intl.DateTimeFormat().resolvedOptions().timeZone}`;
    }
    function intervalText(seconds) {
        for (const [label, divisor] of [["week", 604800], ["day", 86400], ["hour", 3600], ["minute", 60]]) {
            if (seconds >= divisor && seconds % divisor === 0) return `${seconds / divisor} ${label}${seconds === divisor ? "" : "s"}`;
        }
        return durationText(seconds);
    }
    function timingSummary(value) {
        const span = value.profile.mode === "slow" ? value.profile.duration : Math.max(value.profile.duration || 0, ...value.phases.filter(p => p.enabled !== false).map(p => (p.timing?.start_offset || 0) + (p.timing?.duration || 0)));
        return `${{normal: "Normal", slow: "Slow Campaign", custom: "Custom Timing"}[value.profile.mode]}${span ? " · target / planned span " + durationText(span) : ""}`;
    }
    function review(parent) {
        presetWarnings().forEach(w => node("p", "Needs configuration: " + w, parent, "planning-error"));
        if (draft.preset) node("p", `Preset origin: ${draft.preset.id} · version ${draft.preset.version}. Editing saves a custom scenario.`, parent, "muted");
        node("h3", draft.name, parent); node("p", draft.description || "No description", parent);
        if (draft.teaching_objective) node("p", draft.teaching_objective, parent, "muted");
        node("p", draft.target_mode === "auto" ? "Auto Discovery" : "Custom / Fixed Targets", parent);
        node("p", `Attack Technique flow: ${enabled().map(p => `P${p.id} ${capFor(p.id)?.name}`).join(" → ")}`, parent);
        if (commonTarget) node("p", `Common Target: ${commonTarget}`, parent);
        enabled().forEach(p => {
            node("p", `P${p.id} · ${capFor(p.id)?.name}${required(p.id) ? " · Required" : ""}${autoAdded.has(p.id) ? " · Auto-added prerequisite" : ""}`, parent);
            if (draft.target_mode === "fixed") node("p", Object.entries(p.parameters).map(([k,v]) => `${capFor(p.id).fields[k]?.label || k}: ${v}${k === "target" ? inherited.has(p.id) ? " (Common Target)" : " (local)" : ""}`).join(" · "), parent);
            else {node("p", dataHint(p.id), parent, "muted"); node("p", Object.entries(p.parameters).map(([k,v]) => k + ": " + v).join(" · "), parent); }
        });
        node("p", timingSummary(draft), parent);
        if (draft.profile.mode === "custom") enabled().forEach(p => {
            node("p", `P${p.id} timing: ${Object.entries(p.timing).map(([key, value]) => `${{start_offset: "start offset", duration: "activity duration", delay_min: "minimum delay", delay_max: "maximum delay", jitter: "jitter"}[key]} ${key === "jitter" ? value * 100 + "%" : durationText(value)}`).join(" · ") || "default timing"}`, parent, "muted");
        });
        if (draft.profile.mode !== "normal") node("p", "Timing is best-effort. Actual runtime may extend beyond the target duration / planned span.", parent, "muted");
        node("p", scheduleSummary(draft.schedule), parent);
        const details = node("details", undefined, parent); node("summary", "Advanced / Show JSON", details);
        node("p", `Scenario schema version: ${draft.version}`, details, "muted");
        node("pre", JSON.stringify(definition(), null, 2), details, "planning-review");
        if (draft.id) button(details, "Export saved scenario", () => exportScenario(draft.id));
        if (draft.needs_review) {
            node("p", "Needs review: this legacy scenario was migrated using current defaults. Inspect targets, Attack Technique order and timing. Save any edits, then acknowledge before running or scheduling.", parent, "planning-error");
            button(parent, "Save and acknowledge migration review", async () => {
                await saveDraft(false, true);
            });
        }
    }
    const steps = ["Scenario basics", "Target mode", "Attack Techniques / order", "Technique configuration", "Execution profile / timing", "Schedule", "Review / Save / Run"];
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
    function credentials(parent, execution) {
        node("p", "Credentials are supplied only when running or arming a schedule. They are never saved in scenario definitions.", parent, "muted");
        let model = execution?.type === "custom" ? custom.find(s => s.id === execution.id) : execution;
        if (model?.type === "phase") model = {target_mode: model.target_mode, phases: [{id: model.id, parameters: model.parameters || {}}]};
        if (model?.type === "campaign" && model.id === "full-incident") model = {target_mode: "auto", phases: capabilities.filter(c => ["03", "09", "11", "12", "13", "14", "16", "17", ...(execution.powershell_enabled ? ["10"] : [])].includes(c.id)).map(c => ({id: c.id}))};
        const required = new Set();
        if (!model?.phases) {required.add("ssh"); required.add("rdp");}
        else model.phases.filter(p => p.enabled !== false).forEach(p => {
            if (!capabilities.find(c => c.id === p.id)?.credentials) return;
            if (model.target_mode === "auto") {required.add("ssh"); required.add("rdp");}
            else if (["10", "11", "12", "13", "14", "16", "17", "18"].includes(p.id) && !p.parameters?.protocol && (!p.parameters?.platform || p.parameters.platform === "auto")) {required.add("ssh"); required.add("rdp");}
            else required.add(/^(rdp|winrm)/.test(p.parameters?.protocol || (p.parameters?.platform === "windows" ? "winrm-http" : "ssh")) ? "rdp" : "ssh");
        });
        node("p", `Required runtime credentials: ${required.size ? [...required].map(p => p === "ssh" ? "Linux / SSH" : "Windows / RDP / WinRM").join(", ") : "None"}`, parent);
        const inputs = {};
        for (const protocol of required) {
            const input = field(parent, protocol === "ssh" ? "Linux / SSH password" : "Windows / RDP / WinRM password", "", () => {});
            input.type = "password"; input.autocomplete = "new-password"; inputs[protocol + "_password"] = input;
        }
        if (model?.phases?.some(p => p.id === "10" && p.enabled !== false)) {
            const wrap = node("div", undefined, parent, "planning-field");
            for (const [key, label] of [["powershell_windows", "PowerShell command (Windows, optional)"], ["bash", "Bash command (Linux, optional)"]]) {
                const labelNode = node("label", undefined, wrap);
                node("span", label, labelNode);
                const input = node("textarea", undefined, labelNode);
                input.rows = 5; input.autocomplete = "off"; input.maxLength = 16384;
                inputs[key] = input;
            }
            const summary = node("p", "", parent, "muted");
            const update = () => {summary.textContent = `P10 Review: PowerShell ${inputs.powershell_windows.value.trim() ? "configured" : "not configured"} / Bash ${inputs.bash.value.trim() ? "configured" : "not configured"}. Both blank: skipped (NOT_CONFIGURED).`;};
            Object.values(inputs).forEach(input => input.addEventListener("input", update)); update();
            node("p", "Commands are optional and run independently on compatible targets. Schedules hold them only in memory until restart or edit. Reports show bounded redacted output.", parent, "muted");
        }
        return () => Object.fromEntries(Object.entries(inputs).map(([key, input]) => {const value = input.value; input.value = ""; return [key, value];}));
    }
    function newDraft(definition) {
        draft = definition ? copy(definition) : {version: schemaVersion, name: "Custom Incident", description: "", target_mode: "auto", phases: [], profile: {mode: "normal", duration: 0}};
        if (draft.teaching_objective) draft.teaching_objective = String(draft.teaching_objective);
        draft.schedule = {mode: "now", at: "", interval: 86400};
        autoAdded = new Set(); inherited = new Set(); commonTarget = "";
        // Existing/imported definitions retain their exact order and enabled flags.
        if (!definition) ensureAuto();
        step = 0; renderBuilder(); showPage("builder");
    }
    function profileForm(parent, value, rerender, modes = ["normal", "slow", "custom"]) {
        field(parent, "Execution profile", value.mode, mode => {value.mode = mode; value.duration = mode === "slow" ? 14400 : 0; rerender();}, [
            {value: "normal", label: "Normal"}, {value: "slow", label: "Slow Campaign"}, {value: "custom", label: "Custom Timing"}
        ].filter(option => modes.includes(option.value)));
        if (value.mode !== "normal") durationForm(parent, "Target duration", value.duration, v => {value.duration = v;});
        if (value.mode === "slow") node("p", "Discovery spreads host probes across its time slot. Web discovery spaces host/port checks. Other techniques use absolute start offsets. Work can run longer than the target duration.", parent, "muted");
    }
    function parameterForm(parent, phase, mode, common = false, existing = false, onChange = () => {}) {
        const cap = capabilities.find(c => c.id === phase.id);
        if (!cap) return;
        if (!existing) parent = node("div", undefined, parent, "phase-parameters");
        if (cap.runtime_powershell) node("p", "P10 remote command (PowerShell / Bash) is requested on Review or when arming the schedule; it is never stored in the definition.", parent, "muted");
        if (["15", "16", "17"].includes(phase.id)) node("p", {"15": "Fingerprint required: dedicated MrNobody Web Lab endpoint. Auto uses P02 web services; no compromise is invented.", "16": "Only synthetic monitor.conf or exercise.log in the MRN exercise directory; original state is restored. Cleanup recovers an interrupted run.", "17": "Only fixed marker-verified finance/engineering files. Archives feed staged-data.json for P05/P06. Cleanup removes the selected archive."}[phase.id], parent, "muted");
        if (phase.id === "12") node("p", "Synthetic temporary test file only: inspect metadata or verify its fixed lab marker, then clean up. Auto requires prior P03 access.", parent, "muted");
        if (phase.id === "18") node("p", "DNS only, UDP 53. Private resolver and reserved lab domain; use a non-forwarding lab DNS zone. Standard defaults: 5s; low-and-slow: 60s (minimum 30s). Three queries, 0% jitter, 4 minute duration ceiling. Internal DNS timing is independent of campaign offsets. Fixed marker only; no remote commands or answer processing.", parent, "muted");
        if (phase.id === "14") node("p", "Beacons to this MrNobody instance only. Internal interval/count is independent of the technique start offset. Default: HTTP, 5 seconds, 0% jitter, 5 check-ins. Maximum execution budget: 240 seconds. HTTPS uses the lab self-signed certificate policy.", parent, "muted");
        if (phase.id === "13") node("p", "Windows only. Choose encoded PowerShell, local certutil decode, or an empty BITS job that is cancelled. No arbitrary command or URL is accepted. Default: encoded PowerShell.", parent, "muted");
        if (phase.id === "09") node("p", "P09 requires a lab domain controller and AD management rights. New or disabled mrnobody accounts are enabled using the runtime Windows password; an already enabled account keeps its password. Domain Admins membership is verified.", parent, "muted");
        if (mode === "auto") {
            node("p", dataHint(phase.id), parent, "muted");
            if (!["10", "11", "12", "13", "14", "15", "16", "17", "18"].includes(phase.id)) return;
        }
        Object.entries(cap.fields).forEach(([key, spec]) => {
            const platform = phase.parameters.platform || "auto";
            let options = spec.options;
            if (["10", "11", "12", "13", "14", "16", "17", "18"].includes(phase.id)) {
                if (key === "protocol") options = options.filter(v => platform === "auto" || (v === "ssh") === (platform === "linux"));
                if (key === "method" && phase.id === "11") options = options.filter(v => v === "auto" || platform === "auto" || (["cron", "systemd"].includes(v)) === (platform === "linux"));
                if (key === "source" || key === "subnet" || key === "file") return;
            }
            if (spec.type === "seconds") {
                const fallback = phase.id === "18" && key === "dns_interval" ? (phase.parameters.dns_behavior === "low-and-slow" ? 60 : 5) : spec.default;
                durationForm(parent, spec.label, phase.parameters[key] ?? fallback, v => {phase.parameters[key] = v;}); return;
            }
            if (spec.type === "fraction") {
                const input = field(parent, spec.label, (phase.parameters[key] ?? spec.default) * 100, v => {phase.parameters[key] = Number(v) / 100;});
                input.type = "number"; input.min = "0"; input.max = "50"; return;
            }
            const opts = options ? [{value: "", label: "Automatic / choose"}, ...options] : undefined;
            let hint;
            const input = field(parent, spec.label, phase.parameters[key] ?? spec.default, v => {
                if (v === "") delete phase.parameters[key]; else phase.parameters[key] = ["port", "timeout", "number"].includes(spec.type) ? Number(v) : v;
                if (key === "platform") {
                    delete phase.parameters.protocol; delete phase.parameters.port; delete phase.parameters.username;
                    if (phase.id === "11") delete phase.parameters.method;
                    parent.replaceChildren(); parameterForm(parent, phase, mode, common, true, onChange);
                }
                if (phase.id === "18" && key === "dns_behavior") {
                    parent.replaceChildren(); parameterForm(parent, phase, mode, common, true, onChange);
                }
                if (["platform", "protocol"].includes(key)) onChange();
                if (key === "target" && common) {inherited.delete(phase.id); if (hint) hint.textContent = "Local override";}
            }, opts);
            if (key === "target" && common && commonTarget) {
                hint = node("span", inherited.has(phase.id) ? "Inherited from Common Target" : "Local override", parent, "muted");
                button(parent, "Use Common Target", () => {phase.parameters.target = commonTarget; inherited.add(phase.id); renderBuilder();});
            }
            if (spec.type === "timeout") {input.type = "number"; input.min = "5"; input.max = "300";}
            if (spec.type === "port") { input.type = "number"; input.min = "1"; input.max = "65535"; }
        });
        if (cap.credentials) node("p", "Password will be requested when running. It is not part of this definition.", parent, "muted");
        if (cap.wordlist) node("p", "Wordlist upload and usernames are requested on Review for Run Now. Scheduled runs use the service wordlist source.", parent, "muted");
    }
    function timingForm(parent, phase, profile) {
        if (profile.mode !== "custom") return;
        const cap = capFor(phase.id);
        for (const key of cap.timing) {
            if (["start_offset", "duration", "delay_min", "delay_max"].includes(key)) {
                durationForm(parent, {start_offset: "Start offset", duration: "Target activity duration", delay_min: "Minimum action delay", delay_max: "Maximum action delay"}[key], phase.timing[key], v => {phase.timing[key] = v;}); continue;
            }
            const input = field(parent, "Jitter (%)", (phase.timing[key] || 0) * 100, v => {if (v === "") delete phase.timing[key]; else phase.timing[key] = Number(v) / 100;});
            input.type = "number"; input.min = "0"; input.max = "100"; input.step = "any";
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
        if (value.mode === "recurring") recurrenceForm(parent, value);
        if (draft?.phases.some(p => p.enabled !== false && p.id === "08") && value.mode !== "now") node("p", "Scheduled P08 needs a service-side NORDIC_WORDLIST_FILE and NORDIC_WORDLIST_USERS. Password leases expire on restart; configure service credentials for unattended runs. Wordlist contents are never saved in schedules.", parent, "muted");
    }
    function definition() {
        const value = copy(draft); delete value.schedule;
        if (value.profile.mode !== "custom") value.phases.forEach(p => {p.timing = {};});
        return value;
    }
    async function saveDraft(run, acknowledge = false) {
        for (let i = 0; i < 6; i++) {const error = stepError(i); if (error) {step = i; renderBuilder(); byId("builderError").textContent = error; return;}}
        const wordlist = run ? readWordlist() : null;
        const value = definition();
        if (value.needs_review && (run || draft.schedule.mode !== "now")) throw new Error("Acknowledge migration review before running or scheduling.");
        const saved = await api(value.id ? `/api/custom-scenarios/${value.id}` : "/api/custom-scenarios", value.id ? "PUT" : "POST", value);
        draft.id = saved.id;
        if (acknowledge) {
            await api(`/api/custom-scenarios/${saved.id}/review`, "POST", {acknowledged: true});
            delete draft.needs_review;
        }
        const execution = {type: "custom", id: saved.id};
        if (draft.schedule.mode !== "now") {
            const id = await saveSchedule(execution, draft.schedule);
            const secret = readBuilderCredentials();
            if (Object.values(secret).some(Boolean)) await api(`/api/schedules/${id}/arm`, "POST", secret);
            message(`Scenario and schedule saved (${id}). Supply credentials in Scheduler if needed.`);
            await refresh(); showPage("schedules");
        } else if (run) {
            let result;
            const secret = readBuilderCredentials();
            if (wordlist) {
                const data = new FormData(); Object.entries(secret).forEach(([key, value]) => data.append(key, value));
                data.append("wordlist_enabled", "1"); data.append("wordlist_users", wordlist.users);
                if (wordlist.file) data.append("wordlist_file", wordlist.file);
                if (wordlist.path) data.append("wordlist_path", wordlist.path);
                const response = await fetch(`/api/scenario/${saved.id}/start`, {method: "POST", body: data});
                result = await response.json(); if (!response.ok) throw new Error(result.message || result.status);
            } else result = await api("/api/executions/run", "POST", {execution, credentials: secret});
            message(result.status); await refresh();
        } else { message("Scenario saved."); await refresh(); showPage("scenarios"); }
    }
    let readBuilderCredentials = () => ({});
    function renderBuilder() {
        const parent = byId("builderBody"); parent.replaceChildren();
        if (!draft) return newDraft();
        node("h2", `${step + 1}. ${steps[step]}`, parent);
        const progress = node("ol", undefined, parent, "planning-steps");
        steps.forEach((label, index) => {
            const item = node("li", undefined, progress, index < step ? "completed" : index === step ? "current" : "upcoming");
            const control = button(item, `${index + 1}. ${label}`, () => {step = index; renderBuilder();});
            control.disabled = index > step;
            if (index === step) control.setAttribute?.("aria-current", "step");
        });
        const errorBox = node("p", "", parent, "planning-error"); errorBox.id = "builderError"; errorBox.setAttribute?.("role", "alert");
        readWordlist = () => null;
        if (step === 0) {
            field(parent, "Name", draft.name, v => {draft.name = v;});
            field(parent, "Description", draft.description, v => {draft.description = v;});
        } else if (step === 1) {
            field(parent, "Targets", draft.target_mode, v => {
                draft.target_mode = v; if (v === "fixed") {draft.phases = draft.phases.filter(p => !autoAdded.has(p.id)); autoAdded.clear();} else {commonTarget = ""; inherited.clear(); ensureAuto();} renderBuilder();
            }, [{value: "auto", label: "Auto Discovery"}, {value: "fixed", label: "Custom / Fixed Targets"}]);
            node("p", "Auto Discovery uses fresh campaign inventories and checks technique dependencies. Fixed Targets requires private lab addresses and technique-specific settings.", parent);
        } else if (step === 2) {
            const options = capabilities.filter(c => !draft.phases.some(p => p.id === c.id));
            const select = field(parent, "Add Attack Technique", "", () => {}, [{value: "", label: "Select an Attack Technique"}, ...options.map(c => ({value: c.id, label: `P${c.id} · ${c.name}`}))]);
            button(parent, "Add", () => {if (select.value) {draft.phases.push(phase(select.value)); autoAdded.delete(select.value); ensureAuto(); if (draft.target_mode === "fixed") setCommon(commonTarget);} renderBuilder();});
            const workspace = node("div", undefined, parent, "builder-selection");
            const available = node("section", undefined, workspace, "builder-available");
            node("h3", "Available Attack Techniques", available);
            const search = field(available, "Search catalog", "", () => {}); search.type = "search";
            const choiceList = node("div", undefined, available, "builder-choices");
            const renderChoices = () => {
                choiceList.replaceChildren();
                const choices = options.filter(c => (`P${c.id} ${c.name}`).toLowerCase().includes(search.value.trim().toLowerCase()));
                if (!choices.length) node("p", "No matching techniques available.", choiceList, "muted");
                choices.forEach(c => {
                    const b = button(choiceList, `+ P${c.id} · ${c.name}`, () => {draft.phases.push(phase(c.id)); autoAdded.delete(c.id); ensureAuto(); if (draft.target_mode === "fixed") setCommon(commonTarget); renderBuilder();});
                    b.className = "mapped-technique";
                });
            };
            search.addEventListener("input", renderChoices); renderChoices();
            const flow = node("section", undefined, workspace, "builder-selected");
            node("h3", `Selected Attack Techniques · ${enabled().length}`, flow);
            draft.phases.forEach((phase, index) => {
                const row = node("div", undefined, flow, "planning-row");
                const input = node("input", undefined, row); input.type = "checkbox"; input.checked = phase.enabled !== false; input.disabled = required(phase.id); input.setAttribute?.("aria-label", `Enable P${phase.id}`);
                input.addEventListener("change", () => {if (!required(phase.id)) {phase.enabled = input.checked; ensureAuto();} renderBuilder();});
                node("span", `P${phase.id} · ${capabilities.find(c => c.id === phase.id)?.name}`, row);
                if (required(phase.id)) node("span", "Required", row, "planning-badge");
                if (autoAdded.has(phase.id)) node("span", "Auto-added prerequisite", row, "planning-badge");
                if (draft.target_mode === "auto") node("p", dataHint(phase.id), row, "muted");
                for (const [label, delta] of [["↑", -1], ["↓", 1]]) {
                    const control = button(row, label, () => {move(index, delta, true); renderBuilder();});
                    control.disabled = !move(index, delta);
                    control.setAttribute?.("aria-label", `${delta < 0 ? "Move up" : "Move down"} P${phase.id}`);
                }
                button(row, "Remove", () => {if (!required(phase.id)) {draft.phases.splice(index, 1); autoAdded.delete(phase.id); inherited.delete(phase.id);} renderBuilder();}).disabled = required(phase.id);
            });
        } else if (step === 3 || step === 4) {
            if (step === 3 && draft.target_mode === "fixed") field(parent, "Common Target (optional)", commonTarget, value => {setCommon(value); renderBuilder();});
            if (step === 4) profileForm(parent, draft.profile, renderBuilder);
            enabled().forEach(phase => {
                const panel = node("div", undefined, parent, "panel"); node("h3", `P${phase.id} · ${capabilities.find(c => c.id === phase.id)?.name}`, panel);
                if (step === 3) parameterForm(panel, phase, draft.target_mode, true);
                else timingForm(panel, phase, draft.profile);
            });
        } else if (step === 5) scheduleForm(parent, draft.schedule);
        else {
            review(parent);
            readBuilderCredentials = credentials(parent, definition());
            button(parent, draft.schedule.mode === "now" ? "Save" : "Save scenario + schedule", () => saveDraft(false));
            if (draft.schedule.mode === "now") button(parent, "Save + Run Now", () => saveDraft(true));
            if (enabled().some(p => p.id === "08") && draft.schedule.mode === "now") {
                const users = field(parent, "P08 usernames (execution only)", "ubuntu,Administrator", () => {});
                const upload = field(parent, "P08 wordlist upload (execution only)", "", () => {}); upload.type = "file";
                const serverPath = field(parent, "P08 wordlist path on server (execution only)", "", () => {});
                node("p", "Upload a file OR enter an existing absolute path on MrNobody. Leave both empty to use the configured service wordlist. These inputs are never saved in scenario or schedule definitions.", parent, "muted");
                readWordlist = () => {
                    if (!users.value.trim()) throw new Error("Enter at least one P08 username for this run.");
                    const path = serverPath.value.trim(), file = upload.files?.[0];
                    if (path && file) throw new Error("Choose either an upload or a server wordlist path.");
                    if (path && !path.startsWith("/")) throw new Error("Enter an absolute wordlist path on MrNobody.");
                    return {users: users.value.trim(), file, path};
                };
            }
        }
        const navigation = node("div", undefined, parent, "planning-row");
        if (step > 0) button(navigation, "Back", () => {step--; renderBuilder();});
        if (step < steps.length - 1) button(navigation, "Next", () => {const error = stepError(step); if (error) {errorBox.textContent = error; return;} step++; renderBuilder();});
    }
    async function saveSchedule(execution, value, id) {
        const error = scheduleError(value); if (error) throw new Error(error);
        const result = await api(id ? `/api/schedules/${id}` : "/api/schedules", id ? "PUT" : "POST", {
            version: 1, execution, at: new Date(value.at).toISOString(), interval: value.mode === "recurring" ? value.interval : 0, enabled: true
        });
        return result.id;
    }
    function library() {
        const parent = byId("customLibrary"); parent.replaceChildren();
        node("h2", "Custom scenarios", parent);
        const upload = node("input", undefined, parent); upload.type = "file"; upload.accept = ".json,application/json";
        upload.setAttribute?.("aria-label", "Scenario JSON file");
        button(parent, "Import Scenario", async () => {
            const file = upload.files?.[0];
            if (!file) throw new Error("Choose a scenario JSON file first.");
            if (file.size > maxScenarioBytes) throw new Error("Scenario JSON exceeds the 128 KiB limit.");
            const response = await fetch("/api/custom-scenarios/import", {method: "POST", headers: {"Content-Type": "application/json"}, body: await file.text()});
            const result = await response.json();
            if (!response.ok) throw new Error(result.message || "Scenario import failed. Nothing was saved.");
            await refresh();
            message(`${result.readiness}: ${result.message} ${(result.notes || []).join(" ")}`);
        });
        node("p", "JSON only · maximum 128 KiB. Imports create editable custom scenarios. Credentials and P10 commands must be supplied at execution time. Schedules are kept separate and are never recreated by import.", parent, "muted");
        if (!custom.length) node("p", "No custom scenarios saved. Use Scenario Builder to create one.", parent, "empty-state");
        custom.forEach(item => {
            const row = node("div", undefined, parent, "planning-row"); node("strong", item.name, row);
            node("p", item.description || "Custom incident scenario", row);
            node("span", readiness[item.id] || (item.needs_review ? "Needs review" : "Custom scenario"), row, "planning-badge");
            node("p", `${item.target_mode === "auto" ? "Auto Discovery" : "Fixed Targets"} · ${item.phases.filter(p => p.enabled !== false).map(p => "P" + p.id).join(" → ")} · ${timingSummary(item)} · ${schedules.filter(s => s.execution.type === "custom" && s.execution.id === item.id).length} schedule(s)`, row);
            button(row, "Run", () => runCustom(item.id));
            button(row, "Edit", () => newDraft(item));
            button(row, "Export", () => exportScenario(item.id));
            button(row, "Duplicate", () => {const value = copy(item); delete value.id; value.name += " (copy)"; newDraft(value);});
            button(row, "Schedule", () => {showPage("schedules"); scheduleEditor({type: "custom", id: item.id});});
            button(row, "Delete", async () => {if (!confirm(`Delete ${item.name}?`)) return; await api(`/api/custom-scenarios/${item.id}`, "DELETE"); await refresh();});
        });
    }
    async function exportScenario(id) {
        // A native JSON download uses the server's validated document/filename.
        const response = await fetch(`/api/custom-scenarios/${encodeURIComponent(id)}/export`);
        if (!response.ok) {const result = await response.json(); throw new Error(result.message || "Scenario export failed.");}
        const url = URL.createObjectURL(await response.blob());
        const link = document.createElement("a"); link.href = url;
        link.download = response.headers.get("Content-Disposition")?.match(/filename="([^"]+)"/)?.[1] || "mrnobody-scenario.json";
        link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    function scheduleEditor(initial, existing) {
        editingSchedule = existing || null;
        const parent = byId("scheduleEditor"); parent.replaceChildren();
        node("h2", existing ? "Edit schedule" : "Schedule an execution", parent);
        const spec = copy(initial || {type: "campaign", id: scenarios.find(s => !s.custom && !s.preset)?.id || "full-incident", profile: {mode: "normal", duration: 0}});
        const entries = [...scenarios.filter(s => !s.preset).map(s => ({value: `${s.custom ? "custom" : "campaign"}:${s.id}`, label: `${s.custom ? "Custom" : "Campaign"} · ${s.name}`})), ...capabilities.filter(c => c.standalone).map(c => ({value: `phase:${c.id}`, label: `Attack Technique P${c.id} · ${c.name}`}))];
        field(parent, "Execution", `${spec.type}:${spec.id}`, value => {const [type, id] = value.split(":"); scheduleEditor({type, id, profile: {mode: "normal", duration: 0}}, existing);}, entries);
        if (spec.type !== "custom") {
            spec.profile ||= {mode: "normal", duration: 0};
            profileForm(parent, spec.profile, () => scheduleEditor(spec, existing), spec.type === "phase" ? ["normal", "slow", "custom"] : spec.id === "full-incident" ? ["normal", "slow"] : ["normal"]);
        } else node("p", "Uses the profile saved in the custom scenario.", parent);
        let refreshCredentials = () => {};
        if (spec.type === "phase") {
            spec.target_mode = spec.id === "01" ? (spec.target_mode || "auto") : "fixed";
            if (spec.id === "01") field(parent, "Targets", spec.target_mode, value => {spec.target_mode = value; spec.parameters = {}; scheduleEditor(spec, existing);}, [{value: "auto", label: "Auto Discovery"}, {value: "fixed", label: "Fixed subnets"}]);
            const phase = {id: spec.id, parameters: spec.parameters ||= {}, timing: spec.timing ||= {}};
            parameterForm(parent, phase, spec.target_mode, false, false, () => refreshCredentials()); timingForm(parent, phase, spec.profile);
        }
        if (spec.type === "campaign" && spec.id === "full-incident") {
            field(parent, "P10 Custom Remote Command", spec.powershell_enabled ? "1" : "0", value => {spec.powershell_enabled = value === "1"; scheduleEditor(spec, existing);}, [{value:"0",label:"Disabled"},{value:"1",label:"Enabled"}]);
        }
        const when = {mode: existing?.interval ? "recurring" : "once", at: existing ? localDate(existing.next_run || existing.at) : "", interval: existing?.interval || 86400};
        field(parent, "Run Once or Recurring", when.mode, v => {when.mode = v;}, [{value: "once", label: "Run Once"}, {value: "recurring", label: "Recurring"}]);
        field(parent, "Start date/time (browser timezone)", when.at, v => {when.at = v;}).type = "datetime-local";
        recurrenceForm(parent, when);
        node("p", `Timezone: ${Intl.DateTimeFormat().resolvedOptions().timeZone}. Repeat interval is used for Recurring only.`, parent, "muted");
        node("p", "Scheduled P08 requires service-side NORDIC_WORDLIST_FILE and NORDIC_WORDLIST_USERS; configure service credentials for unattended runs. Uploaded wordlists are execution-only.", parent, "muted");
        const credentialPanel = node("div", undefined, parent);
        let read;
        refreshCredentials = () => {credentialPanel.replaceChildren(); read = credentials(credentialPanel, spec);};
        refreshCredentials();
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
            node("h3", `${{phase:"Standalone Attack Technique",campaign:"Built-in scenario",custom:"Custom scenario"}[e.type] || e.type} · ${scenario?.name || capabilities.find(c => c.id === e.id)?.name || e.id}`, row);
            node("p", `${item.enabled ? "Enabled" : "Disabled"} · Next: ${item.enabled ? new Date(item.next_run).toLocaleString() : "—"} · ${executionProfile.mode} ${executionProfile.duration ? durationText(executionProfile.duration) : ""} · ${item.interval ? "Every " + intervalText(item.interval) : "Run Once"}`, row);
            node("p", `Planned start: ${new Date(item.at).toLocaleString()} · Source: ${e.id}`, row, "muted");
            node("p", `Last dispatch: ${item.last_status} · Temporary credentials: ${item.credentials_ready ? "available" : "not supplied"}`, row, "muted");
            button(row, "Run Now", async () => {message((await api(`/api/schedules/${item.id}/run`, "POST", {})).status); await refresh();});
            button(row, "Edit / supply credentials", () => scheduleEditor(e, item));
            button(row, item.enabled ? "Disable" : "Enable", async () => {await api(`/api/schedules/${item.id}/${item.enabled ? "disable" : "enable"}`, "POST", {}); await refresh();});
            button(row, "Delete", async () => {if (!confirm("Delete this schedule?")) return; await api(`/api/schedules/${item.id}`, "DELETE"); await refresh();});
        });
    }
    async function refresh() {
        const [caps, all, saved, planned] = await Promise.all([api("/api/planning/capabilities"), api("/api/scenarios"), api("/api/custom-scenarios"), api("/api/schedules")]);
        capabilities = caps.phases; schemaVersion = caps.version || 1; maxScenarioBytes = caps.max_scenario_bytes || 128 * 1024;
        scenarios = all.scenarios; custom = saved.scenarios; readiness = saved.readiness || {}; schedules = planned.schedules;
        library(); scheduleTable();
        if (typeof loadScenarios === "function") await loadScenarios();
        window.MrnUI?.refreshDashboard(true);
    }
    document.addEventListener("DOMContentLoaded", () => {
        byId("newCustomScenario").addEventListener("click", () => newDraft());
        document.querySelectorAll('[data-page="schedules"], [data-page="scenarios"]').forEach(b => b.addEventListener("click", () => refresh().catch(e => message(e.message))));
        refresh().catch(error => message(error.message));
    });
    // Existing GUI hooks and DOM-based regression tests use the same builder.
    async function runCustom(id) {
        if (!custom.some(s => s.id === id)) await refresh();
        const saved = custom.find(s => s.id === id);
        if (!saved) throw new Error("Custom scenario not found");
        newDraft(saved); step = 0; while (step < 6 && !stepError(step)) step++; renderBuilder();
    }
    async function openPreset(id, run = false) {
        if (!capabilities.length) await refresh();
        const value = await api(`/api/scenario-presets/${encodeURIComponent(id)}`);
        delete value.id;
        newDraft(value);
        if (run) {while (step < 6 && !stepError(step)) step++; renderBuilder();}
    }
    window.MrnPlanning = {newDraft, refresh, localDate, runCustom, openPreset};
})();
