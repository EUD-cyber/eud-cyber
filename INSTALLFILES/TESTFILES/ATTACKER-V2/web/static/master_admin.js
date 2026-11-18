'use strict';
(() => {
    const byId = id => document.getElementById(id);
    const form = byId('adminLogin'), input = byId('adminCredential'), logout = byId('adminLogout');
    const message = byId('adminMessage'), control = byId('jobControl'), select = byId('jobAgent');
    const start = byId('jobStart'), refresh = byId('jobRefresh'), list = byId('jobList'), info = byId('jobMessage');
    const terminal = new Set(['succeeded', 'failed', 'stopped']);
    const pendingKey = 'mrn-fixed-p11-pending'; // Request identity only, never an administrator/Agent token.
    let csrf = null, canControl = true, busy = false, loading = false, working = false, agents = [], jobs = [], pending = null;
    try {
        const value = JSON.parse(sessionStorage.getItem(pendingKey));
        if (value && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value.agent_id)
                && /^web-[a-f0-9-]{36}$/.test(value.request_key)) pending = value;
    } catch { /* A new request remains in memory if browser storage is unavailable. */ }
    function savePending(value) {
        pending = value;
        try { if (value) sessionStorage.setItem(pendingKey, JSON.stringify(value)); else sessionStorage.removeItem(pendingKey); } catch {}
    }
    function signedOut(text) {
        csrf = null; control.hidden = true; form.hidden = false; logout.hidden = true;
        list.replaceChildren(); agents = []; jobs = []; message.textContent = text;
    }
    function buttons() {
        const online = agents.some(agent => agent.agent_id === select.value && agent.status === 'online');
        start.disabled = !canControl || !csrf || working || loading || (!pending && (!online || jobs.some(job => !terminal.has(job.status))));
        start.textContent = pending ? 'Retry the same start request' : 'Start fixed P11 job';
        select.disabled = working || Boolean(pending);
        refresh.disabled = working || loading;
    }
    async function api(url, options = {}) {
        const result = await fetch(url, {credentials:'same-origin', cache:'no-store', redirect:'error', ...options,
            headers:{...(options.body ? {'Content-Type':'application/json', 'X-CSRF-Token':csrf || ''} : {}), ...(options.headers || {})}});
        let body;
        try { body = await result.json(); } catch { throw new Error('Invalid server response. Refresh or retry the same request.'); }
        if (!result.ok) {
            if (result.status === 401) signedOut('Session expired. Log in again to continue.');
            if (result.status === 503) signedOut('Service or administrator credential unavailable. Resolve locally and log in again.');
            const error = new Error(result.status === 429 ? 'Request limit reached; wait at least one minute.' : body.message || 'Request failed.');
            error.status = result.status; throw error;
        }
        return body;
    }
    function node(parent, tag, text, className) {
        const item = document.createElement(tag); if (text !== undefined) item.textContent = text;
        if (className) item.className = className; parent.append(item); return item;
    }
    function renderJobs() {
        list.replaceChildren();
        if (!jobs.length) node(list, 'p', 'No fixed P11 jobs recorded.');
        for (const job of jobs) {
            const card = node(list, 'article', undefined, 'report-artifact');
            card.dataset.jobId = job.job_id;
            node(card, 'h3', job.job_id);
            node(card, 'p', 'Agent: ' + job.agent_id);
            node(card, 'p', 'Status: ' + job.status + (job.stop_requested ? ' · stop requested' : ''));
            node(card, 'p', 'Deadline: ' + new Date(job.deadline * 1000).toLocaleString());
            if (job.reason) node(card, 'p', 'Reason: ' + job.reason);
            const link = node(card, 'a', 'View Receiver events for this job');
            link.href = '/api/master/receiver/events?' + new URLSearchParams({agent_id:job.agent_id, campaign_id:job.job_id});
            link.target = '_blank'; link.rel = 'noopener noreferrer';
            const validation = node(card, 'a', 'Compare imported sensor evidence for this job');
            validation.href = '/master/validation?' + new URLSearchParams({agent_id:job.agent_id, campaign_id:job.job_id});
            const stop = node(card, 'button', 'Stop this job', 'button button-stop'); stop.type = 'button';
            stop.disabled = !canControl || working || terminal.has(job.status) || job.stop_requested;
            stop.addEventListener('click', async () => {
                if (!canControl || working || !confirm('Stop the fixed P11 job ' + job.job_id + ' on ' + job.agent_id + '?')) return;
                working = true; buttons(); renderJobs();
                try {
                    const body = await api('/api/master/admin/jobs/' + encodeURIComponent(job.job_id) + '/stop',
                        {method:'POST', body:JSON.stringify({confirm_job_id:job.job_id})});
                    info.textContent = body.job.status === 'stopped' ? 'Job stopped. Verify received traffic in Receiver.'
                        : 'Stop requested. Waiting for the Agent or deadline; check Receiver for actual traffic.';
                } catch (error) { info.textContent = error.message; }
                finally { working = false; await load(); }
            });
        }
    }
    async function load() {
        if (!csrf || loading || working) return;
        loading = true; buttons();
        try {
            const [agentData, jobData] = await Promise.all([api('/api/master/agents'), api('/api/master/admin/jobs')]);
            if (!csrf) return;
            if (!Array.isArray(agentData.agents) || !Array.isArray(jobData.jobs)) throw new Error('Invalid inventory response.');
            agents = agentData.agents; jobs = jobData.jobs;
            const selected = pending ? pending.agent_id : select.value;
            select.replaceChildren(); const empty = node(select, 'option', 'Select one online Agent'); empty.value = '';
            for (const agent of agents) {
                const item = node(select, 'option', (agent.name || agent.agent_id) + ' · ' + agent.agent_id + ' · ' + agent.status);
                item.value = agent.agent_id; item.disabled = agent.status !== 'online';
            }
            if (agents.some(agent => agent.agent_id === selected)) select.value = selected;
            if (pending) info.textContent = 'Unresolved start for ' + pending.agent_id + '. Retry uses the same request key and cannot create a second job.';
            renderJobs();
            byId('jobRefreshStatus').textContent = 'Refreshed ' + new Date().toLocaleTimeString() + ' · every 5 seconds while visible';
        } catch (error) {
            agents = []; jobs = []; select.replaceChildren(); list.replaceChildren();
            info.textContent = error.message + ' Inventory is unavailable; no start was sent.';
        } finally { loading = false; buttons(); }
    }
    async function session(method = 'GET', credential) {
        if (busy || working) return;
        busy = true; form.querySelector('button').disabled = true; logout.disabled = true; input.value = '';
        try {
            const body = await api('/api/master/admin/session', method === 'GET' ? {} :
                {method, body:JSON.stringify(method === 'POST' ? {credential} : {})});
            if (body.authenticated === true && typeof body.csrf === 'string') {
                canControl = body.web_job_control !== false;
                csrf = body.csrf; form.hidden = canControl; logout.hidden = !canControl; control.hidden = false;
                if (body.lab_mode === true) {
                    byId('adminAccessHint').textContent = 'Lab Mode works across subnets and NAT via IP or DNS. Enter this Master\'s control key to authorize changes. Retrieve it locally with sudo cat /etc/mrnobody/lab-control.key. Use HTTPS to protect credentials in transit.';
                    byId('jobWorkerHint').textContent = 'Lab Mode automatically enables the fixed P11 job worker on configured Slaves. Online still proves heartbeat contact only. A queued job expires after 180 seconds.';
                }
                message.textContent = body.lab_mode === true ? (canControl
                    ? 'Lab Mode: administrator authenticated for this origin. Only the fixed P11 job is remotely supported.'
                    : 'Lab Mode: read-only. Enter the Master control key to enable start, stop and other changes.')
                    : 'Administrator authenticated. Only the fixed P11 job is remotely supported.';
                await load();
            } else signedOut('Logged out.');
        } catch (error) { signedOut(error.status === 503 ? 'Administrator authentication is not configured or unavailable. Provision it locally on Master.' : error.message); }
        finally { busy = false; form.querySelector('button').disabled = false; logout.disabled = false; }
    }
    form.addEventListener('submit', event => { event.preventDefault(); session('POST', input.value); });
    logout.addEventListener('click', () => session('DELETE'));
    select.addEventListener('change', buttons);
    refresh.addEventListener('click', load);
    start.addEventListener('click', async () => {
        if (start.disabled || working) return;
        working = true; buttons(); renderJobs();
        const firstAttempt = !pending;
        if (!pending) savePending({agent_id:select.value, request_key:'web-' + Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2,'0')).join('')
            .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5')});
        try {
            const body = await api('/api/master/admin/jobs', {method:'POST', body:JSON.stringify(pending)});
            if (!body.job || typeof body.job.job_id !== 'string') throw new Error('Start response was not verified; retry the same request.');
            savePending(null); info.textContent = 'Job ' + body.job.job_id + ': ' + body.job.status + '. Waiting for Agent polling.';
        } catch (error) {
            // A rejected retry says nothing about an earlier ambiguous attempt.
            if (firstAttempt && [400, 403, 409].includes(error.status)) savePending(null);
            info.textContent = error.message;
        } finally { working = false; await load(); }
    });
    document.addEventListener('visibilitychange', () => { if (!document.hidden) load(); });
    setInterval(() => { if (!document.hidden) load(); }, 5000);
    session();
})();
