'use strict';
(() => {
    const byId = id => document.getElementById(id);
    const form = byId('validationForm'), button = byId('validationRun'), output = byId('validationResult');
    const message = byId('validationMessage'), download = byId('validationDownload');
    let generation = 0, controller = null, summary = null;
    const labels = {correlated_alert:'Correlated imported alert', candidate_alert:'Candidate alert (not confirmed attribution)',
        correlated_telemetry:'Correlated telemetry (not an alert)', candidate_telemetry:'Candidate telemetry (not an alert)', unmatched:'Unmatched'};
    function node(parent, tag, text, className) {
        const item = document.createElement(tag); if (text !== undefined) item.textContent = text;
        if (className) item.className = className; parent.append(item); return item;
    }
    function invalidate() {
        generation++; summary = null; output.replaceChildren(); download.disabled = true;
        if (controller) controller.abort(); controller = null; button.disabled = false;
    }
    function techniques(parent, title, ids) {
        node(parent, 'p', title);
        for (const id of ids || []) {
            if (!/^T[0-9]{4}(?:\.[0-9]{3})?$/.test(id)) continue;
            const link = node(parent, 'a', id + ' ');
            link.href = 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';
            link.target = '_blank'; link.rel = 'noopener noreferrer';
        }
        if (!ids?.length) node(parent, 'p', 'None supplied.');
    }
    async function json(url, options = {}) {
        const result = await fetch(url, {credentials:'same-origin', cache:'no-store', redirect:'error', ...options});
        let body; try { body = await result.json(); } catch { throw new Error('Invalid server response. No verdict produced.'); }
        if (!result.ok) throw new Error(result.status === 401 ? 'Administrator login expired; log in at /master/admin.'
            : result.status === 429 ? 'Preview limit reached. Wait at least one minute.' : body.message || 'Reference unavailable; no verdict produced.');
        return body;
    }
    function render(result) {
        output.replaceChildren();
        const top = node(output, 'article', undefined, 'report-artifact');
        node(top, 'h2', 'Imported evidence preview — coverage unknown');
        node(top, 'p', 'Agent: ' + result.agent_id + ' · Campaign: ' + result.campaign_id);
        node(top, 'p', result.verdict === 'imported_correlated_alerts' ? 'Correlated alerts exist in the imported slice. Source authenticity and rule quality still require review.'
            : 'No unambiguously correlated alert in the supplied slice. This is not a “not detected” verdict.');
        for (const key of ['correlated_alert','candidate_alert','correlated_telemetry','candidate_telemetry','unmatched','ignored','duplicates','parsed']) {
            node(top, 'p', (labels[key] || key) + ': ' + result.counts[key]);
        }
        node(top, 'p', 'Ground Truth report: ' + result.reference.report_status + '. Fixed Master P11 jobs do not create normal campaign reports.');
        if (result.reference.report_sha256) node(top, 'p', 'Cached report SHA256: ' + result.reference.report_sha256);
        if (result.reference.receiver_page_truncated || result.reference.ground_truth_events_truncated || result.rows_truncated)
            node(top, 'p', 'Bounded output/reference: some earlier receipts, report events or display rows are outside this preview. Counts cover parsed records, not sensor coverage.');
        for (const source of result.sources) node(top, 'p', source.kind + ' source SHA256: ' + source.sha256 + ' · ' + source.bytes + ' bytes');
        for (const limitation of result.limitations) node(top, 'p', limitation);
        node(output, 'h2', 'Verified Receiver reference — receipt is not detection');
        if (!result.receipts.length) node(output, 'p', 'No verified P06/P11 receipt in this bounded reference. Imported records cannot establish detection validation without a reference.');
        for (const receipt of result.receipts) {
            const card = node(output, 'article', undefined, 'report-artifact');
            node(card, 'h3', receipt.phase + ' · Receiver event ' + receipt.id);
            node(card, 'p', 'Master received: ' + new Date(receipt.received_at * 1000).toISOString());
            if (receipt.sequence) node(card, 'p', 'Beacon sequence: ' + receipt.sequence);
            if (receipt.sha256) node(card, 'p', 'Verified fixture SHA256: ' + receipt.sha256);
            node(card, 'p', 'Cached report ACK reference matches: ' + (receipt.ground_truth_linked ? 'yes' : 'unavailable or no exact link'));
            techniques(card, 'Exercise activity reference mapping — not detected coverage', receipt.reference_techniques);
            techniques(card, 'Phase metadata — may describe other persistence actions', receipt.phase_metadata_techniques);
            for (const [key, count] of Object.entries(receipt.sensor_evidence)) node(card, 'p', labels[key] + ': ' + count);
        }
        node(output, 'h2', 'Allowlisted imported record metadata (first 200)');
        for (const row of result.rows) {
            const card = node(output, 'article', undefined, 'report-artifact');
            node(card, 'h3', (labels[row.classification] || 'Unmatched') + ' · ' + row.kind + ' line ' + row.line);
            node(card, 'p', row.timestamp + ' · rule/signature ' + (row.rule_id || 'none'));
            node(card, 'p', 'Basis: ' + row.basis.join(', ') + ' · Receiver IDs: ' + (row.receiver_event_ids.join(', ') || 'none')
                + ' · total possible references: ' + row.receiver_match_count);
            techniques(card, 'Imported rule MITRE IDs — unverified rule metadata', row.rule_techniques);
            node(card, 'p', 'Record SHA256: ' + row.sha256);
            if (row.flow_id) node(card, 'p', 'EVE flow ID (reference only): ' + row.flow_id);
        }
    }
    form.addEventListener('input', invalidate);
    form.addEventListener('change', invalidate);
    byId('validationClear').addEventListener('click', () => {
        invalidate(); byId('validationWazuh').value = ''; byId('validationSuricata').value = '';
        message.textContent = 'Imported files and preview cleared. No server data was saved.';
    });
    form.addEventListener('submit', async event => {
        event.preventDefault(); invalidate(); const version = generation;
        controller = new AbortController(); const signal = controller.signal;
        button.disabled = true; message.textContent = 'Comparing imported evidence…';
        try {
            const files = [['wazuh',byId('validationWazuh').files[0]],['suricata',byId('validationSuricata').files[0]]].filter(pair => pair[1]);
            if (!files.length) throw new Error('Choose at least one filtered NDJSON slice.');
            if (files.reduce((sum, pair) => sum + pair[1].size, 0) > 512 * 1024) throw new Error('Combined files exceed 512 KiB. Export a smaller slice.');
            const sources = await Promise.all(files.map(async ([kind,file]) => ({kind,
                content:new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer())})));
            const data = {agent_id:byId('validationAgent').value, campaign_id:byId('validationCampaign').value,
                window_seconds:Number(byId('validationWindow').value), wazuh_agent_id:byId('validationWazuhId').value,
                observed_source_ip:byId('validationSource').value, observed_destination_ip:byId('validationDestination').value, sources};
            const body = JSON.stringify(data);
            if (new TextEncoder().encode(body).length > 1024 * 1024) throw new Error('Encoded request exceeds 1 MiB. Use a smaller export.');
            const session = await json('/api/master/admin/session', {signal});
            if (!session.authenticated || typeof session.csrf !== 'string') throw new Error('Administrator login required.');
            const result = await json('/api/master/admin/validation', {method:'POST',signal,
                headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf},body});
            if (version !== generation) return;
            render(result); summary = result; download.disabled = false;
            message.textContent = 'Preview ready. Imported correlation is not authenticated SIEM proof; coverage remains unknown.';
        } catch (error) {
            if (version === generation) { output.replaceChildren(); message.textContent = error.message; }
        } finally { if (version === generation) {controller = null; button.disabled = false;} }
    });
    download.addEventListener('click', () => {
        if (!summary) return;
        const url = URL.createObjectURL(new Blob([JSON.stringify(summary,null,2)],{type:'application/json'}));
        const link = document.createElement('a'); link.href = url; link.download = 'detection-validation.json'; link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    const params = new URLSearchParams(location.search);
    byId('validationCampaign').value = params.get('campaign_id') || '';
    json('/api/master/agents').then(data => {
        const select = byId('validationAgent'); select.replaceChildren(); const blank = node(select,'option','Select one Agent'); blank.value = '';
        for (const agent of data.agents || []) {
            if (!['online','offline'].includes(agent.status)) continue;
            const item = node(select,'option', (agent.name || agent.agent_id) + ' · ' + agent.agent_id + ' · ' + agent.status);
            item.value = agent.agent_id;
        }
        if (Array.from(select.options).some(option => option.value === params.get('agent_id'))) select.value = params.get('agent_id');
    }).catch(error => {message.textContent = error.message; button.disabled = true;});
})();
