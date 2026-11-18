'use strict';
(() => {
    const logout = document.getElementById('labLogout'), message = document.getElementById('labMessage');
    document.getElementById('labCommand').textContent = 'sudo mrnobody lab-open ' + location.origin;
    let handoff = new URLSearchParams(location.hash.slice(1)).get('handoff');
    if (location.hash) history.replaceState(null, '', location.pathname);
    let csrf = '', busy = false, pending = null;
    async function session(method = 'GET', ticket) {
        if (busy) return;
        busy = true; logout.disabled = true;
        try {
            const result = await fetch('/api/master/admin/session', {
                method, credentials:'same-origin', cache:'no-store', redirect:'error',
                headers:method === 'GET' ? {} : {'Content-Type':'application/json', 'X-CSRF-Token':csrf},
                ...(method === 'GET' ? {} : {body:JSON.stringify(method === 'POST' ? {handoff:ticket} : {})})
            });
            const body = await result.json();
            if (!result.ok) throw new Error(body.message || 'Access unavailable. Generate a new local link.');
            csrf = body.csrf || '';
            const authorized = body.web_job_control === true;
            logout.hidden = !authorized;
            message.textContent = authorized ? 'Changes authorized for this VM for eight hours. Return to the dashboard.'
                : 'Read-only access. Open the one-time link generated locally on this VM.';
        } catch (error) { message.textContent = error.message; }
        finally {
            busy = false; logout.disabled = false;
            if (pending) { const ticket = pending; pending = null; session('POST', ticket); }
        }
    }
    window.addEventListener('hashchange', () => {
        const ticket = new URLSearchParams(location.hash.slice(1)).get('handoff');
        if (location.hash) history.replaceState(null, '', location.pathname);
        if (ticket) { if (busy) pending = ticket; else session('POST', ticket); }
    });
    logout.addEventListener('click', () => session('DELETE'));
    if (handoff) { session('POST', handoff); handoff = null; }
    else session();
})();
