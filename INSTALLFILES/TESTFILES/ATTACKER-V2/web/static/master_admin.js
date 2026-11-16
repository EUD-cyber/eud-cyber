'use strict';
(() => {
    const form = document.getElementById('adminLogin');
    const input = document.getElementById('adminCredential');
    const logout = document.getElementById('adminLogout');
    const message = document.getElementById('adminMessage');
    let csrf = null;
    let busy = false;
    async function session(method = 'GET', credential) {
        if (busy) return;
        busy = true;
        form.querySelector('button').disabled = true;
        logout.disabled = true;
        // Credentials and CSRF tokens stay in memory; never URL/storage/markup.
        input.value = '';
        try {
            const options = {method, credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: {}};
            if (method !== 'GET') {
                options.headers['Content-Type'] = 'application/json';
                options.body = JSON.stringify(method === 'POST' ? {credential} : {});
                if (method === 'DELETE' && csrf) options.headers['X-CSRF-Token'] = csrf;
            }
            const result = await fetch('/api/master/admin/session', options);
            if (!result.ok) {
                csrf = null;
                form.hidden = false;
                logout.hidden = true;
                message.textContent = result.status === 503 ? 'Administrator authentication is not configured. Web job control remains blocked.'
                    : result.status === 429 ? 'Too many requests. Wait at least one minute.'
                    : 'No authenticated session. Use the separate root-provisioned administrator credential over HTTPS.';
                return;
            }
            const body = await result.json();
            const authenticated = body.authenticated === true && typeof body.csrf === 'string';
            csrf = authenticated ? body.csrf : null;
            form.hidden = authenticated;
            logout.hidden = !authenticated;
            message.textContent = authenticated ? 'Administrator authenticated. Web job control remains blocked pending deployment validation.'
                : 'Logged out. Web job control remains blocked.';
        } catch {
            csrf = null;
            form.hidden = false;
            logout.hidden = true;
            message.textContent = 'Session could not be verified. Web job control remains blocked.';
        } finally {
            busy = false;
            form.querySelector('button').disabled = false;
            logout.disabled = false;
        }
    }
    form.addEventListener('submit', event => {
        event.preventDefault();
        const credential = input.value;
        session('POST', credential);
    });
    logout.addEventListener('click', () => session('DELETE'));
    session();
})();
