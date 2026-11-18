'use strict';
(() => {
    const form = document.getElementById('labLogin'), key = document.getElementById('labKey');
    const logout = document.getElementById('labLogout'), message = document.getElementById('labMessage');
    let csrf = '', busy = false;
    async function session(method = 'GET', credential) {
        if (busy) return;
        busy = true;
        form.querySelector('button').disabled = logout.disabled = true;
        key.value = '';
        try {
            const result = await fetch('/api/master/admin/session', {
                method, credentials:'same-origin', cache:'no-store', redirect:'error',
                headers:method === 'GET' ? {} : {'Content-Type':'application/json', 'X-CSRF-Token':csrf},
                ...(method === 'GET' ? {} : {body:JSON.stringify(method === 'POST' ? {credential} : {})})
            });
            const body = await result.json();
            if (!result.ok) throw new Error(body.message || 'Access unavailable.');
            csrf = body.csrf || '';
            const authorized = body.web_job_control === true;
            form.hidden = authorized; logout.hidden = !authorized;
            message.textContent = authorized ? 'Changes authorized. Return to the dashboard.' : 'Read-only access. Enter the control key to authorize changes.';
        } catch (error) { message.textContent = error.message; }
        finally { busy = false; form.querySelector('button').disabled = logout.disabled = false; }
    }
    form.addEventListener('submit', event => { event.preventDefault(); session('POST', key.value); });
    logout.addEventListener('click', () => session('DELETE'));
    session();
})();
