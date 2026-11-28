(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const form = $('connectionForm'), dialog = $('editConnection');
  const protocols = {rdp:3389, ssh:22, vnc:5900};
  let editing = null, pending = null, busy = false;
  async function api(path, options = {}) {
    const response = await fetch(path, {cache:'no-store', ...options});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Forbindelsen kunne ikke gemmes');
    return result;
  }
  function button(label, handler) {
    const b = document.createElement('button');
    b.type = 'button'; b.textContent = label; b.addEventListener('click', handler); return b;
  }
  async function load() {
    try {
      const data = await api('/api/vm-connections');
      $('labLabel').textContent = `Lab ${data.lab}`;
      $('connectionRows').replaceChildren();
      for (const row of data.connections) {
        const article = document.createElement('article'); article.className = 'vm-row';
        const info = document.createElement('div');
        const title = document.createElement('strong'); title.textContent = `${row.name} · ${row.label}`;
        const detail = document.createElement('p');
        detail.textContent = `${row.protocol.toUpperCase()} · ${row.host}${row.port ? ':'+row.port : ''} · ${row.visible ? 'Synlig' : 'Skjult'} · ${row.owned ? 'Administreret' : 'Eksisterende'}${row.missing ? ' · Mangler i Guacamole DB' : ''}`;
        const actions = document.createElement('div'); actions.className = 'vm-toolbar';
        actions.append(button('Rediger', () => edit(row)), button('Fjern', () => remove(row)));
        info.append(title, detail); article.append(info, actions); $('connectionRows').append(article);
      }
      $('connectionStatus').textContent = data.connections.length ? `${data.connections.length} forbindelser` : 'Ingen forbindelser. Tilføj den første ovenfor.';
    } catch (error) { $('connectionStatus').textContent = error.message; }
  }
  function edit(row = null) {
    editing = row; pending = null; form.reset();
    $('editHeading').textContent = row ? 'Rediger forbindelse' : 'Tilføj forbindelse';
    $('editError').textContent = '';
    form.elements.protocol.replaceChildren(...Object.keys(protocols).map(p => new Option(p.toUpperCase(),p)));
    const legacy = row && !protocols[row.protocol];
    if (legacy) form.elements.protocol.add(new Option(row.protocol.toUpperCase(),row.protocol));
    for (const field of ['name','label','protocol','host','port','username','domain','category','icon','description']) {
      if (row && row[field] !== undefined) form.elements[field].value = row[field];
    }
    form.elements.visible.checked = row ? row.visible : true;
    form.elements.protocol.disabled = !!row;
    for (const field of ['host','port','username','password','domain','clearPassword']) form.elements[field].disabled = !!legacy;
    $('editNote').textContent = legacy ? 'Eksisterende HTTP/HTTPS: kun portalvisning og navne kan ændres her. NAT ændres ikke.' :
      'Tomt password bevarer det gemte. Markér “Fjern gemt password” for at rydde det. Forbindelsen er ikke en kontrol af, om VM’en er installeret eller kører.';
    dialog.showModal();
  }
  function operation(method, key, body) {
    const serialized = JSON.stringify(body), signature = method + key + serialized;
    if (!pending || pending.signature !== signature) pending = {signature, id:crypto.randomUUID()};
    return api('/api/vm-connections/'+encodeURIComponent(key), {method,
      headers:{'Content-Type':'application/json','Idempotency-Key':pending.id}, body:serialized});
  }
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return;
    const body = {};
    for (const field of ['name','label','protocol','host','username','domain','category','icon','description']) body[field] = form.elements[field].value;
    body.port = Number(form.elements.port.value); body.visible = form.elements.visible.checked;
    if (editing) body.version = editing.version;
    if (form.elements.password.value) body.password = form.elements.password.value;
    if (form.elements.clearPassword.checked) body.password = '';
    if (editing && !protocols[editing.protocol]) {
      body.host = editing.host; body.port = editing.port || 443;
      delete body.username; delete body.domain; delete body.password;
    }
    if (!form.dataset.newKey || editing) form.dataset.newKey = editing ? editing.key : crypto.randomUUID();
    busy = true; $('saveConnection').disabled = true; $('cancelEdit').disabled = true;
    try {
      await operation('PUT', editing ? editing.key : form.dataset.newKey, body);
      pending = null; delete form.dataset.newKey; form.elements.password.value = ''; dialog.close(); await load();
    } catch (error) { $('editError').textContent = error.message; }
    finally { busy = false; $('saveConnection').disabled = false; $('cancelEdit').disabled = false; }
  });
  async function remove(row) {
    if (busy || !confirm(row.owned ? `Fjern ${row.label} fra portalen og slet den tilhørende Guacamole-forbindelse?` :
        `Fjern ${row.label} fra portalen? Den eksisterende Guacamole-forbindelse bevares.`)) return;
    busy = true;
    try { await operation('DELETE', row.key, {version:row.version}); pending = null; await load(); }
    catch (error) { $('connectionStatus').textContent = error.message; }
    finally { busy = false; }
  }
  form.elements.protocol.addEventListener('change', () => {form.elements.port.value = protocols[form.elements.protocol.value];});
  $('addConnection').addEventListener('click', () => {delete form.dataset.newKey; edit();});
  $('refreshConnections').addEventListener('click',load);
  $('cancelEdit').addEventListener('click', () => {form.elements.password.value=''; dialog.close();});
  dialog.addEventListener('cancel', event => {if (busy) event.preventDefault(); else form.elements.password.value='';});
  load();
})();
