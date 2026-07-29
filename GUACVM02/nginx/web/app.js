(() => {
  "use strict";

  const sessions = Array.isArray(window.CYBERLAB_SESSIONS) ? window.CYBERLAB_SESSIONS : [];
  const grid = document.getElementById("sessionGrid");
  const template = document.getElementById("sessionTemplate");
  const searchInput = document.getElementById("searchInput");
  const categoryFilters = document.getElementById("categoryFilters");
  const allCount = document.getElementById("allCount");
  const onlineCount = document.getElementById("onlineCount");
  const resultText = document.getElementById("resultText");
  const emptyState = document.getElementById("emptyState");
  const dialog = document.getElementById("connectionDialog");
  const dialogContent = document.getElementById("dialogContent");
  let activeCategory = "Alle";

  const esc = (value) => String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

  const protocolClass = (type) => `protocol protocol-${String(type).toLowerCase()}`;

  function categories() {
    return [...new Set(sessions.map(s => s.category).filter(Boolean))]
      .sort((a,b) => a.localeCompare(b, "da"));
  }

  function renderFilters() {
    allCount.textContent = sessions.length;
    onlineCount.textContent = sessions.length;
    categories().forEach(category => {
      const button = document.createElement("button");
      button.className = "filter";
      button.dataset.category = category;
      button.innerHTML = `<span>${esc(category)}</span><strong>${sessions.filter(s => s.category === category).length}</strong>`;
      categoryFilters.appendChild(button);
    });
  }

  function filteredSessions() {
    const query = searchInput.value.trim().toLocaleLowerCase("da");
    return sessions.filter(session => {
      const categoryMatch = activeCategory === "Alle" || session.category === activeCategory;
      const searchable = [session.name, session.description, session.address, session.category,
        ...(session.connections || []).map(c => `${c.type} ${c.label}`)]
        .join(" ").toLocaleLowerCase("da");
      return categoryMatch && (!query || searchable.includes(query));
    });
  }

  function renderCards() {
    const visible = filteredSessions();
    grid.replaceChildren();

    visible.forEach(session => {
      const fragment = template.content.cloneNode(true);
      fragment.querySelector(".system-icon").textContent = session.icon || session.name.slice(0,3).toUpperCase();
      fragment.querySelector("h2").textContent = session.name;
      fragment.querySelector(".system-description").textContent = session.description || "";
      fragment.querySelector(".system-address").textContent = session.address || "";

      const protocols = fragment.querySelector(".protocols");
      (session.connections || []).forEach(connection => {
        const badge = document.createElement("span");
        badge.className = protocolClass(connection.type);
        badge.textContent = connection.type;
        protocols.appendChild(badge);
      });

      fragment.querySelector(".card-button").addEventListener("click", () => openDialog(session));
      grid.appendChild(fragment);
    });

    resultText.textContent = `${visible.length} af ${sessions.length} systemer vises`;
    emptyState.hidden = visible.length !== 0;
  }

  function openDialog(session) {
    const buttons = (session.connections || []).map(connection => {
      const target = connection.newTab ? ' target="_blank" rel="noopener noreferrer"' : "";
      const note = connection.note ? `<small>${esc(connection.note)}</small>` : "";
      return `<a class="connection-option" href="${esc(connection.url)}"${target}>
        <span class="${protocolClass(connection.type)}">${esc(connection.type)}</span>
        <span class="connection-label"><strong>${esc(connection.label)}</strong>${note}</span>
        <span class="option-arrow">→</span>
      </a>`;
    }).join("");

    dialogContent.innerHTML = `<div class="dialog-heading">
      <span class="system-icon large">${esc(session.icon || session.name.slice(0,3).toUpperCase())}</span>
      <div><p class="eyebrow">${esc(session.category || "System")}</p>
      <h2>${esc(session.name)}</h2><p>${esc(session.description || "")}</p>
      <code>${esc(session.address || "")}</code></div></div>
      <div class="connection-list">${buttons || "<p>Ingen forbindelser oprettet.</p>"}</div>`;
    dialog.showModal();
  }

  document.addEventListener("click", event => {
    const filter = event.target.closest(".filter");
    if (!filter) return;
    activeCategory = filter.dataset.category;
    document.querySelectorAll(".filter").forEach(b => b.classList.toggle("active", b === filter));
    renderCards();
  });

  searchInput.addEventListener("input", renderCards);
  dialog.addEventListener("click", event => { if (event.target === dialog) dialog.close(); });

  renderFilters();
  renderCards();
})();
