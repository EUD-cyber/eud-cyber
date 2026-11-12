(() => {
  "use strict";

  const DEFAULT_PAGE = "overview";

  const links = Array.from(
    document.querySelectorAll(".docs-link[data-page]")
  );

  const pages = Array.from(
    document.querySelectorAll(".doc-page[id]")
  );

  function pageExists(pageId) {
    return pages.some(page => page.id === pageId);
  }

  function normalizePageId(pageId) {
    const cleanPageId = String(pageId || "")
      .trim()
      .replace(/^#/, "");

    return pageExists(cleanPageId)
      ? cleanPageId
      : DEFAULT_PAGE;
  }

  function showPage(pageId, updateHistory = true) {
    const activePageId = normalizePageId(pageId);

    links.forEach(link => {
      const isActive =
        link.dataset.page === activePageId;

      link.classList.toggle("active", isActive);

      link.setAttribute(
        "aria-current",
        isActive ? "page" : "false"
      );
    });

    pages.forEach(page => {
      const isActive =
        page.id === activePageId;

      page.classList.toggle("active", isActive);
      page.hidden = !isActive;
    });

    if (updateHistory) {
      history.pushState(
        { page: activePageId },
        "",
        `#${activePageId}`
      );
    }

    const activePage =
      document.getElementById(activePageId);

    activePage?.scrollTo?.({
      top: 0,
      behavior: "instant"
    });

    document.querySelector(".docs-content")?.scrollTo?.({
      top: 0,
      behavior: "instant"
    });
  }

  links.forEach(link => {
    link.addEventListener("click", event => {
      event.preventDefault();

      showPage(link.dataset.page);
    });
  });

  window.addEventListener("popstate", () => {
    showPage(
      window.location.hash.substring(1),
      false
    );
  });

  window.addEventListener("hashchange", () => {
    showPage(
      window.location.hash.substring(1),
      false
    );
  });

  const initialPage = normalizePageId(
    window.location.hash.substring(1)
  );

  showPage(initialPage, false);

  history.replaceState(
    { page: initialPage },
    "",
    `#${initialPage}`
  );
})();