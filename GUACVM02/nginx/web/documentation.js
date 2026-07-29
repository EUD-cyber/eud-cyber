(() => {
  "use strict";

  const links = document.querySelectorAll(".docs-link");
  const pages = document.querySelectorAll(".doc-page");

  function showPage(pageId) {

    if (!document.getElementById(pageId)) {
      pageId = "overview";
    }

    links.forEach(link => {
      link.classList.toggle(
        "active",
        link.dataset.page === pageId
      );
    });

    pages.forEach(page => {
      page.classList.toggle(
        "active",
        page.id === pageId
      );
    });

    history.replaceState(null, "", `#${pageId}`);
  }

  links.forEach(link => {
    link.addEventListener("click", () => {
      showPage(link.dataset.page);
    });
  });

  showPage(location.hash.substring(1) || "overview");
})();
