(function () {
  "use strict";

  var root = document.documentElement;
  var STORAGE_KEY = "drishtisec-theme";

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    var btn = document.getElementById("theme-toggle");
    if (btn) {
      btn.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
    }
  }

  function initTheme() {
    var saved = null;
    try {
      saved = localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      /* localStorage unavailable; fall back to default */
    }
    applyTheme(saved === "light" ? "light" : "dark");
  }

  function toggleTheme() {
    var current = root.getAttribute("data-theme") === "light" ? "light" : "dark";
    var next = current === "light" ? "dark" : "light";
    applyTheme(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch (e) {
      /* ignore persistence failure */
    }
  }

  function initSidebar() {
    var sidebar = document.getElementById("sidebar");
    var backdrop = document.getElementById("sidebar-backdrop");
    var toggleBtn = document.getElementById("sidebar-toggle");
    if (!sidebar || !toggleBtn) return;

    function open() {
      sidebar.classList.add("open");
      if (backdrop) backdrop.classList.add("open");
    }
    function close() {
      sidebar.classList.remove("open");
      if (backdrop) backdrop.classList.remove("open");
    }

    toggleBtn.addEventListener("click", function () {
      sidebar.classList.contains("open") ? close() : open();
    });
    if (backdrop) backdrop.addEventListener("click", close);
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTheme();
    initSidebar();
    var themeBtn = document.getElementById("theme-toggle");
    if (themeBtn) themeBtn.addEventListener("click", toggleTheme);
  });

  /* Apply theme immediately (before DOMContentLoaded) to avoid a flash
     of the wrong theme on navigation. */
  initTheme();
})();
