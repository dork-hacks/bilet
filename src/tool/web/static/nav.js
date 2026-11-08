// Site menu button for narrow screens (#273). Without this script every link stays
// visible, so the menu never depends on JavaScript.
(function () {
  "use strict";
  var nav = document.querySelector(".site-nav");
  if (!nav) return;
  var button = nav.querySelector(".nav-toggle");
  var list = nav.querySelector("ul");
  var narrow = window.matchMedia("(max-width: 40rem)");

  function apply() {
    if (narrow.matches) {
      button.hidden = false;
      list.hidden = button.getAttribute("aria-expanded") !== "true";
    } else {
      button.hidden = true;
      list.hidden = false;
    }
  }

  button.addEventListener("click", function () {
    var open = button.getAttribute("aria-expanded") === "true";
    button.setAttribute("aria-expanded", open ? "false" : "true");
    apply();
    if (!open) {
      var first = list.querySelector("a");
      if (first) first.focus();
    }
  });
  nav.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && narrow.matches && !list.hidden) {
      button.setAttribute("aria-expanded", "false");
      apply();
      button.focus();
    }
  });
  if (narrow.addEventListener) narrow.addEventListener("change", apply);
  apply();
})();
