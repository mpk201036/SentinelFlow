/*
 * SentinelFlow console - the only script any page loads.
 *
 * It does two things: shows a tooltip for elements carrying data-tip, and
 * gives form buttons a pending state. The CSP forbids inline script, so
 * behaviour lives here or nowhere. Every form works without it.
 *
 * Tooltip content comes from data attributes that may contain attacker-
 * controlled text (a hostname, a rule's observed value). It is therefore
 * written with textContent and createElement only - never innerHTML - so
 * "<img src=x onerror=...>" in an event field renders as those characters.
 *
 * Tooltips enhance, never gate: every value they show is also in a table view
 * or printed on the page. Keyboard focus shows the same content as hover.
 */
(function () {
  "use strict";

  var tip = null;
  var active = null;

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function fill(target) {
    while (tip.firstChild) tip.removeChild(tip.firstChild);

    var value = target.getAttribute("data-tip-value");
    var title = target.getAttribute("data-tip");
    var note = target.getAttribute("data-tip-note");
    var rows = target.getAttribute("data-tip-rows");

    // Values lead, labels follow: the reader already knows the series and
    // wants the number.
    if (value) tip.appendChild(el("div", "tip-value", value));
    if (title) tip.appendChild(el("div", "tip-title", title));
    if (rows) {
      rows.split(";").forEach(function (pair, index) {
        var parts = pair.split("|");
        var row = el("div", "tip-row");
        row.appendChild(el("span", "tip-line tip-line--" + index));
        row.appendChild(el("b", null, parts[1] || ""));
        row.appendChild(el("span", null, parts[0] || ""));
        tip.appendChild(row);
      });
    }
    if (note) tip.appendChild(el("div", "tip-note", note));
  }

  function place(x, y) {
    var pad = 14;
    var rect = tip.getBoundingClientRect();
    var left = x + pad;
    var top = y + pad;
    if (left + rect.width > window.innerWidth - 8) left = x - rect.width - pad;
    if (top + rect.height > window.innerHeight - 8) top = y - rect.height - pad;
    // CSSOM writes from an allowed script are permitted by the CSP; it is
    // style="" attributes in markup that the policy blocks.
    tip.style.left = Math.max(8, left) + "px";
    tip.style.top = Math.max(8, top) + "px";
  }

  function show(target, x, y) {
    if (active !== target) {
      active = target;
      fill(target);
    }
    tip.hidden = false;
    place(x, y);
  }

  function hide() {
    active = null;
    if (tip) tip.hidden = true;
  }

  function targetOf(event) {
    var node = event.target;
    return node && node.closest ? node.closest("[data-tip]") : null;
  }

  document.addEventListener("DOMContentLoaded", function () {
    tip = document.querySelector(".tip");
    if (!tip) return;

    document.addEventListener("pointermove", function (event) {
      var target = targetOf(event);
      if (target) show(target, event.clientX, event.clientY);
      else if (active) hide();
    });
    document.addEventListener("pointerleave", hide);

    document.addEventListener("focusin", function (event) {
      var target = targetOf(event);
      if (!target) return hide();
      var box = target.getBoundingClientRect();
      show(target, box.left + box.width / 2, box.bottom);
    });
    document.addEventListener("focusout", hide);
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") hide();
    });
    window.addEventListener("scroll", hide, { passive: true });
  });

  /*
   * Pending state for forms. A button with data-pending is disabled and
   * relabelled once its form is submitted, so a slow request (asking the
   * local model can take a minute) cannot be sent twice, and the analyst can
   * see it is in progress. The label comes from our own markup, set with
   * textContent.
   */
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (form.getAttribute("aria-busy") === "true") {
      event.preventDefault();
      return;
    }
    form.setAttribute("aria-busy", "true");
    var button = form.querySelector("button[data-pending]");
    if (!button) return;
    button.setAttribute("data-label", button.textContent);
    // Deferred so the submission is already under way when the button goes.
    window.setTimeout(function () {
      button.disabled = true;
      button.textContent = button.getAttribute("data-pending");
    }, 0);
  });

  // Coming back to a page from the history cache must not leave it frozen.
  window.addEventListener("pageshow", function () {
    var busy = document.querySelectorAll("form[aria-busy='true']");
    Array.prototype.forEach.call(busy, function (form) {
      form.removeAttribute("aria-busy");
      var button = form.querySelector("button[data-label]");
      if (button) {
        button.disabled = false;
        button.textContent = button.getAttribute("data-label");
      }
    });
  });
})();
