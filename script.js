/* Cinerarius Top Hair — interactions */
(function () {
  "use strict";

  // Current year in footer
  var yearEl = document.getElementById("year");
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  // Header background on scroll
  var header = document.querySelector(".site-header");
  function onScroll() {
    if (window.scrollY > 20) header.classList.add("scrolled");
    else header.classList.remove("scrolled");
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  // Mobile nav toggle
  var toggle = document.getElementById("navToggle");
  var nav = document.getElementById("mainNav");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      toggle.classList.toggle("open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    nav.addEventListener("click", function (e) {
      if (e.target.tagName === "A") {
        nav.classList.remove("open");
        toggle.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  // Reveal on scroll
  var reveals = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in");
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" });
    reveals.forEach(function (el) { io.observe(el); });
  } else {
    reveals.forEach(function (el) { el.classList.add("in"); });
  }

  // Gallery lightbox
  var grid = document.getElementById("galleryGrid");
  var lb = document.getElementById("lightbox");
  if (grid && lb) {
    var lbImg = document.getElementById("lbImg");
    var imgs = Array.prototype.slice.call(grid.querySelectorAll("img"));
    var current = 0;

    function show(i) {
      current = (i + imgs.length) % imgs.length;
      var src = imgs[current].getAttribute("src");
      lbImg.setAttribute("src", src);
      lbImg.setAttribute("alt", imgs[current].getAttribute("alt") || "");
    }
    function open(i) {
      show(i);
      lb.classList.add("open");
      lb.setAttribute("aria-hidden", "false");
      document.body.style.overflow = "hidden";
    }
    function close() {
      lb.classList.remove("open");
      lb.setAttribute("aria-hidden", "true");
      document.body.style.overflow = "";
    }

    grid.addEventListener("click", function (e) {
      var btn = e.target.closest(".gallery-item");
      if (!btn) return;
      var item = btn.querySelector("img");
      open(imgs.indexOf(item));
    });

    // Expand / collapse gallery (mostra solo alcune foto, poi tutte)
    var moreBtn = document.getElementById("galleryMore");
    if (moreBtn) {
      var LIMIT = 8;
      if (imgs.length > LIMIT) {
        grid.classList.add("collapsed");
        moreBtn.hidden = false;
        moreBtn.addEventListener("click", function () {
          var collapsed = grid.classList.toggle("collapsed");
          moreBtn.setAttribute("aria-expanded", collapsed ? "false" : "true");
          moreBtn.textContent = collapsed ? "Mostra tutte le foto" : "Mostra meno";
          if (collapsed) grid.scrollIntoView({ behavior: "smooth", block: "start" });
        });
      }
    }

    document.getElementById("lbClose").addEventListener("click", close);
    document.getElementById("lbNext").addEventListener("click", function () { show(current + 1); });
    document.getElementById("lbPrev").addEventListener("click", function () { show(current - 1); });
    lb.addEventListener("click", function (e) {
      if (e.target === lb) close();
    });
    document.addEventListener("keydown", function (e) {
      if (!lb.classList.contains("open")) return;
      if (e.key === "Escape") close();
      else if (e.key === "ArrowRight") show(current + 1);
      else if (e.key === "ArrowLeft") show(current - 1);
    });
  }
})();
