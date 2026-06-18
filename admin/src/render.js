/* ============================================================
   Cinerarius — render condiviso dei contenuti del sito
   Usato dal Worker admin (per rigenerare index.html) e dai test.
   Riproduce ESATTAMENTE il markup statico esistente, così lo
   stile resta identico. ESM puro (niente dipendenze).
   ============================================================ */

export const MARKERS = {
  barbers:  "BARBERS",
  services: "SERVICES",
  gallery:  "GALLERY",
};

/* escape per contenuto testuale (mantiene gli apostrofi come nel sito) */
export function escText(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
/* escape per valori di attributo */
export function escAttr(s) {
  return escText(s).replace(/"/g, "&quot;");
}

/* ---------- Barbieri (sezione #barbers .team-grid) ---------- */
export function renderBarbers(list) {
  return (list || []).map(function (b) {
    return (
'        <article class="team-card reveal">\n' +
'          <img class="team-photo" src="' + escAttr(b.img) + '" alt="' + escAttr(b.alt || b.name) + '" loading="lazy" />\n' +
'          <h3>' + escText(b.name) + '</h3>\n' +
'          <p class="role">' + escText(b.role) + '</p>\n' +
'          <p class="spec">' + escText(b.spec) + '</p>\n' +
'        </article>'
    );
  }).join("\n");
}

/* ---------- Listino (sezione #servizi .price-list) ---------- */
function priceName(row) {
  var s = escText(row.name);
  if (row.em)  s += ' <em>' + escText(row.em) + '</em>';
  if (row.loc) s += ' <em class="p-loc">' + escText(row.loc) + '</em>';
  return s;
}
export function renderServices(groups) {
  return (groups || []).map(function (g) {
    var head = '        <h3 class="price-cat reveal">' + escText(g.cat) +
      (g.note ? ' <em>' + escText(g.note) + '</em>' : '') + '</h3>';
    var rows = (g.rows || []).map(function (r) {
      return '        <div class="price-row reveal"><span class="p-name">' + priceName(r) +
        '</span><span class="p-dots"></span><span class="p-dur">' + escText(r.dur) +
        '</span><span class="p-price">' + escText(r.price) + '</span></div>';
    }).join("\n");
    return head + "\n" + rows;
  }).join("\n\n");
}

/* ---------- Gallery (sezione #gallery .gallery-grid) ---------- */
export function renderGallery(items) {
  return (items || []).map(function (g) {
    return '        <button class="gallery-item reveal" type="button"><img src="' +
      escAttr(g.src) + '" alt="' + escAttr(g.alt) + '" loading="lazy" /></button>';
  }).join("\n");
}

/* ---------- Sostituzione di una regione tra i marker ---------- */
export function replaceRegion(htmlStr, name, innerBlock) {
  var start = "<!-- " + name + ":START -->";
  var end = "<!-- " + name + ":END -->";
  var i = htmlStr.indexOf(start);
  var j = htmlStr.indexOf(end);
  if (i === -1 || j === -1 || j < i) throw new Error("Marker mancanti per " + name);
  var before = htmlStr.slice(0, i + start.length);
  var after = htmlStr.slice(j);
  return before + "\n" + innerBlock + "\n        " + after;
}

/* Applica i contenuti forniti (qualunque sottoinsieme) a index.html */
export function applyContent(htmlStr, content) {
  var out = htmlStr;
  if (content.barbers)  out = replaceRegion(out, MARKERS.barbers,  renderBarbers(content.barbers));
  if (content.services) out = replaceRegion(out, MARKERS.services, renderServices(content.services));
  if (content.gallery)  out = replaceRegion(out, MARKERS.gallery,  renderGallery(content.gallery));
  return out;
}
