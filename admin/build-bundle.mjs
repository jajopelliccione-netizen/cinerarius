/* Rigenera admin/worker.bundle.js da src/index.js + src/render.js.
   Uso (facoltativo, solo per sviluppo):  node admin/build-bundle.mjs       */
import fs from "node:fs";
const dir = new URL(".", import.meta.url).pathname;
let render = fs.readFileSync(dir + "src/render.js", "utf8").replace(/^export\s+/gm, "");
let index  = fs.readFileSync(dir + "src/index.js", "utf8")
  .replace(/^import\s*\{[^}]*\}\s*from\s*["']\.\/render\.js["'];\s*\n/m, "");
const banner = "/* AUTO-BUNDLE: generato da src/index.js + src/render.js — file unico per l'editor Cloudflare */\n\n";
fs.writeFileSync(dir + "worker.bundle.js", banner + render.trimEnd() + "\n\n" + index);
console.log("worker.bundle.js rigenerato");
