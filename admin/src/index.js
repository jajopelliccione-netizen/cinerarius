/* ============================================================
   Cinerarius — Pannello di amministrazione (Cloudflare Worker + D1)
   UI inline (HTML+CSS+JS vanilla) + API REST con auth propria.
   Palette: brand Cinerarius (accento turchese "mare").
   ============================================================ */

const COOKIE = "session";
const SESSION_DAYS = 7;
let seeded = false;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      await ensureSeed(env);

      if (path === "/" ) return Response.redirect(new URL("/admin", url).toString(), 302);
      if (path === "/admin" || path === "/admin/") return html(PAGE);
      if (path === "/manifest.webmanifest") return new Response(MANIFEST, { headers: { "content-type": "application/manifest+json; charset=utf-8" } });
      if (path === "/sw.js") return new Response(SW, { headers: { "content-type": "application/javascript; charset=utf-8" } });
      if (path === "/admin-icon.svg") return new Response(ICON, { headers: { "content-type": "image/svg+xml; charset=utf-8" } });
      if (path.startsWith("/api/")) return await api(request, env, url);

      return new Response("Not found", { status: 404 });
    } catch (e) {
      return json({ error: (e && e.message) || "Errore interno" }, 500);
    }
  }
};

/* ---------------- API router ---------------- */
async function api(request, env, url) {
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") return cors(new Response(null, { status: 204 }));

  if (path === "/api/login" && method === "POST") return login(request, env);
  if (path === "/api/logout" && method === "POST") return logout(request, env);
  if (path === "/api/register" && method === "POST") return publicRegister(request, env);

  // ---- protette ----
  const user = await getSessionUser(request, env);
  if (!user) return json({ error: "Non autenticato" }, 401);

  if (path === "/api/me" && method === "GET") return json({ user: pubUser(user) });
  if (path === "/api/change-password" && method === "POST") return changePassword(request, env, user);

  // se deve cambiare password, blocca tutto il resto
  if (user.must_change) return json({ error: "Devi prima cambiare la password", must_change: true }, 403);

  if (path === "/api/registrations" && method === "GET") return listRegistrations(env, user);
  const rm = path.match(/^\/api\/registrations\/(\d+)$/);
  if (rm && method === "DELETE") return deleteRegistration(env, user, rm[1]);

  if (path === "/api/users" && method === "GET") return listUsers(env, user);
  if (path === "/api/users" && method === "POST") return createUser(request, env, user);
  const um = path.match(/^\/api\/users\/(\d+)$/);
  if (um && method === "PATCH") return patchUser(request, env, user, um[1]);
  if (um && method === "DELETE") return deleteUser(env, user, um[1]);

  return json({ error: "Not found" }, 404);
}

/* ---------------- Handlers ---------------- */
async function login(request, env) {
  const b = await readJson(request);
  const email = (b.email || "").trim().toLowerCase();
  const pw = (b.password || "").toString();
  const user = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
  if (!user) return json({ error: "Credenziali non valide" }, 401);
  const ok = await verifyPassword(pw, user.pass_hash, user.pass_salt);
  if (!ok) return json({ error: "Credenziali non valide" }, 401);
  const token = await createSession(env, user.id);
  return json({ ok: true, user: pubUser(user) }, 200, { "Set-Cookie": sessionCookie(token) });
}

async function logout(request, env) {
  const token = getCookie(request, COOKIE);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token=?").bind(token).run();
  return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
}

async function publicRegister(request, env) {
  const b = await readJson(request);
  const nome = cut(b.nome, 120), cognome = cut(b.cognome, 120), email = cut(b.email, 200);
  const tel = cut(b.tel, 60), ruolo = cut(b.ruolo, 120), msg = cut(b.msg, 2000), source = cut(b.source || "sito", 60);
  if (!nome && !email && !tel) return cors(json({ error: "Dati insufficienti" }, 400));
  await env.DB.prepare("INSERT INTO registrations (nome,cognome,email,tel,ruolo,msg,source,created_at) VALUES (?,?,?,?,?,?,?,?)")
    .bind(nome, cognome, email, tel, ruolo, msg, source, Date.now()).run();
  return cors(json({ ok: true }));
}

async function changePassword(request, env, user) {
  const b = await readJson(request);
  const np = (b.new_password || "").toString();
  if (np.length < 8) return json({ error: "La nuova password deve avere almeno 8 caratteri" }, 400);
  if (!user.must_change) {
    const cur = (b.current_password || "").toString();
    const ok = await verifyPassword(cur, user.pass_hash, user.pass_salt);
    if (!ok) return json({ error: "Password attuale non corretta" }, 400);
  }
  const k = await hashPassword(np);
  await env.DB.prepare("UPDATE users SET pass_hash=?,pass_salt=?,must_change=0 WHERE id=?").bind(k.hash, k.salt, user.id).run();
  return json({ ok: true });
}

async function listRegistrations(env, actor) {
  if (!can(actor, "registrations")) return json({ error: "Permesso negato" }, 403);
  const r = await env.DB.prepare("SELECT * FROM registrations ORDER BY created_at DESC").all();
  return json({ rows: r.results || [], count: (r.results || []).length });
}
async function deleteRegistration(env, actor, id) {
  if (!can(actor, "registrations")) return json({ error: "Permesso negato" }, 403);
  await env.DB.prepare("DELETE FROM registrations WHERE id=?").bind(parseInt(id, 10)).run();
  return json({ ok: true });
}

async function listUsers(env, actor) {
  if (!can(actor, "users")) return json({ error: "Permesso negato" }, 403);
  const r = await env.DB.prepare("SELECT id,email,name,role,must_change,perm_registrations,perm_users,created_at FROM users ORDER BY created_at DESC").all();
  return json({ users: r.results || [], me: actor.id });
}
async function createUser(request, env, actor) {
  if (!can(actor, "users")) return json({ error: "Permesso negato" }, 403);
  const b = await readJson(request);
  const email = (b.email || "").trim().toLowerCase();
  const name = (b.name || "").trim();
  const role = b.role === "admin" ? "admin" : "staff";
  if (role === "admin" && actor.role !== "admin") return json({ error: "Solo un amministratore può creare altri amministratori" }, 403);
  const pw = (b.password || "").toString();
  if (!emailValid(email)) return json({ error: "Email non valida" }, 400);
  if (pw.length < 8) return json({ error: "La password provvisoria deve avere almeno 8 caratteri" }, 400);
  const must = b.must_change === false ? 0 : 1;
  const pr = role === "admin" ? 1 : (b.perm_registrations ? 1 : 0);
  const pu = role === "admin" ? 1 : (b.perm_users ? 1 : 0);
  const k = await hashPassword(pw);
  try {
    await env.DB.prepare("INSERT INTO users (email,name,pass_hash,pass_salt,role,must_change,perm_registrations,perm_users,created_at,created_by) VALUES (?,?,?,?,?,?,?,?,?,?)")
      .bind(email, name, k.hash, k.salt, role, must, pr, pu, Date.now(), actor.id).run();
  } catch (e) {
    return json({ error: "Esiste già un account con questa email" }, 409);
  }
  return json({ ok: true });
}
async function patchUser(request, env, actor, id) {
  if (!can(actor, "users")) return json({ error: "Permesso negato" }, 403);
  id = parseInt(id, 10);
  const target = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(id).first();
  if (!target) return json({ error: "Utente non trovato" }, 404);
  const b = await readJson(request);
  const action = b.action;

  if (action === "reset") {
    const pw = (b.password || "").toString();
    if (pw.length < 8) return json({ error: "Password provvisoria troppo corta (min 8)" }, 400);
    const k = await hashPassword(pw);
    await env.DB.prepare("UPDATE users SET pass_hash=?,pass_salt=?,must_change=1 WHERE id=?").bind(k.hash, k.salt, id).run();
    return json({ ok: true });
  }
  if (action === "force_change") {
    await env.DB.prepare("UPDATE users SET must_change=1 WHERE id=?").bind(id).run();
    return json({ ok: true });
  }
  if (action === "update") {
    const role = b.role === "admin" ? "admin" : "staff";
    if (role === "admin" && actor.role !== "admin") return json({ error: "Solo un amministratore può assegnare il ruolo admin" }, 403);
    const pr = role === "admin" ? 1 : (b.perm_registrations ? 1 : 0);
    const pu = role === "admin" ? 1 : (b.perm_users ? 1 : 0);
    const name = b.name != null ? ("" + b.name).trim() : target.name;
    await env.DB.prepare("UPDATE users SET name=?,role=?,perm_registrations=?,perm_users=? WHERE id=?").bind(name, role, pr, pu, id).run();
    return json({ ok: true });
  }
  return json({ error: "Azione non valida" }, 400);
}
async function deleteUser(env, actor, id) {
  if (!can(actor, "users")) return json({ error: "Permesso negato" }, 403);
  id = parseInt(id, 10);
  if (id === actor.id) return json({ error: "Non puoi eliminare il tuo stesso account" }, 400);
  await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();
  return json({ ok: true });
}

/* ---------------- Seed ---------------- */
async function ensureSeed(env) {
  if (seeded) return;
  let row;
  try { row = await env.DB.prepare("SELECT COUNT(*) AS c FROM users").first(); }
  catch (e) { return; } // tabelle non ancora create
  if (row && row.c === 0) {
    const email = (env.SEED_EMAIL || "admin@admin.local").toLowerCase();
    const pw = env.SEED_PASSWORD || "changeme123";
    const k = await hashPassword(pw);
    await env.DB.prepare("INSERT INTO users (email,name,pass_hash,pass_salt,role,must_change,perm_registrations,perm_users,created_at) VALUES (?,?,?,?,?,?,?,?,?)")
      .bind(email, "Amministratore", k.hash, k.salt, "admin", 1, 1, 1, Date.now()).run();
  }
  seeded = true;
}

/* ---------------- Auth utils ---------------- */
async function pbkdf2(password, saltBytes) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" }, key, 256);
  return new Uint8Array(bits);
}
function toHex(b) { let s = ""; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0"); return s; }
function fromHex(h) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
async function hashPassword(pw) { const salt = crypto.getRandomValues(new Uint8Array(16)); const h = await pbkdf2(pw, salt); return { hash: toHex(h), salt: toHex(salt) }; }
async function verifyPassword(pw, hashHex, saltHex) { const h = toHex(await pbkdf2(pw, fromHex(saltHex))); return timingSafeEqual(h, hashHex); }
function timingSafeEqual(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }

async function createSession(env, userId) {
  const token = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const expires = Date.now() + SESSION_DAYS * 86400 * 1000;
  await env.DB.prepare("INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)").bind(token, userId, expires).run();
  return token;
}
async function getSessionUser(request, env) {
  const token = getCookie(request, COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare(
    "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>?"
  ).bind(token, Date.now()).first();
  return row || null;
}

/* ---------------- HTTP utils ---------------- */
function json(obj, status, headers) {
  status = status || 200;
  const h = { "content-type": "application/json; charset=utf-8" };
  if (headers) for (const k in headers) h[k] = headers[k];
  return new Response(JSON.stringify(obj), { status, headers: h });
}
function html(s) { return new Response(s, { headers: { "content-type": "text/html; charset=utf-8" } }); }
function cors(resp) {
  resp.headers.set("Access-Control-Allow-Origin", "*");
  resp.headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  resp.headers.set("Access-Control-Allow-Headers", "Content-Type");
  return resp;
}
async function readJson(request) { try { return await request.json(); } catch (e) { return {}; } }
function getCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|; )" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}
function sessionCookie(token) { return COOKIE + "=" + token + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" + (SESSION_DAYS * 86400); }
function clearCookie() { return COOKIE + "=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"; }
function pubUser(u) { return { id: u.id, email: u.email, name: u.name, role: u.role, must_change: u.must_change, perm_registrations: u.perm_registrations, perm_users: u.perm_users }; }
function can(u, perm) { return u.role === "admin" || u["perm_" + perm] === 1; }
function emailValid(e) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e); }
function cut(v, n) { return (v == null ? "" : ("" + v)).slice(0, n); }

/* ---------------- PWA icon / manifest / SW ---------------- */
const ICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="112" fill="#0e1116"/><g fill="none" stroke="#21b2c6" stroke-width="26" stroke-linecap="round"><circle cx="180" cy="150" r="44"/><circle cx="332" cy="150" r="44"/><path d="M212 182 300 360 M300 182 212 360"/></g><circle cx="256" cy="300" r="16" fill="#21b2c6"/></svg>';

const MANIFEST = JSON.stringify({
  name: "Cinerarius Admin",
  short_name: "Cinerarius",
  start_url: "/admin",
  scope: "/admin",
  display: "standalone",
  background_color: "#090b0e",
  theme_color: "#090b0e",
  icons: [{ src: "/admin-icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any maskable" }]
});

const SW = [
  "self.addEventListener('install', function(e){ self.skipWaiting(); });",
  "self.addEventListener('activate', function(e){ e.waitUntil(self.clients.claim()); });",
  "self.addEventListener('fetch', function(e){ /* network-first, nessuna cache aggressiva */ });"
].join("\n");

/* ============================================================
   UI (HTML + CSS + JS vanilla, inline)
   NB: il JS client usa concatenazione di stringhe (niente
   template literal) per non rompere questo template esterno.
   ============================================================ */
const PAGE = `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<title>Cinerarius · Amministrazione</title>
<meta name="theme-color" content="#090b0e" />
<link rel="manifest" href="/manifest.webmanifest" />
<link rel="icon" href="/admin-icon.svg" />
<link rel="apple-touch-icon" href="/admin-icon.svg" />
<meta name="apple-mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Jost:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet" />
<style>
:root{
  --bg:#090b0e; --surface:#14171d; --surface-2:#0e1116; --surface-3:#1a1e25;
  --line:rgba(255,255,255,.09); --line-soft:rgba(255,255,255,.05);
  --text:#eef0f3; --muted:#99a1ab; --muted-2:#626973;
  --accent:#21b2c6; --accent-2:#0f8294; --accent-soft:rgba(33,178,198,.12);
  --bad:#ff7b7b; --bad-soft:rgba(255,123,123,.12);
  --r:16px; --r-sm:11px; --ease:cubic-bezier(.22,1,.36,1);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  font-family:"Inter",system-ui,sans-serif; color:var(--text); line-height:1.5;
  background:
    radial-gradient(900px 620px at 100% 0%, var(--accent-soft), transparent 60%),
    radial-gradient(820px 600px at 0% 100%, var(--accent-soft), transparent 55%),
    var(--bg);
  -webkit-font-smoothing:antialiased; min-height:100vh;
}
a{color:inherit;text-decoration:none}
.jost{font-family:"Jost",sans-serif;text-transform:uppercase;letter-spacing:.14em}
.eyebrow{font-family:"Jost",sans-serif;text-transform:uppercase;letter-spacing:.28em;font-size:.7rem;color:var(--accent);font-weight:600}
.muted{color:var(--muted)}
.spin{display:inline-block;width:18px;height:18px;border:2px solid var(--line);border-top-color:var(--accent);border-radius:50%;animation:sp .7s linear infinite;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}

/* buttons */
.btn{font-family:"Jost",sans-serif;text-transform:uppercase;letter-spacing:.12em;font-weight:600;font-size:.78rem;
  display:inline-flex;align-items:center;justify-content:center;gap:.5em;cursor:pointer;
  padding:12px 22px;border-radius:40px;border:1px solid transparent;background:transparent;color:var(--text);
  transition:transform .25s var(--ease),background .25s var(--ease),border-color .25s var(--ease),box-shadow .25s var(--ease),opacity .2s}
.btn:hover{transform:translateY(-2px)}
.btn:active{transform:translateY(0)}
.btn:disabled{opacity:.55;cursor:default;transform:none}
.btn svg{width:17px;height:17px;flex:0 0 17px}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#04222a;box-shadow:0 10px 26px rgba(33,178,198,.25)}
.btn-ghost{border-color:var(--line);color:var(--text)}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.btn-danger{border-color:var(--bad-soft);background:var(--bad-soft);color:var(--bad)}
.btn-danger:hover{border-color:var(--bad)}
.btn-sm{padding:8px 14px;font-size:.68rem}
.btn-block{width:100%}

/* card */
.card{background:linear-gradient(180deg,var(--surface),var(--surface-2));border:1px solid var(--line);border-radius:var(--r);
  box-shadow:0 18px 50px rgba(0,0,0,.35);padding:24px}
.card + .card{margin-top:18px}
h1,h2,h3{font-family:"Jost",sans-serif;font-weight:600;letter-spacing:.02em}
.title{font-size:1.5rem;text-transform:uppercase;letter-spacing:.06em}
.sub{color:var(--muted);font-size:.92rem;margin-top:4px}

/* pills / badges */
.pill{display:inline-flex;align-items:center;gap:6px;font-family:"Jost",sans-serif;text-transform:uppercase;letter-spacing:.1em;
  font-size:.62rem;font-weight:600;padding:5px 11px;border-radius:40px;border:1px solid var(--line);color:var(--muted)}
.pill.on{color:var(--accent);border-color:var(--accent);background:var(--accent-soft)}
.pill.role{color:var(--text)}
.pill.admin{color:var(--accent);border-color:var(--accent);background:var(--accent-soft)}

/* form */
.field{margin-bottom:14px}
.field label{display:block;font-family:"Jost",sans-serif;text-transform:uppercase;letter-spacing:.12em;font-size:.66rem;color:var(--muted);margin-bottom:7px}
.field input,.field select{width:100%;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-sm);
  color:var(--text);font-family:inherit;font-size:.95rem;padding:12px 14px;transition:border-color .2s var(--ease),box-shadow .2s var(--ease)}
.field input:focus,.field select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.field input::placeholder{color:var(--muted-2)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.chips{display:flex;flex-wrap:wrap;gap:10px}
.chips label{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:40px;padding:9px 14px;cursor:pointer;
  font-size:.82rem;color:var(--muted);transition:border-color .2s,color .2s,background .2s}
.chips label:has(input:checked){border-color:var(--accent);color:var(--accent);background:var(--accent-soft)}
.chips input{accent-color:var(--accent)}
.err{color:var(--bad);background:var(--bad-soft);border:1px solid var(--bad-soft);border-radius:var(--r-sm);padding:10px 13px;font-size:.86rem;margin-top:6px;display:none}
.err.show{display:block}
.ok{color:var(--accent);font-size:.86rem;margin-top:8px;display:none}
.ok.show{display:block}

/* table */
.tbl{width:100%;border-collapse:collapse}
.tbl thead th{font-family:"Jost",sans-serif;text-transform:lowercase;letter-spacing:.16em;font-size:.68rem;color:var(--muted-2);font-weight:600;
  text-align:left;padding:0 14px 12px;border-bottom:1px solid var(--line)}
.tbl tbody td{padding:14px;border-bottom:1px solid var(--line-soft);font-size:.92rem;vertical-align:middle}
.tbl tbody tr:hover{background:rgba(255,255,255,.02)}
.tbl .strong{font-weight:600}
.count{font-family:"Jost",sans-serif;font-size:.7rem;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);
  border:1px solid var(--accent);background:var(--accent-soft);border-radius:40px;padding:5px 12px}
.empty{padding:40px 14px;text-align:center;color:var(--muted)}

/* login */
.center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.login-box{width:100%;max-width:420px}
.logo{display:flex;align-items:center;gap:12px;justify-content:center;margin-bottom:26px}
.logo img{width:46px;height:46px}
.logo b{font-family:"Jost",sans-serif;text-transform:uppercase;letter-spacing:.18em;font-size:1.05rem}

/* app shell */
.shell{display:flex;min-height:100vh}
.side{width:248px;flex:0 0 248px;position:sticky;top:0;height:100vh;padding:24px 16px;
  background:rgba(14,17,22,.7);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-right:1px solid var(--line);
  display:flex;flex-direction:column;gap:8px}
.side .brand{display:flex;align-items:center;gap:11px;padding:6px 10px 20px}
.side .brand img{width:34px;height:34px}
.side .brand b{font-family:"Jost",sans-serif;text-transform:uppercase;letter-spacing:.16em;font-size:.9rem}
.navit{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:var(--r-sm);color:var(--muted);
  font-family:"Jost",sans-serif;text-transform:uppercase;letter-spacing:.12em;font-size:.76rem;font-weight:500;cursor:pointer;
  transition:background .2s var(--ease),color .2s var(--ease)}
.navit svg{width:19px;height:19px;flex:0 0 19px}
.navit:hover{color:var(--text);background:rgba(255,255,255,.03)}
.navit.active{color:var(--accent);background:var(--accent-soft)}
.side .userbox{margin-top:auto;border-top:1px solid var(--line);padding-top:16px}
.side .userbox .nm{font-weight:600;font-size:.92rem}
.side .userbox .rl{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;font-family:"Jost",sans-serif;margin-top:2px}
.main{flex:1;min-width:0;padding:40px 40px 80px}
.head{margin-bottom:26px}
.topbar{display:none}
.bottomnav{display:none}

@media(max-width:860px){
  .shell{flex-direction:column}
  .side{display:none}
  .topbar{display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:20;
    padding:14px 18px;padding-top:max(14px,env(safe-area-inset-top));
    background:rgba(14,17,22,.82);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid var(--line)}
  .topbar .brand{display:flex;align-items:center;gap:10px}
  .topbar .brand img{width:30px;height:30px}
  .topbar .brand b{font-family:"Jost",sans-serif;text-transform:uppercase;letter-spacing:.16em;font-size:.82rem}
  .main{padding:22px 16px calc(96px + env(safe-area-inset-bottom))}
  .bottomnav{display:flex;position:fixed;left:0;right:0;bottom:0;z-index:30;justify-content:space-around;
    padding:10px 8px;padding-bottom:max(10px,env(safe-area-inset-bottom));
    background:rgba(14,17,22,.92);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-top:1px solid var(--line)}
  .bnit{display:flex;flex-direction:column;align-items:center;gap:4px;color:var(--muted-2);font-family:"Jost",sans-serif;
    text-transform:uppercase;letter-spacing:.08em;font-size:.56rem;cursor:pointer;padding:4px 10px;border-radius:10px}
  .bnit svg{width:21px;height:21px}
  .bnit.active{color:var(--accent)}
  .row{grid-template-columns:1fr}
  /* tabelle -> schede impilate */
  .tbl,.tbl thead,.tbl tbody,.tbl tr,.tbl td{display:block;width:100%}
  .tbl thead{display:none}
  .tbl tbody tr{border:1px solid var(--line);border-radius:var(--r-sm);padding:6px 0;margin-bottom:12px;background:var(--surface-2)}
  .tbl tbody td{border:none;display:flex;justify-content:space-between;gap:14px;padding:9px 14px;text-align:right}
  .tbl tbody td::before{content:attr(data-label);font-family:"Jost",sans-serif;text-transform:uppercase;letter-spacing:.1em;
    font-size:.62rem;color:var(--muted-2);text-align:left;flex:0 0 auto}
  .tbl tbody td.actions{justify-content:flex-end}
}
.flex{display:flex;align-items:center;gap:12px}
.between{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}
.stack8{display:flex;flex-direction:column;gap:8px}
.mt16{margin-top:16px}.mt24{margin-top:24px}
.ulist{list-style:none;display:flex;flex-direction:column;gap:12px}
.ulist li{border:1px solid var(--line);border-radius:var(--r-sm);padding:14px;background:var(--surface-2)}
.uname{font-weight:600}
.uemail{color:var(--muted);font-size:.86rem}
.badges{display:flex;flex-wrap:wrap;gap:7px;margin-top:9px}
.uactions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
</style>
</head>
<body>
<div id="app"><div class="center"><span class="spin"></span></div></div>
<script>
(function(){
"use strict";
var ME=null, SECTION="registrations";
var root=document.getElementById("app");

function h(s){return (s==null?"":String(s)).replace(/[&<>"']/g,function(c){return ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c];});}
function el(id){return document.getElementById(id);}
function api(method,path,body){
  var opt={method:method,headers:{},credentials:"same-origin"};
  if(body!==undefined){opt.headers["Content-Type"]="application/json";opt.body=JSON.stringify(body);}
  return fetch(path,opt).then(function(r){return r.json().then(function(d){return {ok:r.ok,status:r.status,data:d};},function(){return {ok:r.ok,status:r.status,data:{}};});});
}
function fmtDate(ms){var d=new Date(ms);try{return d.toLocaleString("it-IT",{day:"2-digit",month:"2-digit",year:"numeric",hour:"2-digit",minute:"2-digit"});}catch(e){return d.toISOString();}}

/* icone */
var IC={
  reg:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 5h6M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2"/><path d="M9 12h6M9 16h4"/></svg>',
  users:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3.2"/><path d="M3.5 19a5.5 5.5 0 0 1 11 0"/><path d="M16 6.2a3 3 0 0 1 0 5.6M17.5 19a5 5 0 0 0-3-4.6"/></svg>',
  acc:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="3.4"/><path d="M5.5 19.5a6.5 6.5 0 0 1 13 0"/></svg>',
  out:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M15 17l5-5-5-5M20 12H9M11 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h5"/></svg>'
};

/* ============ INIT ============ */
function init(){
  api("GET","/api/me").then(function(res){
    if(res.ok){ ME=res.data.user; if(ME.must_change){renderChange();} else {renderApp();} }
    else { renderLogin(); }
  }).catch(function(){renderLogin();});
}

/* ============ LOGIN ============ */
function renderLogin(){
  root.innerHTML=
    '<div class="center"><div class="login-box">'+
    '<div class="logo"><img src="/admin-icon.svg" alt=""/><b>Cinerarius</b></div>'+
    '<div class="card">'+
      '<p class="eyebrow">Area riservata</p>'+
      '<h1 class="title mt16">Accedi</h1>'+
      '<p class="sub">Pannello di amministrazione</p>'+
      '<div class="mt24">'+
        '<div class="field"><label>Email</label><input id="li_email" type="email" autocomplete="username" placeholder="nome@dominio.it"/></div>'+
        '<div class="field"><label>Password</label><input id="li_pw" type="password" autocomplete="current-password" placeholder="••••••••"/></div>'+
        '<div id="li_err" class="err"></div>'+
        '<button id="li_btn" class="btn btn-primary btn-block mt16">Entra</button>'+
      '</div>'+
    '</div></div></div>';
  el("li_btn").onclick=doLogin;
  el("li_pw").addEventListener("keydown",function(e){if(e.key==="Enter")doLogin();});
  el("li_email").focus();
}
function doLogin(){
  var b=el("li_btn"), err=el("li_err");
  err.classList.remove("show");
  var email=el("li_email").value.trim(), pw=el("li_pw").value;
  if(!email||!pw){err.textContent="Inserisci email e password";err.classList.add("show");return;}
  b.disabled=true;b.innerHTML='<span class="spin"></span>';
  api("POST","/api/login",{email:email,password:pw}).then(function(res){
    if(res.ok){ ME=res.data.user; if(ME.must_change){renderChange();}else{renderApp();} }
    else { err.textContent=res.data.error||"Credenziali non valide";err.classList.add("show");b.disabled=false;b.textContent="Entra"; }
  });
}

/* ============ CAMBIO PASSWORD OBBLIGATORIO ============ */
function renderChange(){
  root.innerHTML=
    '<div class="center"><div class="login-box">'+
    '<div class="logo"><img src="/admin-icon.svg" alt=""/><b>Cinerarius</b></div>'+
    '<div class="card">'+
      '<p class="eyebrow">Sicurezza</p>'+
      '<h1 class="title mt16">Cambia password</h1>'+
      '<p class="sub">Per continuare devi impostare una nuova password personale.</p>'+
      '<div class="mt24">'+
        '<div class="field"><label>Nuova password (min 8)</label><input id="cp_new" type="password" autocomplete="new-password" placeholder="••••••••"/></div>'+
        '<div class="field"><label>Conferma password</label><input id="cp_conf" type="password" autocomplete="new-password" placeholder="••••••••"/></div>'+
        '<div id="cp_err" class="err"></div>'+
        '<button id="cp_btn" class="btn btn-primary btn-block mt16">Salva e continua</button>'+
        '<button id="cp_out" class="btn btn-ghost btn-block mt16">Esci</button>'+
      '</div>'+
    '</div></div></div>';
  el("cp_btn").onclick=function(){
    var err=el("cp_err");err.classList.remove("show");
    var np=el("cp_new").value, cf=el("cp_conf").value;
    if(np.length<8){err.textContent="La password deve avere almeno 8 caratteri";err.classList.add("show");return;}
    if(np!==cf){err.textContent="Le password non coincidono";err.classList.add("show");return;}
    var b=el("cp_btn");b.disabled=true;b.innerHTML='<span class="spin"></span>';
    api("POST","/api/change-password",{new_password:np}).then(function(res){
      if(res.ok){ ME.must_change=0; renderApp(); }
      else{ err.textContent=res.data.error||"Errore";err.classList.add("show");b.disabled=false;b.textContent="Salva e continua"; }
    });
  };
  el("cp_out").onclick=logout;
}

/* ============ APP SHELL ============ */
function navItems(){
  var items=[];
  if(can("registrations")) items.push({k:"registrations",t:"Iscrizioni",i:IC.reg});
  if(can("users")) items.push({k:"users",t:"Accessi",i:IC.users});
  items.push({k:"account",t:"Account",i:IC.acc});
  return items;
}
function can(p){ return ME && (ME.role==="admin" || ME["perm_"+p]===1); }

function renderApp(){
  var items=navItems();
  if(!items.some(function(x){return x.k===SECTION;})) SECTION=items[0].k;
  var sideNav=items.map(function(x){
    return '<div class="navit'+(x.k===SECTION?" active":"")+'" data-k="'+x.k+'">'+x.i+'<span>'+x.t+'</span></div>';
  }).join("");
  var botNav=items.map(function(x){
    return '<div class="bnit'+(x.k===SECTION?" active":"")+'" data-k="'+x.k+'">'+x.i+'<span>'+x.t+'</span></div>';
  }).join("");
  var roleLabel=ME.role==="admin"?"Amministratore":"Staff";
  root.innerHTML=
    '<div class="shell">'+
      '<aside class="side">'+
        '<div class="brand"><img src="/admin-icon.svg" alt=""/><b>Cinerarius</b></div>'+
        sideNav+
        '<div class="userbox">'+
          '<div class="nm">'+h(ME.name||ME.email)+'</div><div class="rl">'+roleLabel+'</div>'+
          '<button id="sb_out" class="btn btn-ghost btn-sm btn-block mt16">'+IC.out+'Esci</button>'+
        '</div>'+
      '</aside>'+
      '<div style="flex:1;min-width:0;display:flex;flex-direction:column">'+
        '<div class="topbar"><div class="brand"><img src="/admin-icon.svg" alt=""/><b>Cinerarius</b></div>'+
          '<button id="tb_out" class="btn btn-ghost btn-sm">'+IC.out+'Esci</button></div>'+
        '<main class="main"><div id="view"></div></main>'+
      '</div>'+
    '</div>'+
    '<nav class="bottomnav">'+botNav+'</nav>';
  Array.prototype.forEach.call(document.querySelectorAll("[data-k]"),function(n){
    n.onclick=function(){ SECTION=n.getAttribute("data-k"); renderApp(); };
  });
  if(el("sb_out")) el("sb_out").onclick=logout;
  if(el("tb_out")) el("tb_out").onclick=logout;
  loadSection();
}

function loadSection(){
  var v=el("view");
  v.innerHTML='<div class="card" style="text-align:center"><span class="spin"></span></div>';
  if(SECTION==="registrations") return viewRegistrations(v);
  if(SECTION==="users") return viewUsers(v);
  if(SECTION==="account") return viewAccount(v);
}

/* ============ ISCRIZIONI ============ */
function viewRegistrations(v){
  api("GET","/api/registrations").then(function(res){
    if(!res.ok){v.innerHTML='<div class="card"><p class="muted">'+h(res.data.error||"Errore")+'</p></div>';return;}
    var rows=res.data.rows||[];
    var head='<div class="head between"><div><p class="eyebrow">Dal sito</p><h1 class="title mt16">Iscrizioni</h1></div>'+
             '<span class="count">'+rows.length+' totali</span></div>';
    if(!rows.length){ v.innerHTML=head+'<div class="card"><div class="empty">Ancora nessuna iscrizione.</div></div>'; return; }
    var body=rows.map(function(r){
      var contacts=[r.email,r.tel].filter(Boolean).map(h).join("<br/>");
      var nome=h([r.nome,r.cognome].filter(Boolean).join(" "))||"—";
      var note=h(r.ruolo||r.msg||"")||"—";
      return '<tr>'+
        '<td data-label="Data">'+h(fmtDate(r.created_at))+'</td>'+
        '<td data-label="Nome" class="strong">'+nome+'</td>'+
        '<td data-label="Contatti">'+(contacts||"—")+'</td>'+
        '<td data-label="Ruolo / Note">'+note+'</td>'+
        '<td data-label="" class="actions"><button class="btn btn-danger btn-sm" data-del="'+r.id+'">Elimina</button></td>'+
      '</tr>';
    }).join("");
    v.innerHTML=head+'<div class="card"><table class="tbl"><thead><tr>'+
      '<th>data</th><th>nome</th><th>contatti</th><th>ruolo / note</th><th></th></tr></thead><tbody>'+body+'</tbody></table></div>';
    Array.prototype.forEach.call(v.querySelectorAll("[data-del]"),function(btn){
      btn.onclick=function(){
        if(!confirm("Eliminare questa iscrizione? L'operazione è irreversibile.")) return;
        btn.disabled=true;btn.innerHTML='<span class="spin"></span>';
        api("DELETE","/api/registrations/"+btn.getAttribute("data-del")).then(function(r){
          if(r.ok) viewRegistrations(v); else {alert(r.data.error||"Errore");btn.disabled=false;btn.textContent="Elimina";}
        });
      };
    });
  });
}

/* ============ ACCESSI (UTENTI) ============ */
function viewUsers(v){
  api("GET","/api/users").then(function(res){
    if(!res.ok){v.innerHTML='<div class="card"><p class="muted">'+h(res.data.error||"Errore")+'</p></div>';return;}
    var users=res.data.users||[], meId=res.data.me;
    var head='<div class="head"><p class="eyebrow">Gestione</p><h1 class="title mt16">Accessi</h1>'+
             '<p class="sub">Crea account e gestisci i permessi dello staff.</p></div>';
    var form='<div class="card">'+
      '<h3 class="jost" style="font-size:.95rem;letter-spacing:.1em">Nuovo accesso</h3>'+
      '<div class="row mt16">'+
        '<div class="field"><label>Nome</label><input id="nu_name" type="text" placeholder="Mario Rossi"/></div>'+
        '<div class="field"><label>Email</label><input id="nu_email" type="email" placeholder="mario@dominio.it"/></div>'+
      '</div>'+
      '<div class="row">'+
        '<div class="field"><label>Password provvisoria</label><input id="nu_pw" type="text" placeholder="min 8 caratteri"/></div>'+
        '<div class="field"><label>Ruolo</label><select id="nu_role"><option value="staff">Staff (permessi su misura)</option><option value="admin">Amministratore (tutti i permessi)</option></select></div>'+
      '</div>'+
      '<div class="field" id="nu_perms_wrap"><label>Permessi</label><div class="chips">'+
        '<label><input type="checkbox" id="nu_p_reg"/> Iscrizioni</label>'+
        '<label><input type="checkbox" id="nu_p_users"/> Accessi (utenti)</label>'+
      '</div></div>'+
      '<div class="field"><label class="chips"><span style="display:inline-flex;gap:8px;align-items:center;border:1px solid var(--line);border-radius:40px;padding:9px 14px"><input type="checkbox" id="nu_must" checked/> Deve cambiare password al primo accesso</span></label></div>'+
      '<div id="nu_err" class="err"></div><div id="nu_ok" class="ok"></div>'+
      '<button id="nu_btn" class="btn btn-primary mt16">Crea accesso</button>'+
    '</div>';

    var list=users.map(function(u){
      var badges=[];
      badges.push('<span class="pill '+(u.role==="admin"?"admin":"role")+'">'+(u.role==="admin"?"Admin":"Staff")+'</span>');
      if(u.role!=="admin"){
        badges.push('<span class="pill '+(u.perm_registrations?"on":"")+'">Iscrizioni</span>');
        badges.push('<span class="pill '+(u.perm_users?"on":"")+'">Accessi</span>');
      }
      if(u.must_change) badges.push('<span class="pill">Deve cambiare pw</span>');
      var actions='<button class="btn btn-ghost btn-sm" data-reset="'+u.id+'">Reset password</button>'+
                  '<button class="btn btn-ghost btn-sm" data-force="'+u.id+'">Forza cambio</button>';
      if(u.id!==meId) actions+='<button class="btn btn-danger btn-sm" data-deluser="'+u.id+'">Elimina</button>';
      return '<li><div class="between"><div><div class="uname">'+h(u.name||"—")+'</div><div class="uemail">'+h(u.email)+'</div></div></div>'+
        '<div class="badges">'+badges.join("")+'</div>'+
        '<div class="uactions">'+actions+'</div></li>';
    }).join("");

    v.innerHTML=head+form+'<div class="card mt24"><h3 class="jost" style="font-size:.95rem;letter-spacing:.1em">Accessi esistenti ('+users.length+')</h3><ul class="ulist mt16">'+list+'</ul></div>';

    // toggle permessi in base al ruolo
    var roleSel=el("nu_role"), permsWrap=el("nu_perms_wrap");
    function syncPerms(){ permsWrap.style.display = roleSel.value==="admin" ? "none" : "block"; }
    roleSel.onchange=syncPerms; syncPerms();

    el("nu_btn").onclick=function(){
      var err=el("nu_err"), ok=el("nu_ok"); err.classList.remove("show"); ok.classList.remove("show");
      var payload={
        name:el("nu_name").value.trim(), email:el("nu_email").value.trim(), password:el("nu_pw").value,
        role:roleSel.value, perm_registrations:el("nu_p_reg").checked, perm_users:el("nu_p_users").checked,
        must_change:el("nu_must").checked
      };
      var b=el("nu_btn");b.disabled=true;b.innerHTML='<span class="spin"></span>';
      api("POST","/api/users",payload).then(function(r){
        b.disabled=false;b.textContent="Crea accesso";
        if(r.ok){ viewUsers(v); }
        else { err.textContent=r.data.error||"Errore"; err.classList.add("show"); }
      });
    };

    Array.prototype.forEach.call(v.querySelectorAll("[data-reset]"),function(btn){
      btn.onclick=function(){
        var np=prompt("Nuova password provvisoria (min 8 caratteri):");
        if(np===null) return;
        if(np.length<8){alert("Troppo corta (min 8).");return;}
        api("PATCH","/api/users/"+btn.getAttribute("data-reset"),{action:"reset",password:np}).then(function(r){
          if(r.ok){alert("Password reimpostata. L'utente dovrà cambiarla al prossimo accesso.");viewUsers(v);} else alert(r.data.error||"Errore");
        });
      };
    });
    Array.prototype.forEach.call(v.querySelectorAll("[data-force]"),function(btn){
      btn.onclick=function(){
        api("PATCH","/api/users/"+btn.getAttribute("data-force"),{action:"force_change"}).then(function(r){
          if(r.ok){viewUsers(v);} else alert(r.data.error||"Errore");
        });
      };
    });
    Array.prototype.forEach.call(v.querySelectorAll("[data-deluser]"),function(btn){
      btn.onclick=function(){
        if(!confirm("Eliminare definitivamente questo accesso?")) return;
        api("DELETE","/api/users/"+btn.getAttribute("data-deluser")).then(function(r){
          if(r.ok){viewUsers(v);} else alert(r.data.error||"Errore");
        });
      };
    });
  });
}

/* ============ ACCOUNT ============ */
function viewAccount(v){
  v.innerHTML=
    '<div class="head"><p class="eyebrow">Profilo</p><h1 class="title mt16">Account</h1>'+
    '<p class="sub">'+h(ME.name||"")+' · '+h(ME.email)+'</p></div>'+
    '<div class="card" style="max-width:480px">'+
      '<h3 class="jost" style="font-size:.95rem;letter-spacing:.1em">Cambia la tua password</h3>'+
      '<div class="mt16">'+
        '<div class="field"><label>Password attuale</label><input id="ac_cur" type="password" autocomplete="current-password"/></div>'+
        '<div class="field"><label>Nuova password (min 8)</label><input id="ac_new" type="password" autocomplete="new-password"/></div>'+
        '<div class="field"><label>Conferma nuova password</label><input id="ac_conf" type="password" autocomplete="new-password"/></div>'+
        '<div id="ac_err" class="err"></div><div id="ac_ok" class="ok"></div>'+
        '<button id="ac_btn" class="btn btn-primary mt16">Aggiorna password</button>'+
      '</div>'+
    '</div>';
  el("ac_btn").onclick=function(){
    var err=el("ac_err"), ok=el("ac_ok"); err.classList.remove("show"); ok.classList.remove("show");
    var cur=el("ac_cur").value, np=el("ac_new").value, cf=el("ac_conf").value;
    if(np.length<8){err.textContent="La nuova password deve avere almeno 8 caratteri";err.classList.add("show");return;}
    if(np!==cf){err.textContent="Le password non coincidono";err.classList.add("show");return;}
    var b=el("ac_btn");b.disabled=true;b.innerHTML='<span class="spin"></span>';
    api("POST","/api/change-password",{current_password:cur,new_password:np}).then(function(r){
      b.disabled=false;b.textContent="Aggiorna password";
      if(r.ok){ ok.textContent="Password aggiornata."; ok.classList.add("show"); el("ac_cur").value="";el("ac_new").value="";el("ac_conf").value=""; }
      else { err.textContent=r.data.error||"Errore"; err.classList.add("show"); }
    });
  };
}

/* ============ LOGOUT ============ */
function logout(){ api("POST","/api/logout").then(function(){ ME=null; renderLogin(); }); }

/* PWA */
if("serviceWorker" in navigator){ navigator.serviceWorker.register("/sw.js").catch(function(){}); }

init();
})();
</script>
</body>
</html>`;
