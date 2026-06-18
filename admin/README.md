# Cinerarius — Pannello di amministrazione

Admin panel servito da un **Cloudflare Worker** con database **D1** e autenticazione propria
(PBKDF2-SHA256, sessioni via cookie HttpOnly). UI inline (HTML+CSS+JS vanilla, niente framework),
installabile come **PWA**. Stesso dominio del Worker → niente problemi CORS sui cookie.

```
admin/
  src/index.js     Worker completo: UI (su /admin) + API (/api/*)
  schema.sql       Tabelle D1 (users, sessions, registrations)
  wrangler.toml    Config (binding DB, seed admin)
```

## Deploy passo-passo

Prerequisiti: Node + `npm i -g wrangler` e `wrangler login`.

```bash
cd admin

# 1) crea il database D1
wrangler d1 create cinerarius_admin
#   -> copia il "database_id" che ti stampa e incollalo in wrangler.toml

# 2) crea le tabelle (in remoto)
wrangler d1 execute cinerarius_admin --remote --file=./schema.sql

# 3) (consigliato) imposta il seed admin come secret invece che in chiaro
wrangler secret put SEED_EMAIL        # es. admin@cinerariustophairroma.com
wrangler secret put SEED_PASSWORD     # password iniziale (verrà cambiata al 1° accesso)

# 4) deploy
wrangler deploy
```

Apri poi `https://<tuo-worker>.workers.dev/admin` (o il dominio/route che assegni).

- Al **primo accesso** usi email/password del seed → il pannello ti **obbliga a cambiare password**.
- L'admin iniziale ha tutti i permessi e può creare altri accessi (Amministratore o Staff con permessi su misura).

### Dominio personalizzato (opzionale)
Su Cloudflare → Workers & Pages → il worker → **Custom Domains/Routes**, es.
`admin.cinerariustophairroma.com`. Essendo stesso dominio della UI, i cookie di sessione funzionano senza CORS.

## API

| Metodo | Endpoint | Auth | Descrizione |
|---|---|---|---|
| POST | `/api/login` | — | login (set cookie sessione) |
| POST | `/api/logout` | sì | logout |
| GET  | `/api/me` | sì | utente corrente |
| POST | `/api/change-password` | sì | cambia la propria password |
| POST | `/api/register` | **pubblico** | invio iscrizione dal sito (CORS aperto) |
| GET  | `/api/registrations` | perm. iscrizioni | elenco iscrizioni |
| DELETE | `/api/registrations/:id` | perm. iscrizioni | elimina iscrizione |
| GET  | `/api/users` | perm. accessi | elenco accessi |
| POST | `/api/users` | perm. accessi | crea accesso |
| PATCH | `/api/users/:id` | perm. accessi | `reset` / `force_change` / `update` |
| DELETE | `/api/users/:id` | perm. accessi | elimina (non te stesso) |

### Inviare iscrizioni dal sito Cinerarius
Dal form del sito (qualsiasi dominio), POST JSON a `/api/register`:

```js
fetch("https://admin.cinerariustophairroma.com/api/register", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ nome, cognome, email, tel, ruolo, msg, source: "sito" })
});
```

## Sicurezza
- Password: PBKDF2-SHA256, 100.000 iterazioni, salt random per utente.
- Sessioni: token random a 256 bit in tabella `sessions`, cookie `HttpOnly; Secure; SameSite=Lax`, 7 giorni.
- Ruolo `admin` = accesso completo; `staff` = solo i permessi assegnati (`perm_registrations`, `perm_users`).
- Se `must_change=1`, ogni azione è bloccata finché l'utente non imposta una nuova password.
- Gli account sono **gestiti in modo trasparente**: ogni admin (con permesso accessi) vede tutti gli accessi esistenti.
