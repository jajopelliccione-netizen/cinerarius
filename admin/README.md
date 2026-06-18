# Cinerarius — Pannello di amministrazione

Admin panel servito da un **Cloudflare Worker** con database **D1** e autenticazione propria
(PBKDF2-SHA256, sessioni via cookie HttpOnly). UI inline (HTML+CSS+JS vanilla, niente framework),
installabile come **PWA**. Stesso dominio del Worker → niente problemi CORS sui cookie.

```
admin/
  src/index.js     Worker completo: UI (su /admin) + API (/api/*)
  src/render.js    Render condiviso dei contenuti (riproduce lo stile del sito)
  worker.bundle.js File UNICO (src/index.js + src/render.js uniti) da incollare
                   nell'editor Cloudflare se NON usi il terminale
  build-bundle.mjs Rigenera worker.bundle.js dai sorgenti (solo sviluppo)
  schema.sql       Tabelle D1 (users, sessions)
  wrangler.toml    Config (binding DB + AI, seed admin, repo GitHub)
```

> **Senza terminale?** Vedi la sezione "Deploy SOLO dal pannello Cloudflare" più sotto:
> si incolla `worker.bundle.js` e si creano i binding/secret a clic.

Sezioni del pannello: **Barbieri**, **Listino**, **Gallery** (gestione contenuti del sito),
**Accessi** (creazione/gestione utenti) e **Account** (cambio password personale).

## Gestione contenuti del sito (Barbieri / Listino / Gallery)

Architettura **Build da Git**: i contenuti vivono in file JSON nel repo del sito
(`content/barbers.json`, `content/services.json`, `content/gallery.json`) e nel markup
statico di `index.html` tra dei marker (`<!-- BARBERS:START -->` … `END`).

Quando salvi dal pannello, il Worker:
1. legge l'`index.html` corrente dal repo via API GitHub;
2. rigenera **solo** la regione interessata con `src/render.js` → **stile identico** a quello esistente
   (niente AI che inventa HTML: template fisso riempito con i dati del form);
3. fa **un commit** (JSON + `index.html` + eventuali foto) sul branch del sito → il deploy
   (Cloudflare Pages / Vercel) ricostruisce in automatico.

Le foto caricate vengono **ridotte e compresse lato browser** (max 1200px barbieri / 1500px gallery,
JPEG q82) prima dell'upload, così i commit restano leggeri e il sito veloce.

**AI (Workers AI, gratis):** nella scheda barbiere il bottone ✦ genera una bozza della riga
"specialità" nello stile del sito a partire da poche parole chiave. Modello di default
`@cf/meta/llama-3.1-8b-instruct` (override con la var `AI_MODEL`).

Permesso dedicato: **`perm_content`** (gli admin ce l'hanno sempre; assegnabile allo staff).

### Link "Area riservata" nel footer del sito
Il footer del sito ha un link discreto **Area riservata** → `https://admin.cinerariustophairroma.com/`.
Assegna quel **Custom Domain** al Worker (vedi sotto), oppure cambia l'`href` nel footer di `index.html`.

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

# 4) token GitHub per pubblicare i contenuti sul sito (Build da Git)
#    Crea un Fine-grained PAT (Contents: Read and write) sul repo del sito, poi:
wrangler secret put GITHUB_TOKEN
#    Verifica in wrangler.toml: GITHUB_REPO / GITHUB_BRANCH e il binding [ai].

# 5) deploy
wrangler deploy
```

> Se aggiorni un DB **già esistente** (creato prima della gestione contenuti), aggiungi la colonna:
> `wrangler d1 execute cinerarius_admin --remote --command "ALTER TABLE users ADD COLUMN perm_content INTEGER NOT NULL DEFAULT 0; UPDATE users SET perm_content=1 WHERE role='admin';"`

Apri poi `https://<tuo-worker>.workers.dev/admin` (o il dominio/route che assegni).

- Al **primo accesso** usi email/password del seed → il pannello ti **obbliga a cambiare password**.
- L'admin iniziale ha tutti i permessi e può creare altri accessi (Amministratore o Staff con permessi su misura).

### Dominio personalizzato (opzionale)
Su Cloudflare → Workers & Pages → il worker → **Custom Domains/Routes**, es.
`admin.cinerariustophairroma.com`. Essendo stesso dominio della UI, i cookie di sessione funzionano senza CORS.

## Deploy SOLO dal pannello Cloudflare (senza terminale)

1. **Crea il Worker**: Cloudflare → *Workers & Pages* → *Create* → *Create Worker* → nome `cinerarius-admin` → *Deploy* → *Edit code*. Cancella il codice di esempio e **incolla tutto** il contenuto di `admin/worker.bundle.js` → *Deploy*.
2. **Database D1**: sezione *Storage & Databases → D1 → Create* → nome `cinerarius_admin`. Apri il DB → *Console* → incolla il contenuto di `schema.sql` → *Execute*.
3. **Binding**: torna al Worker → *Settings → Bindings → Add*:
   - *D1 database* → Variable name **`DB`** → scegli `cinerarius_admin`.
   - *Workers AI* → Variable name **`AI`**.
4. **Variabili e secret** (Worker → *Settings → Variables and Secrets*):
   - Plain text: **`GITHUB_REPO`** = `jajopelliccione-netizen/cinerarius`, **`GITHUB_BRANCH`** = `main`.
   - Secret: **`SEED_EMAIL`**, **`SEED_PASSWORD`**, **`GITHUB_TOKEN`** (token GitHub, vedi sotto).
5. **Deploy** di nuovo (basta *Deploy* dopo aver aggiunto i binding) e apri `https://<worker>.workers.dev/admin`.
6. (Opzionale) **Custom Domain** `admin.cinerariustophairroma.com` come sopra.

## API

| Metodo | Endpoint | Auth | Descrizione |
|---|---|---|---|
| POST | `/api/login` | — | login (set cookie sessione) |
| POST | `/api/logout` | sì | logout |
| GET  | `/api/me` | sì | utente corrente |
| POST | `/api/change-password` | sì | cambia la propria password |
| GET  | `/api/users` | perm. accessi | elenco accessi |
| POST | `/api/users` | perm. accessi | crea accesso |
| PATCH | `/api/users/:id` | perm. accessi | `reset` / `force_change` / `update` |
| DELETE | `/api/users/:id` | perm. accessi | elimina (non te stesso) |
| GET  | `/api/content/:type` | perm. contenuti | legge `barbers` / `services` / `gallery` |
| PUT  | `/api/content/:type` | perm. contenuti | salva + commit su GitHub (foto incluse) |
| POST | `/api/ai/draft` | perm. contenuti | bozza AI della specialità barbiere |

## Sicurezza
- Password: PBKDF2-SHA256, 100.000 iterazioni, salt random per utente.
- Sessioni: token random a 256 bit in tabella `sessions`, cookie `HttpOnly; Secure; SameSite=Lax`, 7 giorni.
- Ruolo `admin` = accesso completo; `staff` = solo i permessi assegnati (`perm_users`).
- Se `must_change=1`, ogni azione è bloccata finché l'utente non imposta una nuova password.
- Gli account sono **gestiti in modo trasparente**: ogni admin (con permesso accessi) vede tutti gli accessi esistenti.
