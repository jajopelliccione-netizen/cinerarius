# Cinerarius Top Hair

Sito vetrina del barber shop **Cinerarius Top Hair** (Roma — Quadraro & Furio Camillo).

Sito statico (HTML + CSS + JS, zero dipendenze). Si deploya su **Vercel** senza build.

## Struttura

```
index.html      Pagina unica (Home, Saloni, Barbers, Servizi, SHOCK, Academy, Contatti)
styles.css      Stile (dark / elegante / oro)
script.js       Menu mobile, header on-scroll, animazioni reveal
vercel.json     Config deploy (cache asset, clean URLs)
assets/         Logo (bianco / nero / oro) + favicon
```

## Da completare (placeholder da sostituire)

- **Foto reali**: saloni, barbieri e prodotti usano placeholder grafici. Sostituire con immagini reali
  nelle sezioni `.salon-photo`, `.team-photo`, `.product-art`.
- **Prenotazioni**: tutti i pulsanti "Prenota" puntano già al sistema di prenotazione online
  (Wegest, `id_punto=2786`). Per cambiarlo basta aggiornare l'URL nei link `Prenota`.
- **Social**: i link Instagram / TikTok / Facebook hanno `href="#"`. Inserire gli URL reali.

## Sviluppo locale

Apri `index.html` nel browser, oppure:

```bash
python3 -m http.server 8000
# poi visita http://localhost:8000
```
