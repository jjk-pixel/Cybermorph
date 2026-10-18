# CYBERMORPH — jumeau numérique de sécurité réseau

CYBERMORPH observe un réseau de lab (Nmap, ARP, ports locaux, Suricata), calcule le risque de chaque actif,
construit un graphe d'attaque, rapproche les alertes de MITRE ATT&CK, suit la propagation des incidents
et permet de simuler des hypothèses (« et si cet actif était compromis ? »). L'interface SOC présente
tout cela autour d'une scène 3D interactive du réseau.

```
 capteurs ──► orchestrateur (systemd, 5 min) ──► PostgreSQL ◄── FastAPI :8000 (127.0.0.1)
 nmap · arp · ss · suricata fast.log                              REST /api/*  +  WS /ws/live (5 s)
                                                                         ▲
                                         navigateur ──► Vite :5173 (proxy /api et /ws, jeton optionnel)
```

## Démarrer

```bash
# Backend (depuis backend/) — écoute en local uniquement
../venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000

# Frontend (depuis frontend/)
npm install
npm run dev          # http://127.0.0.1:5173
# ou : npm run build && npm run preview
```

La collecte tourne indépendamment via `cybermorph-scan.timer` (systemd, toutes les 5 minutes).

## Sécurité

- L'API **n'est jamais exposée sans authentification** : lancez uvicorn sur `127.0.0.1`.
- Pour accéder à l'interface depuis une autre machine, définissez un jeton **des deux côtés** :

  ```bash
  # backend/.env
  CYBERMORPH_API_TOKEN=<jeton long et aléatoire>

  # environnement du serveur Vite (ou frontend/.env.local)
  CYBERMORPH_API_TOKEN=<même jeton>
  CYBERMORPH_UI_HOST=0.0.0.0
  ```

  Le jeton est ajouté par le proxy Vite côté serveur ; il n'est jamais inclus dans le code envoyé au navigateur.
  Sans jeton, laissez `CYBERMORPH_UI_HOST` à sa valeur par défaut (`127.0.0.1`) : le proxy relaie l'API telle quelle.
- `CYBERMORPH_CORS_ORIGINS` (backend) liste les origines autorisées ; par défaut le serveur de développement local.

| Variable | Côté | Défaut | Rôle |
|---|---|---|---|
| `DATABASE_URL` | backend | — | connexion PostgreSQL |
| `CYBERMORPH_API_TOKEN` | backend + Vite | vide | jeton Bearer exigé sur `/api/*` et `/ws/*` |
| `CYBERMORPH_CORS_ORIGINS` | backend | `http://localhost:5173,http://127.0.0.1:5173` | CORS |
| `CYBERMORPH_API_URL` | Vite | `http://127.0.0.1:8000` | cible du proxy |
| `CYBERMORPH_UI_HOST` | Vite | `127.0.0.1` | interface d'écoute de l'UI |

## Interface

| Vue | Contenu | Lien avec la scène 3D |
|---|---|---|
| Jumeau | posture, chemin le plus probable, alertes en direct, actifs par risque | chemin principal en violet, incidents en rouge |
| Alertes | 500 dernières alertes Suricata, filtre de priorité, recherche | clic sur un flux : la paire est tracée |
| Incidents | actifs / tous, étapes de propagation (possibles, confirmées) | la trace de l'incident est dessinée |
| Chemins | chemins vers les cibles à forte valeur, score minimal, nombre de sauts | le chemin sélectionné est isolé |
| ATT&CK | 14 tactiques, techniques suivies et observées, alertes corroborantes | — |
| Historique | score max et nombre de chemins sur 24 h, tableau des scans | « Rejouer » applique l'état historique |
| Simulations | nouvelle hypothèse, comparaison avant/après, historique | chemins nouveaux ou aggravés en violet pointillé |

Codes de la scène : anneau = rôle (routeurs au centre, serveurs, postes, inconnus) ; altitude et auréole = score
de risque ; cyan = trafic observé, bleu pointillé = voisinage ARP, ambre = corroboré par une alerte IDS,
violet = prédit ou simulé, rouge = incident. Les mouvements sont désactivés si le système demande moins d'animations.

## Tests

```bash
cd backend && ../venv/bin/python -m unittest discover -s tests -t .   # moteurs, sur SQLite en mémoire
cd frontend && npm test && npm run lint && npm run build
```

## Notes d'exploitation

- Suricata : `fast.log` n'est plus vidé après lecture ; la position est mémorisée dans
  `backend/suricata_fast.offset` (compatible avec `copytruncate` de logrotate).
- Incidents : sans activité pendant une heure, un incident actif passe en `dormant` (rien n'est supprimé).
