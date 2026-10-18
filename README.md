# CYBERMORPH — jumeau numérique de sécurité réseau

CYBERMORPH observe un réseau de lab (Nmap, ARP, ports locaux, Suricata `fast.log` et `eve.json`), tient un
inventaire rapproché et explicable, apprend la référence des communications habituelles et signale les écarts,
calcule le risque et l'exposition des actifs critiques (chemins d'attaque, points de blocage, mesures chiffrées),
rapproche les alertes de MITRE ATT&CK, suit la propagation des incidents, permet de simuler des hypothèses et
remonte chaque conclusion jusqu'à sa preuve source. L'interface SOC présente tout cela autour d'une scène 3D.

Chaque information distingue **fait observé**, **inférence** et **scénario simulé**. Les choix de conception et
leurs sources sont dans `docs/competitive_analysis.md` ; l'état de chaque capacité dans `docs/feature_gap_analysis.md`.

```
 capteurs ──► orchestrateur (systemd, 5 min) ──► PostgreSQL ◄── FastAPI :8000 (127.0.0.1)
 nmap · arp · ss · suricata fast.log + eve.json                   REST /api/*  +  WS /ws/live (5 s)
                                                                         ▲
                                         navigateur ──► Vite :5173 (proxy /api et /ws, jeton optionnel)
```

## Démarrer

```bash
# Schéma de base : géré par Alembic (depuis backend/)
../venv/bin/alembic upgrade head        # base neuve : crée tout ; base existante : applique les nouveautés

# Backend (depuis backend/) — écoute en local uniquement
../venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000

# Frontend (depuis frontend/)
npm install
npm run dev          # http://127.0.0.1:5173
# ou : npm run build && npm run preview
```

La collecte tourne indépendamment via `cybermorph-scan.timer` (systemd, toutes les 5 minutes).
Ordre d'un cycle : Nmap → ports locaux → ARP → rapprochement d'inventaire → alertes `fast.log` → MITRE → flux
`eve.json` → risque → snapshot → incidents.

> Après une mise à jour du code, **redémarrez uvicorn** : un serveur lancé sans `--reload` continue de servir
> l'ancienne API, et la nouvelle interface ne trouvera pas ses routes.

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
| `CYBERMORPH_LEARNING_HOURS` | backend | `48` | période d'apprentissage (inventaire et comportement), démarrée au premier cycle |
| `CYBERMORPH_ASSET_LEARNING_HOURS` | backend | `24` | apprentissage propre d'un actif découvert après la période globale |
| `CYBERMORPH_EVE_PATH` | backend | `/var/log/suricata/eve.json` | flux Suricata |
| `CYBERMORPH_LOCAL_NETWORKS` | backend | sous-réseau de la route par défaut | réseaux considérés comme locaux (liste CIDR) |

## Interface

| Vue | Contenu | Lien avec la scène 3D |
|---|---|---|
| Jumeau | posture, chemin le plus probable, changements d'inventaire, alertes en direct, actifs par risque | chemin principal en violet, incidents en rouge |
| Exposition | actifs critiques, points d'entrée qualifiés par des faits, points de blocage, mesures chiffrées (contrefactuel) | mesure sélectionnée isolée ; rayon d'impact depuis l'inspecteur |
| Inventaire | identité rapprochée (sources, confiance, conflits), autorisation, scanner, journal des changements | anneau ambre : non autorisé |
| Comportement | écarts à la référence (raisons, preuves, apprendre / acquitter), activités observées, santé du capteur | balise orange : écart ouvert |
| Alertes | 500 dernières alertes, filtre, recherche ; clic sur une ligne : chaîne de preuves (fast.log, flow_id, activité, conclusions) | clic sur un flux : la paire est tracée |
| Incidents | actifs / tous, étapes de propagation (possibles, confirmées) | la trace de l'incident est dessinée |
| Chemins | chemins vers les cibles à forte valeur, score minimal, nombre de sauts | le chemin sélectionné est isolé |
| ATT&CK | 14 tactiques, techniques suivies et observées, alertes corroborantes | — |
| Historique | score max et nombre de chemins, scans, reconstitution (couverture, changements) | « Rejouer » applique l'état historique, topologie comprise quand elle a été enregistrée |
| Simulations | nouvelle hypothèse, comparaison avant/après, historique | chemins nouveaux ou aggravés en violet pointillé |

Codes de la scène : anneau = rôle (routeurs au centre, serveurs, postes, inconnus) ; altitude et auréole = score
de risque ; cyan = trafic observé, bleu pointillé = voisinage ARP, ambre = corroboré par une alerte IDS, blanc =
relation seulement déclarée, estompé = non revu depuis 24 h ; violet = prédit ou simulé, rouge = incident.
Couronne = actif critique (pleine si déclarée), octogone violet = point de blocage, anneau ambre discontinu = non
autorisé, balise orange = écart comportemental ouvert. Les mouvements sont désactivés si le système demande moins
d'animations.

## Tests

```bash
cd backend && ../venv/bin/python -m unittest discover -s tests -t .   # moteurs, API, migrations — SQLite, jamais PostgreSQL
cd frontend && npm test && npm run lint && npm run build
```

## Notes d'exploitation

- Suricata : `fast.log` n'est plus vidé après lecture ; la position est mémorisée dans
  `backend/suricata_fast.offset` (compatible avec `copytruncate` de logrotate).
- Incidents : sans activité pendant une heure, un incident actif passe en `dormant` (rien n'est supprimé).
- Suricata `eve.json` : lu en lecture seule ; la position est mémorisée en base (`cybermorph_settings`) et la fin
  du fichier précédent est relue dans `eve.json.1.gz` à la rotation.
- Sauvegardes : `pg_dump` avant chaque migration dans `backups/` (non versionné).
- Le capteur CYBERMORPH est déclaré « scanner » : ses sondes vers le réseau local ne sont jamais apprises.
  Décocher ce drapeau (inspecteur) ferait apprendre les balayages Nmap comme du trafic normal.
