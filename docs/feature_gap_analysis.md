# Analyse des écarts et feuille de route — CYBERMORPH

*État de référence : branche `feature/soc-3d-rebuild`, instantané `pre-feature-evolution` (18 octobre 2026), avant
toute modification de cette évolution.*

## Statuts

- **Opérationnel** : implémenté, alimenté par des données réelles, testé automatiquement.
- **Partiel** : une partie existe, mais elle est incomplète, non alimentée ou non testée.
- **Absent** : aucune implémentation.
- **Bloqué** : il manque des données ou un capteur, et le code seul ne peut pas combler l'écart.

> Une route d'API ne vaut pas une fonctionnalité. Par exemple, `POST /api/connections` permet de déclarer une
> relation, mais rien ne la distingue ensuite d'une relation observée dans l'interface ou dans le calcul des chemins.

## Capteurs et données réellement disponibles

| Source | État | Ce qu'elle apporte | Limites |
|---|---|---|---|
| Nmap `-sn` puis `-sV -O` (toutes les 5 min, root) | actif | IP, MAC, constructeur (OUI), OS probable, ports et services TCP | scan actif ; l'OS est une estimation ; aucun port UDP |
| ARP (`ip neigh`) | actif | voisinage L2 de l'hôte capteur | vue limitée à la table ARP locale |
| `ss -tulnp` | actif | ports en écoute de l'hôte CYBERMORPH | hôte local uniquement |
| Suricata `fast.log` | actif | alertes IDS | pas d'identifiant de flux |
| Suricata `eve.json` | **présent, non exploité** | événements `flow` (environ 20 000 en 25 min), `dhcp` (couple MAC/IP), `dns`, `mdns`, `tls` (SNI, JA3/JA4), `alert` | rotation quotidienne compressée ; environ 80 % des flux sont les sondes Nmap de CYBERMORPH lui-même |
| Zeek | installé (`/opt/zeek`), **non branché** | `conn.log` | collecteur présent mais jamais appelé ; capture limitée à 20 s |
| Base de vulnérabilités / CVE | **aucune** | — | toute fonctionnalité CVE est **bloquée** |
| Inventaire déclaratif (CMDB) | **aucun** | — | criticité et propriétaire sont à saisir dans CYBERMORPH |

Constat : dans `eve.json`, l'hôte capteur (192.168.43.135) émet environ 16 000 flux TCP sans réponse par cycle, issus
de ses propres scans Nmap. Une référence comportementale construite sans filtrer ces sondes serait fausse.

## Écarts par capacité

| # | Capacité | État avant évolution | Constat dans le code |
|---|---|---|---|
| 1 | Inventaire et rapprochement des identités | **Partiel** | Actif identifié par l'IP seule (`ip_address` unique). La MAC est réécrite à chaque scan sans historique, et un changement de MAC n'est pas détecté. Le nom est parfois inventé (`vmware-server`). DHCP et mDNS ne sont pas exploités. |
| 2 | Classification explicable avec confiance | **Partiel** | `guess_asset_type` applique des règles du type « premier qui correspond », sans raison ni confiance. Le type est réécrit à chaque scan, sans saisie manuelle possible. `local_ports_collector` force `server`. |
| 3 | Historique des observations et détection des changements | **Partiel** | Les `snapshots` (2 283 depuis le 5 septembre) gardent un résumé par cycle (id, ip, type, risque, statut), mais sans ports, sans MAC et sans topologie. Aucun événement de changement n'est produit. |
| 4 | Topologie : relations observées, inférées et déclarées | **Partiel** | `connection_type` accepte bien `detected`, `neighbor_detected`, `inferred` et `declared`. En pratique, seules les relations ARP sont alimentées. Les 3 relations « observées » viennent d'un import Zeek ponctuel et figé, et l'interface ne montre pas la provenance déclarée. |
| 5 | Référence comportementale | **Absent** | Les données existent (`eve.json`), mais il n'y a ni ingestion ni agrégation. |
| 6 | Détection explicable des écarts | **Absent** | Rien n'existe en dehors des alertes Suricata. |
| 7 | Risque tenant compte des preuves, de la criticité et de l'exposition | **Partiel** | Le modèle à 5 critères est déjà explicable (détail par critère et facteurs). En revanche, la criticité se déduit du type seul, les alertes et les écarts n'entrent pas dans le score, et aucune confiance n'est donnée. |
| 8 | Chemins d'attaque vers les actifs critiques | **Partiel** | Chemins calculés et testés, avec niveau de preuve. Mais une cible est simplement « un serveur, un routeur ou un risque ≥ 50 » : il n'y a ni criticité ni point d'entrée qualifié. |
| 9 | Points de blocage et mesures de réduction | **Absent** | — |
| 10 | Reconstitution historique | **Partiel** | La relecture d'un snapshot existe dans l'interface, mais seuls les scores et statuts sont rejoués : pas la topologie, pas les ports. |
| 11 | Corrélation et traçabilité vers les preuves | **Partiel** | Les maillons alerte → liaison → chemin et alerte → incident → étapes existent. Il manque le lien vers la ligne source du capteur, et aucune corrélation avec les flux observés. |
| 12 | Visualisations intégrées au jumeau | **Partiel** | La scène 3D affiche le risque, les liaisons par niveau de preuve, les chemins et les incidents. Il manque la criticité, les points de blocage, les écarts et la provenance des attributs. |
| — | Vulnérabilités (CVE) | **Bloqué** | Aucune source. |
| — | Zones et segmentation | **Bloqué partiellement** | Un seul sous-réseau est observé. Le champ `zone` existe mais n'est jamais renseigné. |
| — | Migrations de schéma | **Absent** | Alembic figure dans `requirements.txt` sans être configuré. Le schéma est créé par `create_all` au démarrage de l'API, ce qui n'ajoute jamais de colonne. |

## Priorisation

La valeur est estimée pour un analyste SOC sur ce lab. La difficulté tient compte du code existant. Le prérequis
indique ce qui doit exister avant de commencer.

| Amélioration | Valeur | Difficulté | Prérequis | Lot |
|---|---|---|---|---|
| Migrations Alembic (référence et `stamp` de la base existante) | indispensable | faible | sauvegarde `pg_dump` | 1 |
| Criticité déclarée ou inférée, avec raison et confiance | élevée | faible | migrations | 1 |
| Classification explicable et type déclaré non écrasé | élevée | faible | migrations | 1 |
| Chemins vers les actifs critiques, points d'entrée qualifiés | élevée | faible | criticité | 1 |
| Points de blocage, rayon d'impact, recommandations contrefactuelles | **très élevée** | moyenne | criticité | 1 |
| Journal d'observations par source et attribut | élevée | moyenne | migrations | 2 |
| Rapprochement des identités (IP + MAC, DHCP, mDNS) et changements | élevée | moyenne | journal | 2 |
| Drapeau scanner, actifs nouveaux ou non autorisés | élevée | faible | journal | 2 |
| Ingestion des flux `eve.json` et agrégation en activités | **très élevée** | moyenne | migrations | 3 |
| Topologie dynamique observée / inférée / déclarée | élevée | faible | activités | 3 |
| Référence comportementale et écarts explicables | **très élevée** | moyenne | activités, drapeau scanner | 3 |
| Risque enrichi (alertes, écarts, criticité, confiance) | élevée | faible | écarts | 3 |
| Topologie dans les snapshots et reconstitution historique | moyenne | faible | activités | 4 |
| Traçabilité vers la ligne source (fichier, position) et corrélation alerte ↔ activité | moyenne | faible | activités | 4 |
| Vues Inventaire, Comportement et Exposition dans le jumeau | élevée | moyenne | lots 1 à 4 | à chaque lot |
| Vulnérabilités (CVE) | élevée | — | **source à brancher** | interface prévue, non alimentée |
| Zeek | moyenne | moyenne | décision d'exploitation (capture continue) | hors lots, documenté |

## Feuille de route

Chaque lot se termine par les tests, la vérification des contrats d'API, l'intégration dans le frontend et la mise à
jour de ce document (section « Résultats des lots »).

1. **Lot 1 — Exposition**
   - Fondations : Alembic.
   - Actifs : criticité, classification explicable.
   - Chemins : chemins vers les actifs critiques, points d'entrée, points de blocage, rayon d'impact et
     recommandations.
   - Interface : vue « Exposition » et couronne de criticité dans la scène.
2. **Lot 2 — Inventaire et identités**
   - Journal d'observations et rapprochement des identités.
   - Événements de changement.
   - Drapeau scanner et autorisation des actifs.
   - Interface : vue « Inventaire ».
3. **Lot 3 — Comportement**
   - Ingestion de `eve.json`, activités et topologie dynamique.
   - Référence comportementale, écarts et revue par l'opérateur.
   - Risque enrichi.
   - Interface : vue « Comportement » et écarts dans la scène.
4. **Lot 4 — Mémoire et traçabilité**
   - Topologie historisée et reconstitution.
   - Références aux preuves sources et corrélation alerte ↔ activité.

---

## Résultats des lots

*(Complété au fil de la livraison.)*

### Lot 1 — Fondations et exposition (livré le 18/10/2026)

**Livré**
- **Alembic** :
  - révision de référence `0001_baseline`, identique au schéma en service (colonne héritée `alerts.detected_at`
    comprise) ;
  - la base existante a été marquée (`stamp`), sans être recréée ;
  - `0002_asset_exposure` ajoute uniquement des colonnes nullables ;
  - sauvegarde `pg_dump` préalable dans `backups/` ;
  - `create_all` n'est plus appelé au démarrage de l'API.
- **Classification explicable** (`app/inventory/classification.py`) :
  - mêmes décisions que l'ancien `guess_asset_type`, mais chaque règle est publiée comme preuve pour ou contre ;
  - la confiance tient compte des preuves concordantes et contradictoires, et les types concurrents sont listés ;
  - un type déclaré n'est plus jamais écrasé par Nmap ni par le collecteur local.
- **Criticité** (`app/exposure/criticality.py`) :
  - déclarée (prioritaire) ou inférée, avec raisons et confiance ;
  - l'échelle de points reprend exactement l'ancienne échelle par type : **aucun score existant n'a changé**
    (vérifié sur les 5 actifs réels).
- **Exposition** (`app/exposure/exposure_engine.py`, `GET /api/exposure`, `GET /api/exposure/blast-radius/{id}`) :
  - cibles critiques ;
  - points d'entrée qualifiés par des faits (incident, alerte IDS émise, service à risque) ; sinon le chemin est
    marqué « hypothèse » ;
  - points de blocage ;
  - rayon d'impact ;
  - recommandations contrefactuelles chiffrées.
- **Déclarations** : `PATCH /api/assets/{id}` modifie la criticité et le type ; `null` rend la main à l'inférence, et le
  risque est recalculé immédiatement.
- **Interface** :
  - vue « Exposition » ;
  - inspecteur avec preuves de classification, formulaire de déclaration et rayon d'impact ;
  - scène 3D : couronne sur les actifs critiques (pleine si la criticité est déclarée, estompée si elle est inférée),
    octogone violet sur les points de blocage, rayon d'impact en violet pointillé, mise en avant de la mesure
    sélectionnée.

**Vérifié**
- 37 tests backend, dont une migration `upgrade head` sur une base vide comparée aux modèles, puis `downgrade`.
- Contrats d'API :
  - lectures sur la base réelle ;
  - écritures `PATCH` uniquement sur une instance SQLite dédiée ;
  - erreurs 404 et 422 ;
  - CORS.
- 39 vérifications d'interface sur données réelles.
- Les cycles systemd continuent de se terminer sans erreur.

**Constats sur les données réelles**
- 192.168.43.1 est classé serveur (MySQL ouvert), mais son empreinte d'OS est Windows 11 : la confiance tombe à
  0,35 et « poste » est proposé comme alternative.
- Aucun point de blocage : les 4 chemins actuels sont directs (1 saut).
- La mesure la plus efficace consiste à filtrer `tcp/22` de .1 vers .135, ce qui ferait baisser de 49 % le score
  d'exposition total.

**Limites**
- Les recommandations sont des estimations sur le modèle.
- Sans base de vulnérabilités, l'exposition se lit dans les services ouverts.
- La criticité inférée d'un serveur reste générique tant que l'opérateur ne la déclare pas.

### Lot 2 — Inventaire et identités (livré le 18/10/2026)

**Livré**
- Migration `0003_inventory` : tables `asset_observations`, `asset_changes` et `cybermorph_settings`, plus des
  colonnes d'autorisation et de scanner.
- **Journal d'observations** : chaque fait est enregistré par attribut et par source :
  - Nmap : MAC, constructeur, OS, ports, services ;
  - mDNS, DNS ou heuristique : nom d'hôte ;
  - hôte local : `ss` et nom ;
  - table ARP : MAC ;
  - Suricata DHCP (lot 3) : MAC et nom.
- **Détection des changements une fois par cycle**, et non à chaque collecteur, pour éviter les faux changements
  entre Nmap et `ss`. Délai de grâce de 12 min avant de déclarer un port fermé, et seulement si la même source a
  bien sondé l'actif. Le premier passage sert de référence et ne produit aucun changement.
- **Rapprochement conservateur des identités** :
  - une MAC différente sur une même IP produit un conflit d'identité ;
  - une même MAC sur plusieurs IP est signalée une fois par 24 h ;
  - rien n'est jamais fusionné automatiquement.
- **Confiance d'identité** : elle dépend de l'IP, de la MAC observée et corroborée, d'un nom annoncé ou résolu (un nom
  déduit ne compte pas) et des conflits ouverts.
- **Autorisation** :
  - les actifs présents pendant l'apprentissage (48 h, `CYBERMORPH_LEARNING_HOURS`) sont autorisés ;
  - un actif apparu ensuite est « non autorisé » jusqu'à validation ;
  - le statut est déclarable via `PATCH`.
- **Drapeau scanner** : il est posé automatiquement sur l'hôte CYBERMORPH.
- **API** : `GET /api/inventory/`, `GET /api/inventory/{id}`, `GET /api/changes/`,
  `POST /api/changes/{id}/acknowledge`.
- **Interface** :
  - vue « Inventaire » (identité, sources, statut, journal filtrable) ;
  - section « Identité » de l'inspecteur ;
  - panneau « Changements d'inventaire » dans la vue d'ensemble ;
  - anneau ambre sur les actifs non autorisés.

**Constats sur les données réelles**
- La MAC de .1 est corroborée par Nmap, ARP et DHCP.
- DHCP a fourni la MAC de .135, que Nmap ne voit pas pour l'hôte local.
- Les noms `vmware-*` sont désormais identifiés comme « déduits ».
- Premier changement réel : « port 8010 ouvert sur .135 », qui est l'instance de test lancée pour vérifier l'API.

### Lot 3 — Comportement (livré le 18/10/2026)

**Livré**
- Migration `0004_behavior` :
  - tables `communications` et `deviations` ;
  - colonne `network_connections.source` ;
  - renommage sans perte de `assets.authorization` en `authorization_status` (mot réservé PostgreSQL).
- **Lecture incrémentale d'`eve.json`** :
  - la position est mémorisée en base ;
  - à la rotation, la fin de l'ancien fichier est relue dans `eve.json.1.gz` (vérification par empreinte) ;
  - les lignes incomplètes ne sont jamais lues ;
  - le fichier n'est jamais modifié.
- **Activités** : les flux sont agrégés par source, destination (ou portée), protocole, port et protocole
  applicatif, avec compteurs, volumes, échantillons de destinations externes, SNI TLS et `flow_id`.
- **Sondes exclues** :
  - les flux de l'actif scanner vers le réseau local ne sont jamais appris ;
  - une tentative TCP sans SYN+ACK n'est pas une communication. Un RST n'est pas une réponse : la passerelle NAT
    VMware répond RST sur tous les ports.
- **Référence et écarts explicables** :
  - pendant l'apprentissage, une activité nouvelle est apprise ; ensuite, c'est un écart ;
  - un actif découvert après l'apprentissage dispose de 24 h pour apprendre ses propres activités ;
  - la sévérité dépend de facteurs explicites (port à risque, cible critique, source non autorisée, sortie
    Internet sur un port inhabituel, alerte IDS sur la même paire) ;
  - elle est atténuée si la même activité est déjà connue depuis un autre actif.
- **Balayages** : ports d'une cible (≥ 15) ou hôtes sur un même port (≥ 8), uniquement depuis un actif non scanner.
- **Hôte hors inventaire** : une IP locale vue par Suricata mais jamais par Nmap est signalée.
- **Identité** : le DHCP fournit la MAC, et l'adresse IPv6 lien-local EUI-64 est rattachée à l'actif qui porte cette
  MAC.
- **Topologie observée** : un flux établi entre deux actifs crée ou rafraîchit une relation « observée », qui
  expire après 24 h sans flux. Le flux live publie, pour chaque relation, sa provenance (observée, inférée,
  déclarée, IDS) et sa dernière observation.
- **Risque** :
  - le critère « signaux comportementaux » intègre les écarts ouverts, les alertes IDS émises ou reçues en 24 h et
    le statut non autorisé ;
  - une **confiance du score** est publiée (OS, MAC, visibilité dans les flux, fraîcheur) ;
  - le risque est désormais calculé après la lecture des alertes et des flux.
- **API** : `GET /api/behavior/`, `/communications`, `/deviations`, `POST /deviations/{id}/learn`, `POST /deviations/{id}/acknowledge`.
- **Interface** :
  - vue « Comportement » : écarts avec raisons et preuves, activités, santé du capteur, méthode ;
  - scène 3D : balise orange sur les actifs en écart, relation déclarée en blanc, relation non revue depuis 24 h
    estompée ;
  - inspecteur : provenance et âge de chaque relation.

**Constats sur les données réelles (premier passage)**
- 50 116 flux lus, dont 49 981 sondes du capteur écartées.
- 9 activités apprises :
  - navigation de .1 vers l'interface (:5173) ;
  - DHCP de .1 vers .254 ;
  - SSDP, mDNS et LLMNR en multidiffusion ;
  - NTP et TLS de .135 vers Internet (`api.anthropic.com`, `datadoghq.com`, `downloads.claude.ai`).
- Variations de risque dues aux alertes IDS : .1 passe de 20,5 à 29,5 (émetteur d'alertes sévères en 24 h) et
  .135 de 28,0 à 32,5 (cible de ces alertes).

**Limites**
- Le trafic réel hors capteur est très faible sur ce lab : la référence est mince mais authentique.
- L'hôte capteur est à la fois scanner et serveur. Ses communications locales ne sont pas apprises, faute de pouvoir
  distinguer ses sondes de son trafic normal ; seules ses sorties vers l'extérieur le sont.
- Pas de détection sur les volumes.
- Les seuils de balayage sont fixes.
- Un cycle d'orchestration (00:55) a échoué pendant la migration `0004`, car le modèle a été modifié quelques
  secondes avant l'application de la migration ; aucune donnée n'a été perdue.
