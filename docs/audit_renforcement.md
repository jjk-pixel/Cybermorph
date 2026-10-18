# CYBERMORPH — Audit et plan de renforcement du moteur

Audit réalisé le 18/10/2026 sur `main` (`e6d7d20`, v0.4.0), avant toute modification.

Il porte sur le code, sur la base PostgreSQL de production (lecture seule), sur `cybermorph.log` et sur l'exécution réelle des tests. Ce document est la référence du chantier. La section « Résultats » est complétée après chaque lot.

## Méthode

- **Code.** J'ai lu tous les modules backend : collecteurs, orchestrateur, inventaire, risque, exposition, graphe d'attaque, MITRE, incidents, simulation, API et modèles. J'ai aussi lu les contrats du frontend (`frontend/src/api/types.ts`, `client.ts`).
- **Base.** J'ai lancé des requêtes de comptage et lu les actifs, les relations et les alertes, sans aucune écriture.
- **Journaux.** J'ai relevé les 22 lignes `[ERROR]` de `cybermorph.log` et la durée des cycles (≈ 101 s toutes les 5 min).
- **Tests.** Les 72 tests backend passent (`unittest`), de même que les 19 tests frontend (`node --test`).

## Données réelles au moment de l'audit

| Table | Lignes | Remarque |
|---|---:|---|
| assets | 5 | .1 (Windows 11 + MySQL), .135 (capteur), .2 (NAT VMware), .254, .133 (hors ligne depuis le 12/10) |
| asset_observations | 43 | journal d'observations (lot 2) |
| network_connections | 10 | 4 flux Suricata, 4 voisinages ARP, **2 relations « detected » sans provenance** (historiques) |
| alerts | 412 | dominées par `ICMPv4 unknown code` (P3) et `ET SCAN Non-Allowed Host … MySQL` (P2) |
| alert_technique_mappings | 5 | une seule technique par alerte, premier mot-clé qui correspond |
| incidents / attack_path_steps | 28 / 94 | étapes « potentielles » créées pour chaque voisin du graphe |
| snapshots | 2 315 | un par cycle, sans rétention |
| communications / deviations | 14 / 0 | référence comportementale (lot 3) |

## Problèmes constatés, par domaine

Statuts : **[OK]** implémenté et vérifié, **[Partiel]**, **[Absent]**, **[Défaut]** (comportement incorrect constaté).

### 1. Inventaire et classification

- [Défaut] **Le type et le rôle sont confondus.** `classify_asset` applique la première règle « décisive ».
  - Un port 53 suffit à classer l'actif comme routeur.
  - Un port MySQL suffit à en faire un serveur.
  - Cas réel : **192.168.43.1** porte l'empreinte « Microsoft Windows 11 21H2 » et un seul port (3306). Il est classé `server`, alors que c'est un poste Windows qui héberge MySQL.
- [Défaut] **Une empreinte d'OS n'est jamais décisive face à un service.** Dans le sens inverse, des services sans rapport avec le type pèsent plus que l'OS observé.
- [Absent] **Les rôles ne sont pas modélisés** (serveur DNS, web, base de données, passerelle, SSH). Ils restent implicites dans le type.
- [Absent] **La route par défaut n'est pas utilisée.** C'est pourtant le seul fait fiable qui désigne la passerelle (`ip route` : `default via 192.168.43.2`).
- [Absent] **La version des services n'est pas conservée.** Nmap `-sV` renvoie le produit, la version et le CPE, mais seuls les noms de service sont stockés. Sans version, aucune correspondance de vulnérabilité n'est possible.
- [Partiel] **Les classes d'OS de Nmap sont ignorées** (`osclass.type`, `accuracy`). Seul le premier nom de `osmatch` est gardé.
- [Partiel] **Une adresse IP vaut une identité.**
  - Un changement d'adresse crée un nouvel actif, et l'ancien passe « down ».
  - Les conflits de MAC sont signalés (lot 2), mais aucune continuité d'identité n'est proposée.
- [OK] Journal d'observations par source, conflits d'identité, première et dernière observation, historique des changements (lot 2).

### 2. Découverte réseau (Nmap)

- [Absent] **La portée n'est ni validée ni configurable.** La cible est le sous-réseau de la route par défaut, sans contrôle de taille ni de nature (privé ou public).
- [Absent] **Aucun verrou contre les exécutions concurrentes.** Le timer systemd est `oneshot`, mais un lancement manuel (`python -m app.collectors.orchestrator`) peut chevaucher un cycle.
- [Absent] **Aucun arrêt propre.** Un SIGTERM interrompt la boucle en plein milieu, et aucun état « interrompu » n'est enregistré.
- [Défaut] **« Hors ligne » et « non observé » sont confondus.**
  - Tout actif absent d'un seul balayage `-sn` passe `down` immédiatement, même si un capteur passif (ARP, flux) le voit encore.
  - Si le balayage échoue, l'exception évite le marquage, mais rien ne trace l'échec dans les données.
- [Absent] **Aucun historique des exécutions de scan.** On ne peut pas distinguer le résultat d'un scan ponctuel de l'état estimé.
- [Absent] **Les changements de service sur un même port ne sont pas détectés** (seuls l'ouverture et la fermeture le sont).
- [OK] **Changements de ports :** ouverture immédiate, fermeture après un délai de grâce (lot 2).

### 3. Graphe réseau

- [Partiel] **Provenance partielle.** Elle est connue pour les flux Suricata et l'ARP. Les deux relations `detected` historiques n'ont aucune source : elles sont pourtant traitées comme des observations de premier rang.
- [Absent] **Ni confiance, ni période de validité par relation.** Seuls `last_seen` et l'expiration à 24 h des flux existent.
- [Défaut] **`POST /api/connections` accepte n'importe quel `connection_type`.** Un appel d'API peut donc créer une relation « observée » qui ne l'a jamais été.
- [OK] **Aucune connectivité déduite du sous-réseau.** Le graphe est reconstruit uniquement depuis la base.

### 4. Moteur de risque

- [Défaut] **Une donnée manquante augmente le risque.**
  - OS non identifié : +40 sur le critère « vulnérabilité OS ».
  - Absence de dernière observation : +100 sur la fraîcheur.
  - L'incertitude est confondue avec le risque.
- [Défaut] **L'indisponibilité est comptée deux fois.** Un actif hors ligne reçoit +50 en signal comportemental, puis une pénalité de fraîcheur. Or l'indisponibilité ne rend pas un actif plus vulnérable.
- [Défaut] **Une même alerte IDS peut être comptée deux fois** : comme signal « alerte IDS », puis comme facteur de sévérité de l'écart qu'elle aggrave.
- [Partiel] **L'explication est sous forme de chaînes.** Le facteur, le poids et la justification ne sont pas structurés. Les données manquantes et la date de calcul ne sont pas exposées.
- [Partiel] **Le calcul n'est pas déterministe à données égales**, parce que `datetime.now()` est appelé à l'intérieur.
- [Absent] **Aucun historique des scores** : le dernier écrase le précédent. Les snapshots ne gardent que le score.
- [Absent] **Le risque potentiel et une compromission constatée ne sont pas distingués.**
- [OK] **Seuils et bornes :** borné à 100, seuils 25 / 50 / 75 cohérents avec le graphe d'attaque.

### 5. Vulnérabilités

- [Absent] **Aucune capacité.**
  - Pas de CVE, pas de CVSS, pas de source.
  - Seul un marqueur « OS potentiellement obsolète » existe, appliqué à une estimation Nmap.

### 6. Graphe d'attaque

- [Défaut] **Une transition n'exige aucun service atteignable.** Un simple voisinage ARP vers un actif sans aucun port ouvert produit un saut d'attaque.
- [Absent] **Aucune précondition documentée par saut.**
  - Les incertitudes ne sont pas listées.
  - Rien ne distingue un chemin observé (corroboré par des détections) d'un chemin hypothétique.
- [Défaut] **La simulation « actif compromis » ajoute `declared` aux types de relation.** Une hypothèse prend alors l'apparence d'une déclaration fiable de l'opérateur.
- [Partiel] **Limites présentes (25 chemins par paire, 500 au total, profondeur 4), mais leur atteinte n'est pas signalée.** L'ordre des résultats à score égal dépend de l'itération.

### 7. Corrélation

- [Partiel] **Seule l'association alerte ↔ paire de la relation existe** (`compute_alert_score`).
  - Rien ne rapproche les alertes, les écarts et les changements d'un même actif.
  - Aucune séquence temporelle n'est repérée (par exemple un nouveau service suivi d'une activité).
- [Absent] **Aucune entité « corrélation »** : ni événements sources, ni raisonnement, ni confiance.

### 8. MITRE ATT&CK

- [Partiel] **Le rapprochement se fait par mot-clé, et seul le premier gagne.**
  - Il ne s'applique qu'aux alertes : les balayages mesurés dans les flux (lot 3) ne sont pas rattachés.
  - Aucun statut observé / inféré / non confirmé, aucun compteur d'observations, aucune distinction entre événement isolé et répété.
- [OK] **Les identifiants du catalogue sont valides** (T1046, T1110, T1190, T1595, T1071), et une confiance est enregistrée par rapprochement.

### 9. Supervision

- [Défaut] **`/api/health` renvoie toujours « healthy »**, même si les collecteurs échouent depuis des heures.
- [Absent] **Aucun état par collecteur** (dernière exécution, dernier succès, erreur, durée) ni du timer. Les erreurs n'existent que dans le fichier journal.
- [Partiel] **La fraîcheur n'est signalée que dans le score de risque.** Aucun indicateur « donnée obsolète » par actif ni « absence de données ≠ absence de menace ».

### 10. API et base

- [Défaut] **Les opérations d'écriture ne sont pas protégées sans jeton** : déclarations, relations, simulations, acquittements. L'instance du laboratoire écoute sur 0.0.0.0.
- [Partiel] **Validation incomplète.**
  - `limit` des alertes non borné.
  - Hypothèse de simulation en `dict` libre, avec erreurs 400 par `KeyError`.
  - Pas de pagination (`offset`).
- [Partiel] **Journaux texte non structurés**, avec des `print` mêlés.
- [OK] **Migrations et configuration.**
  - Alembic réversible (0001 à 0005), avec test d'aller-retour.
  - Configuration par variables d'environnement.
  - Le jeton n'est jamais exposé au navigateur.

### 11. Frontend

- [OK] **Toutes les vues consomment l'API réelle**, sans données fictives.
- [Absent] **Sur un actif :** rôles, versions de service, vulnérabilités, facteurs de risque structurés, données manquantes.
- [Absent] **Sur le graphe et la supervision :** préconditions des sauts, état de santé de la collecte, corrélations, statuts ATT&CK.

## Plan priorisé

Je priorise en mettant d'abord la fiabilité des données, puis l'explicabilité, puis les nouvelles capacités. Chaque lot :

- est commité séparément sur `feature/renforcement-moteur`, ce qui permet un retour arrière lot par lot ;
- inclut ses tests et, si besoin, une migration réversible ;
- est précédé d'une sauvegarde `pg_dump`.

| Lot | Contenu | Fichiers principaux | Schéma |
|---|---|---|---|
| A | Classification multi-indices : type ≠ rôle ≠ services, passerelle par la route, classes d'OS Nmap, `unknown` si les indices sont insuffisants ou contradictoires | `inventory/classification.py`, `exposure/criticality.py`, collecteurs Nmap et local | — (JSON `classification` enrichi) |
| B | Nmap fiable : portée validée, verrou, arrêt propre, journal des exécutions, hors ligne ≠ non observé, versions et CPE, changement de service, continuité d'identité si l'IP change | `collectors/nmap_collector.py`, `orchestrator.py`, `collectors/scope.py`, `inventory/observations.py` | 0006 : `collector_runs`, `assets.missed_scans` |
| C | Relations : confiance, période de validité, classe observée / inférée / déclarée, création API limitée aux déclarations | `models/network_connection.py`, `api/network_connections.py`, `graph_engine.py` | 0007 : colonnes de relation |
| D | Risque v2 : facteurs structurés, données manquantes ≠ risque, pas de double comptage, `now` injecté, historique, potentiel ≠ compromission | `risk/*`, `api/assets.py` | 0007 : `risk_history` |
| E | Vulnérabilités : inventaire logiciel (CPE), interface de sources (flux local, NVD optionnel), statuts de correspondance, aucune CVE inventée | `vulnerabilities/*`, `api/vulnerabilities.py` | 0008 : `vulnerability_findings` |
| F | Graphe d'attaque : préconditions par saut, service atteignable exigé, chemins observés / hypothétiques, limites signalées, ordre déterministe, correctif de la simulation | `attack_graph/graph_engine.py`, `simulation/simulation_engine.py`, `exposure_engine.py` | — |
| G | Corrélation et ATT&CK : corrélations avec événements sources, raisonnement et confiance ; preuves ATT&CK généralisées (alertes et écarts) avec statut | `correlation/engine.py`, `mitre/*`, `api/correlations.py` | 0009 : `correlations`, `technique_evidence` |
| H | Supervision : santé réelle des collecteurs, du timer, retards, fraîcheur par actif | `api/system.py`, `orchestrator.py` | (utilise `collector_runs`) |
| I | API : validation stricte, pagination, écritures réservées au jeton ou à la boucle locale, journaux JSON | `security.py`, routeurs, `logging_config.py` | — |
| J | Frontend : rôles, versions, vulnérabilités, facteurs de risque, préconditions, santé, corrélations, navigation événement → actif et relation | `frontend/src/**` | — |

Hors périmètre (demandé nulle part, ou impossible avec les capteurs disponibles) :

- exploitation réelle ou scans agressifs (non activés) ;
- probabilités de compromission (aucun modèle statistique validé) ;
- téléchargement automatique de flux CVE (désactivé par défaut, à brancher par l'opérateur).

## Résultats

Complété après chaque lot.
