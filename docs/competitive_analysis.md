# Étude comparative — plateformes de visibilité réseau, d'exposition et de jumeau numérique

*Rédigée le 18 octobre 2026 à partir de documentations publiques consultées le même jour. Les liens sont listés en fin de
document.*

## Méthode et conventions

- Seules les **capacités décrites dans des documents publics** sont présentées comme « documentées ». Les fiches produit
  et articles de tiers sont signalés comme tels.
- Les algorithmes de ces produits sont **propriétaires et non publiés**. Quand une capacité est expliquée ici, c'est
  au niveau du **principe** (ce que la documentation dit faire), jamais de l'implémentation. Toute reconstitution du
  « comment » est marquée **Hypothèse**.
- Aucun code, texte, icône ou schéma de ces produits n'est repris. Les mécanismes proposés pour CYBERMORPH sont
  conçus à partir de notions générales de l'état de l'art (graphes, centralité, apprentissage par fenêtre temporelle,
  rapprochement d'identifiants) et des capteurs open source déjà présents (Nmap, ARP, `ss`, Suricata).
- Légende des niveaux de source : **[Off]** documentation officielle de l'éditeur · **[Fiche]** fiche produit /
  datasheet · **[Tiers]** article tiers · **[Hyp]** hypothèse de travail.

---

## 1. Nozomi Networks Guardian

### Fonctionnalités observées

| Fonctionnalité | Ce qui est documenté | Niveau |
|---|---|---|
| Découverte passive des actifs et cartographie | Carte du réseau (actifs, liaisons, protocoles) construite par analyse passive du trafic ; module optionnel d'interrogation active à faible volume (« Smart Polling »). | [Fiche] |
| Modèle actif / nœud | Un *asset* représente un système physique local et peut regrouper un ou plusieurs *nodes* ; IP et MAC peuvent être vides (nœuds L2). Le nom de l'actif est choisi à partir de l'information « la plus fiable ». | [Off] SDK data model |
| Provenance et confiance par attribut | Pour chaque donnée d'un actif, l'interface montre sa **source** (saisie manuelle, import, DPI passive, Asset Intelligence, Smart Polling), sa granularité et sa **confiance**. | [Off] CMC, page *Details* |
| Apprentissage puis protection | Deux objectifs d'apprentissage : **réseau** (nœuds, liaisons, protocoles, codes de fonction) et **processus** (variables). Chacun est en mode *learning* ou *protecting*. | [Off] page *Learning* |
| Bascule dynamique | Une « fenêtre dynamique » configurable après laquelle un changement est considéré comme appris ; évaluation **par nœud et par segment** ; bascule automatique en protection. | [Off] |
| Revue opérateur | En protection, les éléments suspects sont ajoutés avec l'attribut *is learned* désactivé : l'opérateur peut les confirmer ou les supprimer. | [Off] |
| Détection adaptative vs stricte | *Adaptive* évalue les écarts globalement (ajouter un équipement semblable aux existants n'alerte pas) ; *Strict* signale tout écart. | [Off] |
| Réduction des faux positifs | Filtrage des anomalies bénignes à l'aide d'un corpus de profils d'actifs. | [Fiche] — non reproductible |

### Problème résolu
Savoir **ce qui existe** sur un réseau sans agent, puis **ce qui a changé** par rapport à un comportement appris,
sans noyer l'analyste sous des alertes au démarrage.

### Données et composants nécessaires
Copie du trafic (SPAN/TAP), dissection protocolaire profonde, base de connaissance d'empreintes, stockage des
liaisons apprises avec un statut appris/non appris, interface de revue.

### Correspondance dans CYBERMORPH (avant évolution)
Inventaire par scan actif Nmap, voisinage ARP ; **aucun** apprentissage, **aucune** provenance par attribut ; liaisons
« observées » limitées à un ancien import Zeek. Suricata `eve.json` est disponible sur la machine mais non exploité.

### Améliorations proposées
1. Journal d'observations **par attribut et par source** (IP, MAC, nom, OS, ports, services) avec premier/dernier vu.
2. Référence comportementale des **activités** (agrégats source → destination / protocole / port) issues des flux
   Suricata réels, avec une fenêtre d'apprentissage globale et par actif, puis statut *appris / nouveau / accepté*.
3. Revue opérateur : accepter un écart dans la référence ou l'acquitter.
4. Évaluation « adaptative » simple et explicable : un écart est moins grave si une activité identique (même
   service de destination) existe déjà dans la référence pour un autre actif.

**Complexité** : moyenne. **Dépendances** : `eve.json` (flow, dhcp, dns, mdns), migrations de schéma.

---

## 2. Microsoft Defender for IoT

### Fonctionnalités observées

| Fonctionnalité | Ce qui est documenté | Niveau |
|---|---|---|
| Inventaire riche | Colonnes : autorisation, type, classe, première/dernière activité, MAC, IPv4/IPv6, constructeur (via la MAC), OS, protocoles, **Importance** (Low/Medium/High), **Scanner device**, **Programming device**, emplacement réseau (local/routé), zone, VLAN, source de données. | [Off] *Device inventory* |
| Consolidation automatique | Les équipements vus **dans la même zone** avec une combinaison logique de caractéristiques similaires sont considérés comme un seul ; exemple : même IP **et** même MAC. Même MAC mais IP différentes : **pas** de fusion. | [Off] |
| Types particuliers | *Transient* (vu brièvement, à investiguer) ; *Unclassified* (aucune catégorie). | [Off] |
| Équipements non autorisés | Pendant l'apprentissage, tout est *autorisé* ; après, tout nouvel équipement est *nouveau* et *non autorisé* jusqu'à validation manuelle. | [Off] |
| Équipements importants | Marquage manuel ; utilisés comme **cibles** dans les simulations de vecteurs d'attaque et dans le score de sécurité. | [Off] |
| Apprentissage en 3 étapes | *Learning* (2 à 6 semaines ; tout nouvel équipement apprend 7 jours) → *Dynamic* (introduction progressive des alertes de violation de politique) → *Operational*. Les écarts à la référence (« Policy Violation ») ne sont pas émis en apprentissage. Action **Learn** : une activité apprise ne déclenche plus d'alerte. | [Off] *Create a learned baseline* |

### Problème résolu
Tenir un inventaire **dédoublonné et actionnable**, distinguer le connu de l'inconnu, et rattacher les alertes aux
équipements et à leur importance.

### Données et composants nécessaires
Capteur passif, notion de zone, règles de rapprochement d'identifiants, attributs éditables, état d'apprentissage.

### Correspondance dans CYBERMORPH (avant évolution)
Actif identifié **uniquement par l'IP** (contrainte d'unicité), type deviné par règles sans explication et
**réécrit à chaque scan**, pas d'importance, pas d'autorisation, pas de notion de scanner. Le nom affiché est parfois
**inventé** par heuristique (`vmware-server`).

### Améliorations proposées
1. Rapprochement **conservateur** inspiré de la règle documentée : IP + MAC = même actif ; MAC différente sur une IP
   connue = événement de changement d'identité (pas de fusion silencieuse) ; même MAC sur plusieurs IP = signalé.
2. Attributs déclarés par l'opérateur (type, criticité, autorisation) **qui ne sont jamais écrasés** par un scan.
3. Drapeau **scanner** : l'hôte CYBERMORPH est déclaré comme scanner pour que ses sondes Nmap ne polluent pas la
   référence comportementale.
4. Statut **nouveau / non autorisé** pour un actif apparu après la période d'apprentissage.

**Complexité** : moyenne. **Dépendances** : journal d'observations, migrations.

---

## 3. Microsoft Security Exposure Management

### Fonctionnalités observées

| Fonctionnalité | Ce qui est documenté | Niveau |
|---|---|---|
| Chemins d'attaque | Combinaison d'actifs et de techniques montrant comment un attaquant passe d'un **point d'entrée** à un **actif critique**. Générés à partir des données collectées ; leur nombre fluctue avec l'environnement. Ils peuvent être absents ou incomplets si les données ou les actifs critiques sont mal définis. | [Off] |
| Tableau de bord | Évolution du nombre de chemins, principaux **points de blocage** (*choke points*), scénarios, cibles et points d'entrée ; regroupement par point d'entrée, cible, criticité, niveau de risque. | [Off] |
| Points de blocage | Nœuds où plusieurs chemins convergent vers un actif critique ; les sécuriser bloque plusieurs chemins à la fois. | [Off] |
| Rayon d'impact (*blast radius*) | À partir d'un point de blocage, visualiser comment sa compromission affecterait d'autres actifs. | [Off] |
| Recommandations | Recommandations actionnables pour réduire les chemins. | [Off] |
| Actifs critiques | Catalogue de classifications prédéfinies, identification automatique, requêtes personnalisées, ajout manuel, **revue des classifications à faible confiance**, niveau de criticité affiché dans l'inventaire et utilisé dans les chemins. | [Off] *Critical asset management* |
| Fin de chemin | Les chemins sur site s'arrêtent aux actifs « fin de partie » (contrôleurs de domaine…). | [Off] |

### Problème résolu
Passer d'une liste de faiblesses à une **priorisation** : quelles corrections coupent le plus de chemins vers ce qui
compte vraiment.

### Données et composants nécessaires
Graphe d'exposition (actifs, relations, privilèges, vulnérabilités), criticité des actifs, moteur de recherche de
chemins, calcul de convergence.

### Correspondance dans CYBERMORPH (avant évolution)
Graphe orienté NetworkX avec poids explicables et niveau de preuve ; chemins vers « cibles à forte valeur » définies
grossièrement (serveur, routeur ou risque ≥ 50). **Pas** de criticité, de point d'entrée qualifié, de point de blocage,
de rayon d'impact ni de recommandation.

### Améliorations proposées
1. **Criticité** explicite (déclarée ou inférée, avec raison et confiance) ; cibles = actifs critiques.
2. **Points d'entrée qualifiés** à partir de faits : source d'un incident, actif exposé à l'extérieur (flux entrant
   externe observé), actif portant des services dangereux.
3. **Points de blocage** : nombre et score cumulé des chemins traversant un nœud intermédiaire.
4. **Rayon d'impact** : actifs atteignables depuis un nœud, avec le meilleur score de chemin.
5. **Recommandations calculées** : pour chaque liaison et nœud, réduction du score total des chemins si l'élément est
   retiré du graphe (simulation contrefactuelle), traduite en mesure concrète (filtrer un port, isoler un actif).

**Complexité** : faible à moyenne (calcul pur sur le graphe existant). **Dépendances** : criticité.

---

## 4. Cisco Cyber Vision

### Fonctionnalités observées

| Fonctionnalité | Ce qui est documenté | Niveau |
|---|---|---|
| Composants et équipements | Un *component* est un objet du réseau (interface d'automate, PC, adresse de diffusion) ; les *devices* regroupent les composants partageant des propriétés (IP, MAC) ; le type d'équipement est inféré des tags et propriétés protocolaires. | [Off] guide admin 5.1 |
| Flux et activités | Un *flow* est une communication unique ; un ensemble de flux forme une *activity* (ligne entre deux composants). | [Off] |
| Tags | Tags d'équipement (fonction, dérivés des propriétés) et tags d'activité (protocoles, calculés au niveau du flux puis résumés). | [Off] |
| Groupes et conduits | Regroupement des équipements, groupes imbriqués ; les activités entre groupes sont agrégées en **conduits**. | [Off] |
| Presets et Monitor mode | Un *preset* est un ensemble de critères (tags, groupes, réseaux, capteurs, score de risque) ; le **Monitor mode** montre l'évolution des comportements par rapport à une référence et affiche les **différences**. API : *baselines*, liste d'activités d'une référence. | [Off] guide + API |
| Score de risque | Indicateur 0–100 de santé et de criticité ; **Risque = Impact × Probabilité** ; impact selon le type et l'impact industriel du groupe ; probabilité selon activités, exposition externe et vulnérabilités. Pondérations non publiées. | [Off] |
| Vulnérabilités | Correspondance des propriétés avec une base de connaissance ; sévérité CVSS ; acquittement possible si atténuée. | [Off] |

### Problème résolu
Rendre lisible un réseau dense (agrégation flux → activités, groupes, tags) et suivre son **évolution** par rapport à
une référence validée.

### Données et composants nécessaires
Capteurs DPI, base de connaissance protocolaire et vulnérabilités, modèle composant/équipement, moteur de comparaison.

### Correspondance dans CYBERMORPH (avant évolution)
Zone (`zone`) présente dans le schéma mais jamais renseignée ; pas d'agrégation de flux ; `risk_score` additif à
5 critères, déjà explicable ; pas de base de vulnérabilités.

### Améliorations proposées
1. Modèle **flux → activité** : agréger les flux Suricata par (source, destination, protocole, port, protocole
   applicatif) avec compteurs, volumes, premier/dernier vu — c'est l'unité de la référence comportementale.
2. **Différences** de la référence présentées comme une liste d'écarts explicables, consultable et filtrable.
3. Score de risque : conserver le modèle additif explicable existant, l'enrichir de preuves (alertes, écarts) et de la
   criticité, et publier une **confiance** du score (complétude des données). Ne pas prétendre reproduire
   *Impact × Probabilité* de Cisco dont les poids ne sont pas publics.
4. Vulnérabilités : **bloqué** — aucune source de vulnérabilités n'est branchée. Interface d'intégration prévue
   (import de résultats d'un scanner tiers) mais **non alimentée**.

**Complexité** : moyenne. **Dépendances** : ingestion `eve.json`.

---

## Synthèse des principes retenus pour CYBERMORPH

| Principe | Inspiré de | Mise en œuvre open source |
|---|---|---|
| Chaque fait a une **source**, une date et une confiance | Nozomi (provenance par attribut) | table d'observations ; Nmap, ARP, `ss`, Suricata DHCP/mDNS/flows |
| Rapprochement **conservateur**, jamais de fusion silencieuse | Defender for IoT (IP+MAC, même zone) | règles explicites + événements de changement |
| Déclaré > observé > inféré, et le déclaré n'est jamais écrasé | Exposure Mgmt (classification manuelle et revue) | colonnes `*_source` |
| Apprendre puis signaler les **différences** | Nozomi, Defender, Cyber Vision | fenêtre d'apprentissage configurable, statut des activités |
| Le scanner du capteur ne fait pas partie du comportement normal | Defender (*Scanner device*) | drapeau `is_scanner`, sondes non abouties exclues |
| Chemins vers les **actifs critiques**, points de blocage, rayon d'impact, recommandations | Exposure Management | NetworkX + simulation contrefactuelle |
| Flux agrégés en activités | Cyber Vision | agrégat SQL incrémental |

### Ce que CYBERMORPH ne prétend pas faire
- Pas de dissection de protocoles industriels, ni de corpus d'empreintes, ni de profils d'actifs mondiaux.
- Pas de base de vulnérabilités : aucun score CVE n'est affiché tant qu'une source réelle n'est pas branchée.
- Pas de détection d'anomalies statistiques sur les volumes : la référence porte sur l'**existence** des activités
  (qui parle à qui, sur quoi), ce qui est vérifiable et explicable.

## Sources consultées

- Microsoft Learn — *Defender for IoT device inventory* :
  https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/device-inventory
- Microsoft Learn — *Create a learned baseline of OT traffic* :
  https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/ot-deploy/create-learned-baseline
- Microsoft Learn — *Work with attack paths in Microsoft Security Exposure Management* :
  https://learn.microsoft.com/en-us/security-exposure-management/work-attack-paths-overview
- Microsoft Learn — *Review attack paths* : https://learn.microsoft.com/en-us/security-exposure-management/review-attack-paths
- Microsoft Learn — *Overview of critical asset management* :
  https://learn.microsoft.com/en-us/security-exposure-management/critical-asset-management
- Cisco — *Cyber Vision Administrator Guide 5.1, Introduction* :
  https://www.cisco.com/c/en/us/td/docs/security/cyber_vision/b-cisco-cyber-vision-admin-guide-v5-1-0/m-introduction-to-cyber-vision.html
- Cisco DevNet — *Cyber Vision API (activities, baselines)* : https://developer.cisco.com/docs/cyber-vision/
- Nozomi Networks — *Learning* (documentation technique N2OS) :
  https://technicaldocs.nozominetworks.com/cmc/latest/products/n2os/topics/administration/settings/scp/c_n2os_admin_settings_scp_edit_learning.html
- Nozomi Networks — *Assets data model* (SDK N2OS) :
  https://technicaldocs.nozominetworks.com/products/n2os/topics/sdk/data-model/r_n2os-sdk_data_model_assets.html
- Nozomi Networks — *Asset details page* (CMC) : https://technicaldocs.nozominetworks.com/products/cmc/topics/assets/c_cmc_assets_details.html
- Nozomi Networks — fiches produit Guardian et Asset Intelligence (hébergées par des revendeurs, niveau [Fiche]).
