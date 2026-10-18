"""
Sous-ensemble volontairement restreint du catalogue MITRE ATT&CK (Enterprise), limité aux techniques que les
capteurs de CYBERMORPH (réseau, scan, IDS) peuvent étayer. Pas une prétention à couvrir tout ATT&CK.

Référentiel : https://attack.mitre.org/techniques/enterprise/ — identifiants et noms recopiés du référentiel officiel
(ATT&CK v15) ; un test vérifie que toute règle pointe vers une technique du catalogue au format valide.
"""

ATTACK_VERSION = "ATT&CK Enterprise v15"

TECHNIQUES = [
    {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
     "description": "Découverte des services réseau accessibles, souvent via scan de ports.", "platform": "Network"},
    {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
     "description": "Tentatives répétées d'authentification pour deviner des identifiants valides.", "platform": "Network"},
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
     "description": "Exploitation d'une vulnérabilité dans une application exposée (ex: injection SQL, XSS).", "platform": "Network"},
    {"technique_id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance",
     "description": "Sondage actif de l'infrastructure cible pour collecter des informations.", "platform": "Network"},
    {"technique_id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control",
     "description": "Utilisation de protocoles applicatifs standards pour dissimuler des communications C2.", "platform": "Network"},
    {"technique_id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery",
     "description": "Recherche des autres systèmes joignables sur le réseau (balayage d'hôtes).", "platform": "Network"},
]


# Règles de mapping : mots-clés recherchés dans (message, classification) de l'alerte,
# associés à une technique et un niveau de confiance. Ordre = priorité (premier match retenu).
# Une signature ne fait qu'INFÉRER une technique : le statut « observé » est réservé aux comportements mesurés.
MAPPING_RULES = [
    {"keywords": ["mysql", "non-allowed host", "sql server"], "technique_id": "T1046", "confidence": 0.6,
     "reason": "Tentative de connexion à un service de base de données non autorisée : reconnaissance de service."},
    {"keywords": ["brute", "login", "authentication failure"], "technique_id": "T1110", "confidence": 0.7,
     "reason": "Motif de tentatives d'authentification répétées."},
    {"keywords": ["sql injection", "sqli", "union select", "xss", "command injection"], "technique_id": "T1190",
     "confidence": 0.75, "reason": "Signature correspondant à une tentative d'exploitation applicative connue."},
    {"keywords": ["scan", "nmap", "port scan"], "technique_id": "T1595", "confidence": 0.5,
     "reason": "Motif réseau typique d'un scan de reconnaissance."},
]

# Comportements mesurés dans les flux (écarts du lot 3) : correspondance directe avec la définition de la technique
DEVIATION_RULES = {
    "port_scan": {"technique_id": "T1046", "confidence": 0.8,
                  "reason": "Nombreux ports distincts tentés sur une même cible, mesurés dans les flux Suricata."},
    "host_sweep": {"technique_id": "T1018", "confidence": 0.8,
                   "reason": "Nombreuses cibles distinctes sondées sur un même port, mesurées dans les flux Suricata."},
}

# En dessous, une alerte isolée ne suffit pas à affirmer la technique
MIN_OBSERVATIONS = 3
