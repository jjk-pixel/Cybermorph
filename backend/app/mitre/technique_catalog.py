"""
Sous-ensemble volontairement restreint du catalogue MITRE ATT&CK, limité aux
techniques réellement pertinentes pour les signaux que CYBERMORPH peut observer
(réseau, scan, IDS). Pas une prétention à couvrir tout ATT&CK.
"""

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
]


# Règles de mapping : mots-clés recherchés dans (message, classification) de l'alerte,
# associés à une technique et un niveau de confiance. Ordre = priorité (premier match retenu).
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
