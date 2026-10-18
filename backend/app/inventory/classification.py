"""
Classification explicable des actifs, multi-indices (modèle 2).

Trois notions distinctes, jamais déduites l'une de l'autre sans preuve :
- le **type** de l'équipement (pc = poste de travail, server, router, firewall, iot, unknown) ;
- ses **rôles** réseau (serveur DNS, serveur web, base de données, passerelle…), déduits des services ;
- les **services** exposés eux-mêmes (port, protocole, produit, version), tels qu'observés.

Un service n'est qu'un indice faible du type : un poste Windows peut héberger MySQL sans devenir un serveur dédié,
un port 53 ouvert ne prouve pas qu'un équipement est un routeur, une empreinte Linux ne prouve pas un serveur.
Chaque indice porte un poids, une raison lisible et sa source ; les scores par type sont publiés. Le type n'est
attribué que si le meilleur score atteint ASSIGN_THRESHOLD et devance le suivant d'au moins DECISION_MARGIN ;
sinon l'actif reste « unknown », avec les candidats en alternatives.

Ce module est pur (aucun accès base) : il est testé directement.
"""

MODEL_VERSION = 2

TYPE_LABEL = {
    "pc": "poste de travail", "server": "serveur", "router": "routeur", "firewall": "pare-feu",
    "iot": "objet connecté", "unknown": "inconnu",
}

NETWORK_VENDORS = ["cisco", "mikrotik", "ubiquiti", "tp-link", "netgear", "juniper", "aruba", "zyxel", "d-link"]
FIREWALL_VENDORS = ["fortinet", "palo alto", "sophos", "watchguard", "check point", "sonicwall", "stormshield"]
IOT_VENDORS = ["espressif", "tuya", "hikvision", "dahua", "axis communications", "sonos", "philips lighting",
               "signify", "shelly", "nest labs", "ring", "roku"]
VIRTUAL_VENDORS = ["vmware", "qemu", "virtualbox", "oracle virtualbox", "microsoft hyper-v", "parallels", "xensource"]

DATABASE_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 27017: "MongoDB", 6379: "Redis"}
DATABASE_SERVICES = {"mysql", "postgres", "postgresql", "ms-sql-s", "oracle", "mongod", "mongodb", "redis", "redis-server"}
WEB_PORTS = {80, 443, 8000, 8080, 8443}
WEB_SERVICES = {"http", "https", "http-proxy", "http-alt", "ssl/http", "uvicorn", "nginx", "apache2", "httpd"}
MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
PRINTER_PORTS = {515, 631, 9100}
IOT_PORTS = {554: "RTSP (caméra)", 1883: "MQTT", 8883: "MQTT/TLS", 5683: "CoAP"}

# Services typiques d'un serveur ; chacun n'apporte qu'un indice faible, plafonné
SERVER_SERVICE_WEIGHT = 0.15
SERVER_SERVICE_CAP = 0.6

ROUTER_OS_MARKERS = ["router", "nat device", "switch", "routeros", "gateway", "wap", "access point"]
FIREWALL_OS_MARKERS = ["firewall", "fortios", "pfsense", "opnsense", "pan-os"]
CLIENT_OS_MARKERS = ["windows 11", "windows 10", "windows 8", "windows 7", "windows xp", "windows vista",
                     "mac os", "macos", "os x", "android", "ios"]
SERVER_OS_MARKERS = ["windows server"]
IOT_OS_MARKERS = ["printer", "webcam", "camera", "embedded", "media device", "game console", "phone", "smart tv"]

# Classes d'OS de Nmap (osclass.type) → type d'équipement
OSCLASS_TYPES = {
    "router": "router", "broadband router": "router", "switch": "router", "wap": "router", "bridge": "router",
    "firewall": "firewall", "security-misc": "firewall",
    "printer": "iot", "webcam": "iot", "media device": "iot", "game console": "iot", "phone": "iot",
    "power-device": "iot", "storage-misc": "iot",
    # « specialized », « general purpose », « terminal »… couvrent des équipements trop variés : pas d'indice de type
}
OS_WEIGHT = 0.55
DEFAULT_OS_ACCURACY = 0.85   # empreinte sans précision connue (données antérieures)

ASSIGN_THRESHOLD = 0.4
DECISION_MARGIN = 0.1
CONFIDENCE_FLOOR = 0.1
CONFIDENCE_CEILING = 0.95
UNKNOWN_CONFIDENCE = 0.2

ROLE_LABEL = {
    "gateway": "Passerelle", "dns_server": "Serveur DNS", "web_server": "Serveur web",
    "database_server": "Base de données", "ssh_server": "Administration SSH", "remote_desktop": "Bureau à distance",
    "file_sharing": "Partage de fichiers", "mail_server": "Serveur de messagerie", "printer": "Impression",
    "telnet": "Administration Telnet", "ftp_server": "Serveur FTP",
}


def _evidence(type_: str, weight: float, reason: str, source: str) -> dict:
    return {"type": type_, "weight": round(weight, 3), "reason": reason, "source": source}


def _os_accuracy(os_classes: list[dict] | None) -> float:
    if not os_classes:
        return DEFAULT_OS_ACCURACY
    try:
        return max(min(float(c.get("accuracy") or 0) / 100, 1.0) for c in os_classes) or DEFAULT_OS_ACCURACY
    except (TypeError, ValueError):
        return DEFAULT_OS_ACCURACY


def _os_evidence(os_detected: str | None, os_classes: list[dict] | None) -> tuple[list[dict], list[str]]:
    """Indices tirés de l'empreinte d'OS (estimation Nmap) : leur poids suit la précision annoncée par Nmap."""
    hits, notes = [], []
    os_l = (os_detected or "").lower()
    accuracy = _os_accuracy(os_classes)
    source = f"nmap · empreinte OS ({accuracy:.0%})"

    for c in os_classes or []:
        mapped = OSCLASS_TYPES.get((c.get("type") or "").lower())
        if mapped:
            hits.append(_evidence(mapped, OS_WEIGHT * accuracy, f"Classe d'OS Nmap « {c.get('type')} » ({os_detected or c.get('osfamily')})", source))
            return hits, notes

    if not os_l:
        return hits, notes
    if any(m in os_l for m in FIREWALL_OS_MARKERS):
        hits.append(_evidence("firewall", OS_WEIGHT * accuracy, f"Empreinte d'OS de pare-feu ({os_detected})", source))
    elif any(m in os_l for m in ROUTER_OS_MARKERS):
        hits.append(_evidence("router", OS_WEIGHT * accuracy, f"Empreinte d'OS d'équipement réseau ({os_detected})", source))
    elif any(m in os_l for m in SERVER_OS_MARKERS):
        hits.append(_evidence("server", OS_WEIGHT * accuracy, f"Empreinte d'OS serveur ({os_detected})", source))
    elif any(m in os_l for m in CLIENT_OS_MARKERS):
        hits.append(_evidence("pc", OS_WEIGHT * accuracy, f"Empreinte d'OS de poste client ({os_detected})", source))
    elif any(m in os_l for m in IOT_OS_MARKERS):
        hits.append(_evidence("iot", OS_WEIGHT * accuracy, f"Empreinte d'OS d'objet connecté ({os_detected})", source))
    elif "linux" in os_l or "bsd" in os_l or "unix" in os_l:
        notes.append(f"Empreinte {os_detected} : système généraliste, n'indique ni un serveur ni un poste")
    return hits, notes


def _server_services(ports: set[int], services_l: set[str]) -> list[str]:
    found = []
    if 22 in ports or "ssh" in services_l:
        found.append("SSH")
    if ports & WEB_PORTS or services_l & WEB_SERVICES:
        found.append("web")
    if any(p in ports for p in DATABASE_PORTS) or services_l & DATABASE_SERVICES:
        found.append("base de données")
    if ports & MAIL_PORTS or services_l & {"smtp", "imap", "pop3", "submission", "smtps", "imaps", "pop3s"}:
        found.append("messagerie")
    if 389 in ports or 636 in ports or "ldap" in services_l:
        found.append("annuaire LDAP")
    if 21 in ports or "ftp" in services_l:
        found.append("FTP")
    return found


def evaluate_evidence(
    open_ports: list[int], services: list[str], vendor: str | None, os_detected: str | None,
    os_classes: list[dict] | None = None, is_gateway: bool = False,
) -> tuple[list[dict], list[str]]:
    """Tous les indices de type, et les notes (faits observés qui n'indiquent aucun type)."""
    ports = set(open_ports)
    services_l = {s.lower() for s in services if s}
    vendor_l = (vendor or "").lower()
    hits, notes = [], []

    if is_gateway:
        hits.append(_evidence("router", 0.7, "Passerelle par défaut du capteur (table de routage)", "ip route · hôte capteur"))
    if any(v in vendor_l for v in FIREWALL_VENDORS):
        hits.append(_evidence("firewall", 0.4, f"Constructeur de pare-feu ({vendor})", "nmap · OUI MAC"))
    elif any(v in vendor_l for v in NETWORK_VENDORS):
        hits.append(_evidence("router", 0.35, f"Constructeur d'équipements réseau ({vendor})", "nmap · OUI MAC"))
    elif any(v in vendor_l for v in IOT_VENDORS):
        hits.append(_evidence("iot", 0.4, f"Constructeur d'objets connectés ({vendor})", "nmap · OUI MAC"))
    elif any(v in vendor_l for v in VIRTUAL_VENDORS):
        notes.append(f"Carte réseau virtuelle ({vendor}) : n'indique pas le type de l'équipement")

    os_hits, os_notes = _os_evidence(os_detected, os_classes)
    hits += os_hits
    notes += os_notes

    server_like = _server_services(ports, services_l)
    if server_like:
        weight = min(SERVER_SERVICE_WEIGHT * len(server_like), SERVER_SERVICE_CAP)
        hits.append(_evidence("server", weight, f"Services de type serveur exposés ({', '.join(server_like)}) : indice faible, un poste peut aussi en héberger", "nmap · ports"))
    windows = sorted(p for p in ports if p in (3389, 445, 139))
    if windows:
        hits.append(_evidence("pc", 0.2, f"RDP/SMB exposé ({', '.join(map(str, windows))}) : fréquent sur les postes Windows", "nmap · ports"))
    printers = sorted(ports & PRINTER_PORTS)
    if printers:
        hits.append(_evidence("iot", 0.4, f"Ports d'impression ({', '.join(map(str, printers))})", "nmap · ports"))
    iot = [label for port, label in IOT_PORTS.items() if port in ports]
    if iot:
        hits.append(_evidence("iot", 0.3, f"Protocoles d'objets connectés ({', '.join(iot)})", "nmap · ports"))
    if (53 in ports or "domain" in services_l) and not is_gateway:
        notes.append("Service DNS (53) exposé : rôle de résolveur, ne prouve pas un routeur")
    return hits, notes


def infer_roles(open_ports: list[int], services: list[str], is_gateway: bool = False) -> list[dict]:
    """Rôles réseau déduits des services observés. Le rôle ne détermine pas le type de l'équipement."""
    ports = set(open_ports)
    services_l = {s.lower() for s in services if s}
    roles = []

    def add(role: str, reason: str, port_seen: bool, name_seen: bool, source: str = "nmap · ports"):
        # Port et nom de service concordants (détection de version Nmap) : plus sûr qu'un numéro de port seul
        confidence = 0.9 if port_seen and name_seen else 0.6
        roles.append({"role": role, "label": ROLE_LABEL[role], "confidence": confidence, "reasons": [reason], "source": source})

    if is_gateway:
        roles.append({"role": "gateway", "label": ROLE_LABEL["gateway"], "confidence": 0.9,
                      "reasons": ["Passerelle par défaut du capteur (table de routage)"], "source": "ip route · hôte capteur"})
    if 53 in ports or "domain" in services_l:
        add("dns_server", "Port 53 ouvert (DNS)", 53 in ports, "domain" in services_l)
    web = sorted(ports & WEB_PORTS)
    if web or services_l & WEB_SERVICES:
        add("web_server", f"Service web ({', '.join(map(str, web)) or 'nom de service'})", bool(web), bool(services_l & WEB_SERVICES))
    db = database_ports(open_ports, services)
    if db:
        add("database_server", f"Base de données : {', '.join(db)}",
            any(p in ports for p in DATABASE_PORTS), bool(services_l & DATABASE_SERVICES))
    if 22 in ports or "ssh" in services_l or "sshd" in services_l:
        add("ssh_server", "SSH (22)", 22 in ports, bool(services_l & {"ssh", "sshd"}))
    if 3389 in ports or "ms-wbt-server" in services_l:
        add("remote_desktop", "RDP (3389)", 3389 in ports, "ms-wbt-server" in services_l)
    if ports & {139, 445} or services_l & {"microsoft-ds", "netbios-ssn", "smbd"}:
        add("file_sharing", "SMB/NetBIOS (139, 445)", bool(ports & {139, 445}), bool(services_l & {"microsoft-ds", "netbios-ssn", "smbd"}))
    mail = sorted(ports & MAIL_PORTS)
    if mail:
        add("mail_server", f"Messagerie ({', '.join(map(str, mail))})", True, bool(services_l & {"smtp", "imap", "pop3", "submission", "couriertcpd"}))
    if 23 in ports or "telnet" in services_l:
        add("telnet", "Telnet (23) : administration en clair", 23 in ports, "telnet" in services_l)
    if 21 in ports or "ftp" in services_l:
        add("ftp_server", "FTP (21)", 21 in ports, "ftp" in services_l)
    printers = sorted(ports & PRINTER_PORTS)
    if printers:
        add("printer", f"Impression ({', '.join(map(str, printers))})", True, bool(services_l & {"ipp", "jetdirect", "printer"}))
    return roles


def classify_asset(
    open_ports: list[int], services: list[str], vendor: str | None, os_detected: str | None,
    os_classes: list[dict] | None = None, is_gateway: bool = False, service_details: list[dict] | None = None,
) -> dict:
    hits, notes = evaluate_evidence(open_ports, services, vendor, os_detected, os_classes, is_gateway)

    scores: dict[str, float] = {}
    for h in hits:
        scores[h["type"]] = scores.get(h["type"], 0.0) + h["weight"]
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    best, best_score = ranked[0] if ranked else ("unknown", 0.0)
    second_score = ranked[1][1] if len(ranked) > 1 else 0.0

    if best_score < ASSIGN_THRESHOLD:
        decision = "insufficient"
    elif best_score - second_score < DECISION_MARGIN:
        decision = "contradictory"
    else:
        decision = "assigned"

    if decision == "assigned":
        chosen = best
        # Indices de natures différentes (route, OUI, empreinte, ports) qui concordent : bonus de corroboration
        kinds = len({h["source"].split(" (")[0] for h in hits if h["type"] == best})
        confidence = best_score - 0.5 * second_score + 0.05 * (kinds - 1)
        confidence = round(min(max(confidence, CONFIDENCE_FLOOR), CONFIDENCE_CEILING), 2)
    else:
        chosen, confidence = "unknown", UNKNOWN_CONFIDENCE

    reasons = [{"reason": h["reason"], "source": h["source"], "supports": h["type"] == chosen, "type": h["type"], "weight": h["weight"]} for h in hits]
    if decision == "insufficient":
        reasons.append({
            "reason": (f"Indices insuffisants : meilleur candidat {TYPE_LABEL.get(best, best)} à {best_score:.2f} (seuil {ASSIGN_THRESHOLD})"
                       if ranked else "Aucun indice discriminant observé"),
            "source": "classification", "supports": True, "type": "unknown", "weight": 0.0,
        })
    elif decision == "contradictory":
        reasons.append({
            "reason": f"Indices contradictoires : {TYPE_LABEL.get(best, best)} ({best_score:.2f}) et {TYPE_LABEL.get(ranked[1][0], ranked[1][0])} ({second_score:.2f}) trop proches pour trancher",
            "source": "classification", "supports": True, "type": "unknown", "weight": 0.0,
        })
    for note in notes:
        reasons.append({"reason": note, "source": "observation", "supports": False, "type": None, "weight": 0.0})

    alternatives = [
        {"type": t, "score": round(s, 2), "reasons": [h["reason"] for h in hits if h["type"] == t]}
        for t, s in ranked if t != chosen
    ]

    missing = []
    if not os_detected:
        missing.append("Système d'exploitation non identifié")
    if not open_ports:
        missing.append("Aucun port TCP ouvert observé (les services UDP ne sont pas sondés)")
    elif service_details is not None and not any(d.get("version") for d in service_details):
        missing.append("Versions des services inconnues")
    if not vendor:
        missing.append("Constructeur inconnu (MAC absente ou hors segment)")

    return {
        "model": MODEL_VERSION,
        "type": chosen,
        "confidence": confidence,
        "decision": decision,
        "scores": {t: round(s, 2) for t, s in ranked},
        "reasons": reasons,
        "alternatives": alternatives,
        "roles": infer_roles(open_ports, services, is_gateway),
        "services": service_details if service_details is not None else [{"port": p} for p in sorted(open_ports)],
        "missing": missing,
    }


def classify_sensor_host(open_ports: list[int] | None = None, services: list[str] | None = None) -> dict:
    """
    L'hôte qui exécute CYBERMORPH : ses ports sont lus localement (`ss`), pas devinés. Le type « serveur » repose sur un
    fait vérifié (il héberge l'API, la base et les collecteurs), pas sur son système d'exploitation.
    """
    open_ports = open_ports or []
    services = services or []
    return {
        "model": MODEL_VERSION,
        "type": "server",
        "confidence": 0.9,
        "decision": "assigned",
        "scores": {"server": 0.9},
        "reasons": [{
            "reason": "Hôte du capteur CYBERMORPH : API, base et collecteurs y tournent (ports lus localement)",
            "source": "ss · hôte local", "supports": True, "type": "server", "weight": 0.9,
        }],
        "alternatives": [],
        "roles": infer_roles(open_ports, services),
        "services": [{"port": p, "source": "ss"} for p in sorted(open_ports)],
        "missing": [] if open_ports else ["Aucun port en écoute lu localement"],
    }


def database_ports(open_ports: list[int], services: list[str]) -> list[str]:
    found = [f"{name} ({port})" for port, name in DATABASE_PORTS.items() if port in open_ports]
    services_l = {s.lower() for s in services}
    if not found and services_l & DATABASE_SERVICES:
        found = sorted(services_l & DATABASE_SERVICES)
    return found


def parse_ports(raw: str | None) -> list[int]:
    return [int(p) for p in (raw or "").split(",") if p.strip().isdigit()]


def parse_list(raw: str | None) -> list[str]:
    return [s.strip() for s in (raw or "").split(",") if s.strip()]
