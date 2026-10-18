"""
Classification explicable des actifs.

Chaque règle qui s'applique est conservée comme une preuve, avec la raison lisible et la source de la donnée.
Le type retenu est celui de la première règle prioritaire qui s'applique : c'est l'ordre historique de
`guess_asset_type`, ce qui garde les mêmes décisions sur les données existantes. La confiance, elle, tient compte
des preuves concordantes et contradictoires, et les types concurrents sont publiés comme alternatives.

Ce module est pur (aucun accès base) : il est testé directement.
"""

NETWORK_VENDORS = ["cisco", "mikrotik", "ubiquiti", "tp-link", "netgear", "juniper", "fortinet", "aruba"]
WEB_DB_PORTS = [80, 443, 3306, 5432, 8080]
DATABASE_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB", 6379: "Redis"}
ROUTER_OS_MARKERS = ["router", "nat device", "switch", "firewall", "gateway", "routeros"]
CLIENT_OS_MARKERS = ["windows 11", "windows 10", "windows 8", "windows 7", "windows xp", "mac os", "macos", "android", "ios"]
SERVER_OS_MARKERS = ["windows server"]

CONFIDENCE_FLOOR = 0.1
CONFIDENCE_CEILING = 0.95


def _rule(type_: str, strength: float, reason: str, source: str, decisive: bool = True) -> dict:
    return {"type": type_, "strength": strength, "reason": reason, "source": source, "decisive": decisive}


def evaluate_rules(open_ports: list[int], services: list[str], vendor: str | None, os_detected: str | None) -> list[dict]:
    """Toutes les règles qui s'appliquent, dans l'ordre de priorité. `decisive=False` : indice d'appui seulement."""
    ports = set(open_ports)
    services_l = [s.lower() for s in services]
    vendor_l = (vendor or "").lower()
    os_l = (os_detected or "").lower()
    hits = []

    brand = next((v for v in NETWORK_VENDORS if v in vendor_l), None)
    if brand:
        hits.append(_rule("router", 0.8, f"Constructeur d'équipements réseau ({vendor})", "nmap · OUI MAC"))
    if "domain" in services_l or 53 in ports:
        hits.append(_rule("router", 0.6, "Service DNS exposé (53) : résolveur ou passerelle probable", "nmap · ports"))
    if 22 in ports:
        hits.append(_rule("server", 0.45, "SSH exposé (22)", "nmap · ports"))
    web_db = sorted(p for p in ports if p in WEB_DB_PORTS)
    if web_db:
        hits.append(_rule("server", 0.5, f"Service web ou base de données exposé ({', '.join(map(str, web_db))})", "nmap · ports"))
    windows_share = sorted(p for p in ports if p in (3389, 445))
    if windows_share:
        hits.append(_rule("pc", 0.5, f"RDP/SMB exposé ({', '.join(map(str, windows_share))}) : poste Windows probable", "nmap · ports"))

    # Indices tirés de l'empreinte d'OS : estimation Nmap, donc jamais décisifs face à un service observé
    if os_l:
        if any(m in os_l for m in ROUTER_OS_MARKERS):
            hits.append(_rule("router", 0.6, f"Empreinte d'OS d'équipement réseau ({os_detected})", "nmap · empreinte OS", decisive=False))
        elif any(m in os_l for m in SERVER_OS_MARKERS):
            hits.append(_rule("server", 0.5, f"Empreinte d'OS serveur ({os_detected})", "nmap · empreinte OS", decisive=False))
        elif any(m in os_l for m in CLIENT_OS_MARKERS):
            hits.append(_rule("pc", 0.5, f"Empreinte d'OS de poste client ({os_detected})", "nmap · empreinte OS", decisive=False))
    return hits


def classify_asset(open_ports: list[int], services: list[str], vendor: str | None, os_detected: str | None) -> dict:
    hits = evaluate_rules(open_ports, services, vendor, os_detected)
    decisive = [h for h in hits if h["decisive"]]
    chosen = decisive[0] if decisive else (hits[0] if hits else None)

    if not chosen:
        return {
            "type": "unknown",
            "confidence": 0.2,
            "reasons": [{"reason": "Aucun service ni indice discriminant observé", "source": "nmap", "supports": True}],
            "alternatives": [],
        }

    supporting = [h for h in hits if h["type"] == chosen["type"] and h is not chosen]
    contradicting_types = sorted({h["type"] for h in hits if h["type"] != chosen["type"]})
    confidence = chosen["strength"] + 0.1 * len(supporting) - 0.15 * len(contradicting_types)
    confidence = round(min(max(confidence, CONFIDENCE_FLOOR), CONFIDENCE_CEILING), 2)

    alternatives = []
    for t in contradicting_types:
        evidence = [h for h in hits if h["type"] == t]
        alternatives.append({
            "type": t,
            "reasons": [h["reason"] for h in evidence],
        })

    return {
        "type": chosen["type"],
        "confidence": confidence,
        "reasons": [
            {"reason": h["reason"], "source": h["source"], "supports": h["type"] == chosen["type"]}
            for h in hits
        ],
        "alternatives": alternatives,
    }


def classify_sensor_host() -> dict:
    """L'hôte qui exécute CYBERMORPH : ses ports sont lus localement (ss), pas devinés."""
    return {
        "type": "server",
        "confidence": 0.9,
        "reasons": [{
            "reason": "Hôte du capteur CYBERMORPH : API, base et collecteurs y tournent (ports lus localement)",
            "source": "ss · hôte local",
            "supports": True,
        }],
        "alternatives": [],
    }


def database_ports(open_ports: list[int], services: list[str]) -> list[str]:
    found = [f"{name} ({port})" for port, name in DATABASE_PORTS.items() if port in open_ports]
    services_l = {s.lower() for s in services}
    if not found and services_l & {"mysql", "postgres", "postgresql", "mongod", "redis-server"}:
        found = sorted(services_l & {"mysql", "postgres", "postgresql", "mongod", "redis-server"})
    return found


def parse_ports(raw: str | None) -> list[int]:
    return [int(p) for p in (raw or "").split(",") if p.strip().isdigit()]


def parse_list(raw: str | None) -> list[str]:
    return [s.strip() for s in (raw or "").split(",") if s.strip()]
