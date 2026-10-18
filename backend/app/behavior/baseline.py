"""
Ingestion des flux Suricata et référence comportementale explicable.

Unité de référence : l'**activité** (source → destination, protocole, port de service, protocole applicatif),
inspirée des « activities » agrégeant des flux. Ce qui est appris est l'*existence* d'une activité (qui parle à qui,
sur quoi), pas des volumes : c'est vérifiable et explicable.

Règles :
- pendant la période d'apprentissage globale, toute activité nouvelle entre dans la référence ;
- un actif découvert après cette période dispose de sa propre fenêtre d'apprentissage pour ses activités sortantes ;
- au-delà, une activité nouvelle est un **écart** ; sa sévérité est expliquée par des facteurs (port à risque,
  cible critique, source non autorisée, alerte IDS sur la même paire) et abaissée si une activité semblable est
  déjà connue depuis un autre actif (évaluation « adaptative ») ;
- les sondes de l'actif scanner (le capteur CYBERMORPH) vers le réseau local ne sont jamais apprises : elles sont
  comptées à part ; une tentative TCP sans poignée de main (pas de SYN+ACK) n'est pas une communication, elle
  alimente seulement la détection de balayage.
"""
import ipaddress
import json
import os
from datetime import datetime, timedelta, UTC

from sqlalchemy.orm import Session

from app.behavior.eve_reader import read_new_lines
from app.exposure.criticality import effective_criticality, is_target_level
from app.inventory.observations import as_utc, get_setting, learning_window, record_observation, set_setting
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.behavior import Communication, Deviation
from app.models.network_connection import NetworkConnection
from app.models.observation import AssetObservation
from app.risk.risk_engine import DANGEROUS_PORTS

EVE_PATH = os.getenv("CYBERMORPH_EVE_PATH", "/var/log/suricata/eve.json")
ASSET_LEARNING = timedelta(hours=float(os.getenv("CYBERMORPH_ASSET_LEARNING_HOURS", "24")))
FLOW_RELATION_TTL = timedelta(hours=24)
PORT_SCAN_THRESHOLD = 15       # ports distincts tentés sur une même cible, dans un lot
HOST_SWEEP_THRESHOLD = 8       # cibles distinctes sur un même port, dans un lot
DEDUP_WINDOW = timedelta(hours=1)
SAMPLE_LIMIT = 10
COMMON_EXTERNAL_PORTS = {53, 80, 123, 443}

SYN_ACK = 0x12


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("+0000", "+00:00"))
    except ValueError:
        return None


def classify_scope(ip: str, local_networks: list) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "external"
    if addr.is_multicast:
        return "multicast"
    if addr.version == 4 and (str(addr) == "255.255.255.255" or any(addr == n.broadcast_address for n in local_networks if n.version == 4)):
        return "broadcast"
    if addr.is_link_local:
        return "link-local"
    if any(addr in n for n in local_networks):
        return "local"
    if addr.is_private:
        return "routed"
    return "external"


def mac_from_eui64(ip: str) -> str | None:
    """MAC d'origine d'une adresse IPv6 lien-local EUI-64 (fe80::xxff:fexx:xxxx), ou None."""
    try:
        addr = ipaddress.IPv6Address(ip)
    except ValueError:
        return None
    if not addr.is_link_local:
        return None
    b = addr.packed[8:]
    if b[3] != 0xFF or b[4] != 0xFE:
        return None
    mac = bytes([b[0] ^ 0x02, b[1], b[2], b[5], b[6], b[7]])
    return ":".join(f"{x:02X}" for x in mac)


def flow_established(event: dict) -> bool:
    """TCP : la cible a répondu SYN+ACK (un RST n'est pas une réponse de service). Autres : un paquet retour."""
    flow = event.get("flow", {})
    if event.get("proto") == "TCP":
        try:
            return int(event.get("tcp", {}).get("tcp_flags_tc", "0"), 16) & SYN_ACK == SYN_ACK
        except ValueError:
            return False
    return (flow.get("pkts_toclient") or 0) > 0


def local_networks_default() -> list:
    raw = os.getenv("CYBERMORPH_LOCAL_NETWORKS")
    if raw:
        return [ipaddress.ip_network(n.strip(), strict=False) for n in raw.split(",") if n.strip()]
    try:
        from app.collectors.network_utils import get_local_subnet
        return [ipaddress.ip_network(get_local_subnet(), strict=False)]
    except Exception:
        return []


class _Context:
    """Index chargés une fois par lot."""

    def __init__(self, db: Session, now: datetime):
        self.db = db
        self.now = now
        self.assets_by_ip = {a.ip_address: a for a in db.query(Asset).all()}
        self.scanner_ips = {ip for ip, a in self.assets_by_ip.items() if a.is_scanner}
        self.asset_by_mac: dict[str, Asset] = {}
        for o in db.query(AssetObservation).filter(AssetObservation.attribute == "mac", AssetObservation.retired_at.is_(None)).all():
            asset = self.assets_by_ip.get(o.ip)
            if asset:
                self.asset_by_mac[o.value] = asset
        self.learning = learning_window(db, now)
        self.relations: dict[tuple, NetworkConnection] = {}

    def resolve(self, ip: str) -> Asset | None:
        asset = self.assets_by_ip.get(ip)
        if asset:
            return asset
        mac = mac_from_eui64(ip)
        return self.asset_by_mac.get(mac) if mac else None


def _update_sample(details: dict, key: str, value, limit: int = SAMPLE_LIMIT):
    if value is None:
        return
    values = details.setdefault(key, [])
    if value in values:
        return
    values.append(value)
    del values[:-limit]


def _severity_for_new(ctx: _Context, comm: Communication, src: Asset | None, dst: Asset | None) -> tuple[str, list[str], dict]:
    db = ctx.db
    reasons, warning, evidence = [], False, {}
    learning = ctx.learning
    reasons.append(
        f"Activité jamais observée pendant l'apprentissage "
        f"(du {learning['started_at']:%d/%m %H:%M} au {learning['ends_at']:%d/%m %H:%M} UTC)."
    )
    if comm.dst_port in DANGEROUS_PORTS:
        warning = True
        reasons.append(f"Port à risque : {DANGEROUS_PORTS[comm.dst_port]['label']}.")
    if dst is not None and is_target_level(effective_criticality(dst)["level"]):
        warning = True
        reasons.append(f"La destination {dst.ip_address} est un actif critique.")
    if src is not None and src.authorization == "unauthorized":
        warning = True
        reasons.append(f"La source {src.ip_address} n'est pas autorisée dans l'inventaire.")
    if comm.dst_scope == "external" and comm.dst_port not in COMMON_EXTERNAL_PORTS and comm.dst_port != -1:
        warning = True
        reasons.append(f"Sortie vers Internet sur un port inhabituel ({comm.proto.lower()}/{comm.dst_port}).")
    if dst is not None:
        since = ctx.now - timedelta(hours=24)
        alerts = (
            db.query(Alert)
            .filter(Alert.source_ip == comm.src_ip, Alert.destination_ip == dst.ip_address, Alert.last_seen >= since)
            .all()
        )
        if alerts:
            warning = True
            evidence["alert_ids"] = [a.id for a in alerts[:10]]
            reasons.append(f"Corrélation : {len(alerts)} alerte(s) IDS sur la même paire en 24 h ({alerts[0].message}).")

    similar = (
        db.query(Communication)
        .filter(
            Communication.dst_key == comm.dst_key, Communication.proto == comm.proto, Communication.dst_port == comm.dst_port,
            Communication.src_ip != comm.src_ip, Communication.baseline_state.in_(("baseline", "accepted")),
        )
        .first()
    )
    if similar:
        evidence["similar_communication_id"] = similar.id
        reasons.append(f"Activité semblable déjà connue depuis {similar.src_ip} : écart atténué.")
    severity = "warning" if warning else ("info" if similar else "notice")
    return severity, reasons, evidence


def _describe(comm: Communication) -> str:
    service = f"{comm.proto.lower()}/{comm.dst_port}" if comm.dst_port != -1 else comm.proto.lower()
    if comm.app_proto:
        service += f" ({comm.app_proto})"
    dst = comm.dst_key if comm.dst_scope == "local" else {"external": "Internet", "multicast": "multidiffusion",
                                                          "broadcast": "diffusion", "routed": "un réseau routé",
                                                          "link-local": "le lien local"}.get(comm.dst_scope, comm.dst_key)
    return f"{comm.src_ip} → {dst} en {service}"


def _open_deviation(ctx, kind, severity, explanation, reasons, evidence, src_ip, dst_ip, src_asset, dst_asset, comm=None):
    deviation = Deviation(
        kind=kind, severity=severity, status="open", src_ip=src_ip, dst_ip=dst_ip,
        src_asset_id=src_asset.id if src_asset else None, dst_asset_id=dst_asset.id if dst_asset else None,
        communication_id=comm.id if comm else None, explanation=explanation, reasons=reasons, evidence=evidence,
        first_seen=ctx.now, last_seen=ctx.now, occurrences=1,
    )
    ctx.db.add(deviation)
    ctx.db.flush()  # visible des requêtes suivantes du même lot (pas d'autoflush)
    return deviation


def _upsert_relation(ctx: _Context, src: Asset, dst: Asset, comm: Communication, seen: datetime):
    """Relation de topologie OBSERVÉE (flux établi), alimentant le graphe d'attaque."""
    port = comm.dst_port if comm.dst_port != -1 else None
    protocol = comm.proto.lower()
    key = (src.id, dst.id, port, protocol)
    # La session n'a pas d'autoflush : une relation créée dans ce lot n'est visible que via ce cache
    relation = ctx.relations.get(key) or (
        ctx.db.query(NetworkConnection)
        .filter(
            NetworkConnection.source_asset_id == src.id, NetworkConnection.destination_asset_id == dst.id,
            NetworkConnection.connection_type == "detected", NetworkConnection.port == port,
            NetworkConnection.protocol == protocol,
        )
        .first()
    )
    if relation:
        relation.status = "active"
        if not relation.last_seen or as_utc(relation.last_seen) < seen:
            relation.last_seen = seen
        relation.source = relation.source or "suricata_flow"
    else:
        relation = NetworkConnection(
            source_asset_id=src.id, destination_asset_id=dst.id, protocol=protocol, port=port,
            connection_type="detected", status="active", source="suricata_flow", last_seen=seen,
        )
        ctx.db.add(relation)
    ctx.relations[key] = relation


def process_events(db: Session, lines: list[str], now: datetime | None = None, local_networks: list | None = None) -> dict:
    now = now or datetime.now(UTC)
    local_networks = local_networks if local_networks is not None else local_networks_default()
    ctx = _Context(db, now)
    stats = {"lines": len(lines), "flows": 0, "probes_excluded": 0, "unanswered": 0, "communications_new": 0,
             "communications_updated": 0, "deviations_new": 0, "dhcp": 0, "relations": 0}
    sni_by_flow: dict[int, str] = {}
    flows: list[dict] = []

    for line in lines:
        # Pré-filtre textuel : la plupart des lignes (stats, dns…) ne sont pas décodées
        if '"event_type":"flow"' in line:
            kind = "flow"
        elif '"event_type":"dhcp"' in line:
            kind = "dhcp"
        elif '"event_type":"tls"' in line:
            kind = "tls"
        elif '"event_type":"alert"' in line:
            kind = "alert"
        else:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if kind == "flow":
            flows.append(event)
        elif kind == "alert":
            if _attach_alert_flow(db, event):
                stats["alerts_linked"] = stats.get("alerts_linked", 0) + 1
        elif kind == "tls":
            sni = event.get("tls", {}).get("sni")
            if sni and event.get("flow_id"):
                sni_by_flow[event["flow_id"]] = sni
        elif kind == "dhcp":
            dhcp = event.get("dhcp", {})
            ip, mac = dhcp.get("assigned_ip"), dhcp.get("client_mac")
            asset = ctx.assets_by_ip.get(ip) if ip and ip != "0.0.0.0" else None
            if asset and mac:
                seen = _parse_ts(event.get("timestamp")) or now
                record_observation(db, ip, "dhcp", "mac", mac, asset.id, seen)
                if dhcp.get("hostname"):
                    record_observation(db, ip, "dhcp", "hostname", dhcp["hostname"], asset.id, seen)
                ctx.asset_by_mac[mac.upper()] = asset
                stats["dhcp"] += 1

    unanswered_ports: dict[tuple[str, str], set[int]] = {}
    sweep_targets: dict[tuple[str, int], set[str]] = {}

    for event in flows:
        stats["flows"] += 1
        src_ip, dst_ip, proto = event.get("src_ip"), event.get("dest_ip"), event.get("proto") or "?"
        if not src_ip or not dst_ip:
            continue
        flow = event.get("flow", {})
        seen = _parse_ts(flow.get("end")) or _parse_ts(event.get("timestamp")) or now
        port = event.get("dest_port") if proto in ("TCP", "UDP") else None
        dst_port = int(port) if port is not None else -1
        app = event.get("app_proto") or ""
        if app == "failed":
            app = ""
        scope = classify_scope(dst_ip, local_networks)
        src = ctx.resolve(src_ip)
        dst = ctx.resolve(dst_ip) if scope in ("local", "link-local") else None
        src_key = src.ip_address if src else src_ip

        if src_key in ctx.scanner_ips and scope in ("local", "link-local", "broadcast"):
            stats["probes_excluded"] += 1
            continue
        if proto == "TCP" and not flow_established(event):
            stats["unanswered"] += 1
            if scope == "local" and dst_port != -1:
                unanswered_ports.setdefault((src_key, dst_ip), set()).add(dst_port)
                sweep_targets.setdefault((src_key, dst_port), set()).add(dst_ip)
            continue

        dst_key = (dst.ip_address if dst else dst_ip) if scope == "local" else scope
        comm = (
            db.query(Communication)
            .filter(Communication.src_ip == src_key, Communication.dst_key == dst_key, Communication.proto == proto,
                    Communication.dst_port == dst_port, Communication.app_proto == app)
            .first()
        )
        created = comm is None
        if created:
            in_asset_learning = src is not None and as_utc(src.created_at) is not None and now - as_utc(src.created_at) < ASSET_LEARNING
            if ctx.learning["in_learning"]:
                state, via = "baseline", "global_learning"
            elif in_asset_learning:
                state, via = "baseline", "asset_learning"
            else:
                state, via = "new", None
            comm = Communication(
                src_ip=src_key, dst_key=dst_key, dst_scope=scope, src_asset_id=src.id if src else None,
                dst_asset_id=dst.id if dst else None, proto=proto, dst_port=dst_port, app_proto=app,
                first_seen=seen, last_seen=seen, flow_count=0, established_count=0, bytes_toserver=0, bytes_toclient=0,
                baseline_state=state, learned_via=via, details={},
            )
            db.add(comm)
            db.flush()
            stats["communications_new"] += 1
        else:
            stats["communications_updated"] += 1

        comm.flow_count += 1
        comm.established_count += 1 if flow_established(event) else 0
        comm.bytes_toserver += int(flow.get("bytes_toserver") or 0)
        comm.bytes_toclient += int(flow.get("bytes_toclient") or 0)
        if seen > as_utc(comm.last_seen):
            comm.last_seen = seen
        if seen < as_utc(comm.first_seen):
            comm.first_seen = seen
        details = dict(comm.details or {})
        if scope != "local":
            _update_sample(details, "destinations", dst_ip)
        _update_sample(details, "sni", sni_by_flow.get(event.get("flow_id")))
        _update_sample(details, "flow_ids", event.get("flow_id"), limit=5)
        comm.details = details

        if created and comm.baseline_state == "new":
            severity, reasons, evidence = _severity_for_new(ctx, comm, src, dst)
            evidence.update({"communication_id": comm.id, "flow_ids": details.get("flow_ids", [])})
            _open_deviation(ctx, "new_communication", severity, f"Nouvelle activité : {_describe(comm)}.",
                            reasons, evidence, src_key, dst_ip if scope == "local" else dst_key, src, dst, comm)
            stats["deviations_new"] += 1
        elif comm.baseline_state == "new":
            deviation = db.query(Deviation).filter(Deviation.communication_id == comm.id).order_by(Deviation.id.desc()).first()
            if deviation:
                deviation.last_seen = max(as_utc(deviation.last_seen), seen)
                deviation.occurrences += 1

        if scope == "local" and src is not None and dst is not None and flow_established(event) and src.id != dst.id:
            _upsert_relation(ctx, src, dst, comm, seen)
            stats["relations"] += 1

        if src is None and scope_is_local_source(src_ip, local_networks):
            _flag_unknown_host(ctx, src_ip, comm, stats)

    _detect_scans(ctx, unanswered_ports, sweep_targets, stats)
    _expire_flow_relations(ctx)
    db.flush()
    return stats


def _attach_alert_flow(db: Session, event: dict) -> bool:
    """
    Rattache l'alerte agrégée (issue de fast.log) au flow_id Suricata de l'événement eve correspondant :
    même signature (gid:sid:rev) et même couple source/destination. Lien exact, sans heuristique.
    """
    info = event.get("alert", {})
    sig = f"{info.get('gid', 1)}:{info.get('signature_id')}:{info.get('rev', 0)}"
    alert = (
        db.query(Alert)
        .filter(Alert.signature_id == sig, Alert.source_ip == event.get("src_ip"), Alert.destination_ip == event.get("dest_ip"))
        .first()
    )
    if not alert or not event.get("flow_id"):
        return False
    evidence = dict(alert.evidence or {})
    flows = [f for f in evidence.get("flow_ids", []) if f != event["flow_id"]] + [event["flow_id"]]
    evidence["flow_ids"] = flows[-SAMPLE_LIMIT:]
    evidence["eve_last"] = {
        "timestamp": event.get("timestamp"), "flow_id": event["flow_id"],
        "src_port": event.get("src_port"), "dest_port": event.get("dest_port"), "proto": event.get("proto"),
        "app_proto": event.get("app_proto"),
    }
    alert.evidence = evidence
    return True


def scope_is_local_source(ip: str, local_networks: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and any(addr in n for n in local_networks)


def _recent_open(ctx: _Context, kind: str, src_ip: str, dst_ip: str | None) -> Deviation | None:
    q = ctx.db.query(Deviation).filter(Deviation.kind == kind, Deviation.src_ip == src_ip, Deviation.status == "open",
                                       Deviation.last_seen >= ctx.now - DEDUP_WINDOW)
    if dst_ip is not None:
        q = q.filter(Deviation.dst_ip == dst_ip)
    return q.first()


def _flag_unknown_host(ctx: _Context, src_ip: str, comm: Communication, stats: dict):
    """Une IP locale communique sans être dans l'inventaire : découverte passive, à signaler."""
    if ctx.db.query(Deviation).filter(Deviation.kind == "unknown_host", Deviation.src_ip == src_ip, Deviation.status == "open").first():
        return
    _open_deviation(ctx, "unknown_host", "warning",
                    f"{src_ip} communique sur le réseau local mais n'est pas dans l'inventaire (non découvert par Nmap).",
                    ["Hôte vu passivement par Suricata, absent des scans actifs."],
                    {"communication_id": comm.id}, src_ip, None, None, None, comm)
    stats["deviations_new"] += 1


def _detect_scans(ctx: _Context, unanswered_ports, sweep_targets, stats):
    for (src_ip, dst_ip), ports in unanswered_ports.items():
        if len(ports) < PORT_SCAN_THRESHOLD:
            continue
        evidence = {"ports_sample": sorted(ports)[:30], "distinct_ports": len(ports)}
        existing = _recent_open(ctx, "port_scan", src_ip, dst_ip)
        if existing:
            existing.last_seen = ctx.now
            existing.occurrences += 1
            existing.evidence = {**(existing.evidence or {}), **evidence}
            continue
        _open_deviation(ctx, "port_scan", "warning",
                        f"Balayage de ports : {src_ip} a tenté {len(ports)} ports distincts de {dst_ip} sans connexion établie.",
                        [f"Seuil : {PORT_SCAN_THRESHOLD} ports distincts dans un même lot de flux.",
                         "La source n'est pas déclarée comme scanner."],
                        evidence, src_ip, dst_ip, ctx.assets_by_ip.get(src_ip), ctx.assets_by_ip.get(dst_ip))
        stats["deviations_new"] += 1
    for (src_ip, port), targets in sweep_targets.items():
        if len(targets) < HOST_SWEEP_THRESHOLD:
            continue
        if _recent_open(ctx, "host_sweep", src_ip, None):
            continue
        _open_deviation(ctx, "host_sweep", "warning",
                        f"Balayage d'hôtes : {src_ip} a tenté le port {port} sur {len(targets)} hôtes distincts.",
                        [f"Seuil : {HOST_SWEEP_THRESHOLD} hôtes distincts sur un même port dans un même lot."],
                        {"targets_sample": sorted(targets)[:30], "port": port}, src_ip, None, ctx.assets_by_ip.get(src_ip), None)
        stats["deviations_new"] += 1


def _expire_flow_relations(ctx: _Context):
    """Une relation observée par les flux et plus revue depuis 24 h n'est plus active (rien n'est supprimé)."""
    cutoff = ctx.now - FLOW_RELATION_TTL
    for relation in ctx.db.query(NetworkConnection).filter(
        NetworkConnection.source == "suricata_flow", NetworkConnection.status == "active",
    ).all():
        if as_utc(relation.last_seen) and as_utc(relation.last_seen) < cutoff:
            relation.status = "inactive"


def ingest_eve(db: Session, path: str = EVE_PATH, now: datetime | None = None, local_networks: list | None = None) -> dict:
    """Un passage incrémental : lit la suite d'eve.json, met à jour activités et écarts, mémorise la position."""
    now = now or datetime.now(UTC)
    result = read_new_lines(path, get_setting(db, "eve_reader"))
    if result is None:
        stats = {"error": f"Fichier introuvable : {path}"}
        set_setting(db, "eve_last_run", {"at": now.isoformat(), **stats})
        return stats
    lines, state, info = result
    stats = process_events(db, lines, now, local_networks)
    stats.update(info)
    set_setting(db, "eve_reader", state)
    set_setting(db, "eve_last_run", {"at": now.isoformat(), "path": str(path), **stats})
    return stats


def learn_deviation(db: Session, deviation: Deviation, now: datetime | None = None) -> Deviation:
    """L'opérateur valide l'écart : l'activité entre dans la référence (« accepted »), elle n'alertera plus."""
    now = now or datetime.now(UTC)
    deviation.status = "learned"
    deviation.reviewed_at = now
    if deviation.communication_id:
        comm = db.get(Communication, deviation.communication_id)
        if comm:
            comm.baseline_state = "accepted"
            comm.learned_via = "operator"
    return deviation
