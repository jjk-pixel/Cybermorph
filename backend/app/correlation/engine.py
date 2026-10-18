"""
Corrélation explicable d'événements : alertes IDS, écarts comportementaux, changements d'inventaire.

Règles (fenêtre CORRELATION_WINDOW, événements des LOOKBACK dernières heures) :
- port_probe : balayage de ports mesuré dans les flux (écart port_scan), rapproché des alertes de la même paire ;
- new_service_activity : un port s'ouvre ou un service change, puis une activité vise cet actif dans l'heure ;
- profile_change : au moins deux changements de nature différente sur un actif dans l'heure ;
- address_activity : une même adresse impliquée dans au moins deux catégories d'événements dans l'heure.

Chaque corrélation conserve ses événements sources (une fois chacun), son raisonnement, sa fenêtre et sa confiance.
Le lien est toujours qualifié : « temporal » (proximité dans le temps), « same_target » (même cible) ou
« same_address » ; aucune règle ne conclut à une causalité, qui n'est jamais démontrée par la seule chronologie.
"""
from datetime import datetime, timedelta, UTC

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.asset import Asset
from app.models.attack_technique import AttackTechnique
from app.models.behavior import Deviation
from app.models.correlation import Correlation, TechniqueEvidence
from app.models.observation import AssetChange

CORRELATION_WINDOW = timedelta(hours=1)
LOOKBACK = timedelta(hours=24)
PROFILE_TYPES = ("os_changed", "identity_conflict", "hostname_changed", "vendor_changed", "service_changed",
                 "port_opened", "ip_changed", "mac_shared")
CAUSALITY_NOTE = "Corrélation temporelle : la succession des événements ne démontre pas une relation de cause à effet."


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _event(kind: str, obj, at: datetime | None, summary: str) -> dict:
    return {"type": kind, "id": obj.id, "at": _utc(at).isoformat() if at else None, "summary": summary[:300]}


def _alert_event(a: Alert) -> dict:
    return _event("alert", a, a.last_seen, f"{a.message} (P{a.priority}, ×{a.occurrence_count}) {a.source_ip} → {a.destination_ip}")


def _deviation_event(d: Deviation) -> dict:
    return _event("deviation", d, d.last_seen, d.explanation)


def _change_event(c: AssetChange) -> dict:
    return _event("change", c, c.detected_at, c.explanation)


class _Store:
    """Crée ou complète une corrélation identifiée par (kind, fingerprint), sans compter deux fois un événement."""

    def __init__(self, db: Session, now: datetime, techniques: dict[tuple[str, int], list[str]]):
        self.db, self.now, self.techniques = db, now, techniques
        self.stats = {"created": 0, "updated": 0}

    def save(self, kind: str, fingerprint: str, asset_id: int | None, ip: str | None, events: list[dict],
             reasoning: str, relation: str, confidence: float):
        row = self.db.query(Correlation).filter_by(kind=kind, fingerprint=fingerprint).first()
        known = {(e["type"], e["id"]): e for e in (row.events if row else [])}
        for e in events:
            known[(e["type"], e["id"])] = e
        merged = sorted(known.values(), key=lambda e: (e["at"] or "", e["type"], e["id"]))
        if row and len(merged) == row.event_count and row.reasoning == reasoning:
            return row
        times = [datetime.fromisoformat(e["at"]) for e in merged if e["at"]]
        techniques = sorted({t for e in merged for t in self.techniques.get((e["type"], e["id"]), [])})
        if row is None:
            row = Correlation(kind=kind, fingerprint=fingerprint, created_at=self.now)
            self.db.add(row)
            self.stats["created"] += 1
        else:
            self.stats["updated"] += 1
        row.asset_id, row.ip = asset_id, ip
        row.events, row.event_count = merged, len(merged)
        row.window_start, row.window_end = min(times, default=self.now), max(times, default=self.now)
        row.reasoning, row.relation, row.confidence = reasoning, relation, round(min(confidence, 0.95), 2)
        row.techniques, row.updated_at = techniques, self.now
        self.db.flush()
        return row


def _technique_index(db: Session) -> dict[tuple[str, int], list[str]]:
    index: dict[tuple[str, int], list[str]] = {}
    rows = db.query(TechniqueEvidence.event_type, TechniqueEvidence.event_id, AttackTechnique.technique_id).join(
        AttackTechnique, AttackTechnique.id == TechniqueEvidence.technique_ref).all()
    for event_type, event_id, technique_id in rows:
        index.setdefault((event_type, event_id), []).append(technique_id)
    return index


def correlate(db: Session, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    since = now - LOOKBACK
    assets = {a.id: a for a in db.query(Asset).all()}
    by_ip = {a.ip_address: a for a in assets.values()}
    alerts = db.query(Alert).filter(Alert.last_seen >= since).order_by(Alert.id).all()
    deviations = db.query(Deviation).filter(Deviation.last_seen >= since).order_by(Deviation.id).all()
    changes = db.query(AssetChange).filter(AssetChange.detected_at >= since).order_by(AssetChange.id).all()
    store = _Store(db, now, _technique_index(db))

    def near(a: datetime | None, b: datetime | None, window=CORRELATION_WINDOW) -> bool:
        return a is not None and b is not None and abs(_utc(a) - _utc(b)) <= window

    # 1. Balayage de ports d'un même actif : écart mesuré + alertes de la même paire
    for d in (d for d in deviations if d.kind == "port_scan"):
        related = [a for a in alerts if a.source_ip == d.src_ip and a.destination_ip == d.dst_ip and near(a.last_seen, d.last_seen)]
        ports = (d.evidence or {}).get("distinct_ports")
        reasoning = (f"{d.src_ip} a tenté {ports or 'de nombreux'} ports distincts sur {d.dst_ip} (flux Suricata)"
                     + (f" ; {len(related)} alerte(s) IDS sur la même paire dans l'heure" if related else " ; aucune alerte IDS associée")
                     + ". Même cible, même source : regroupés comme une seule activité de reconnaissance.")
        target = by_ip.get(d.dst_ip)
        store.save("port_probe", f"deviation:{d.id}", target.id if target else d.dst_asset_id, d.dst_ip,
                   [_deviation_event(d)] + [_alert_event(a) for a in related], reasoning, "same_target",
                   0.8 + (0.1 if related else 0.0))

    # 2. Nouveau service puis activité vers cet actif. Les changements d'un même actif constatés au même cycle
    #    (même date de détection) forment un seul ensemble : sinon chaque port ouvert répéterait la même suite.
    service_changes: dict[tuple[int, datetime], list[AssetChange]] = {}
    for c in changes:
        if c.change_type in ("port_opened", "service_changed") and c.asset_id in assets:
            service_changes.setdefault((c.asset_id, _utc(c.detected_at)), []).append(c)
    for (asset_id, detected), group in service_changes.items():
        ip = assets[asset_id].ip_address
        ports = sorted({(c.new_value or "").split("/")[0].split(" ")[0] for c in group})
        after = lambda t: t is not None and detected <= _utc(t) <= detected + CORRELATION_WINDOW  # noqa: E731
        follow = [_deviation_event(d) for d in deviations if d.dst_ip == ip and after(d.first_seen)]
        follow += [_alert_event(a) for a in alerts if a.destination_ip == ip and after(a.last_seen)]
        if not follow:
            continue
        label = f"Le port {ports[0]} est apparu (ou a changé de service)" if len(ports) == 1 else \
            f"Les ports {', '.join(ports)} sont apparus (ou ont changé de service)"
        reasoning = (f"{label} sur {ip} à {detected:%H:%M} UTC, puis {len(follow)} événement(s) ont visé cet actif "
                     f"dans l'heure. {CAUSALITY_NOTE}")
        store.save("new_service_activity", f"changes:{asset_id}:{detected.isoformat()}", asset_id, ip,
                   [_change_event(c) for c in sorted(group, key=lambda c: c.id)] + follow, reasoning,
                   "temporal", 0.5 + 0.1 * min(len(follow), 3))

    # 3. Changement inhabituel du profil d'un actif
    profile: dict[int, list[AssetChange]] = {}
    for c in changes:
        if c.change_type in PROFILE_TYPES and c.asset_id in assets:
            profile.setdefault(c.asset_id, []).append(c)
    for asset_id, group in profile.items():
        group.sort(key=lambda c: (_utc(c.detected_at), c.id))
        anchor = group[0]
        cluster = [c for c in group if near(c.detected_at, anchor.detected_at)]
        kinds = sorted({c.change_type for c in cluster})
        if len(kinds) < 2:
            continue
        ip = assets[asset_id].ip_address
        reasoning = (f"{len(kinds)} changements de nature différente sur {ip} en moins d'une heure ({', '.join(kinds)}) : "
                     f"profil de l'actif modifié (remplacement, reconfiguration ou usurpation). {CAUSALITY_NOTE}")
        store.save("profile_change", f"change:{anchor.id}", asset_id, ip, [_change_event(c) for c in cluster], reasoning,
                   "temporal", 0.4 + 0.1 * (len(kinds) - 1))

    # 4. Plusieurs catégories d'événements autour d'une même adresse, par tranche horaire
    per_ip: dict[tuple[str, str], dict[str, list[dict]]] = {}

    def bucket(ip: str | None, at: datetime | None, category: str, event: dict):
        if not ip or ip not in by_ip or at is None:
            return
        key = (ip, _utc(at).strftime("%Y%m%d%H"))
        per_ip.setdefault(key, {}).setdefault(category, []).append(event)
    for a in alerts:
        if a.priority is not None and a.priority <= 2:
            for ip in {a.source_ip, a.destination_ip}:
                bucket(ip, a.last_seen, "alerte IDS", _alert_event(a))
    for d in deviations:
        for ip in {d.src_ip, d.dst_ip} - {None}:
            bucket(ip, d.last_seen, "écart comportemental", _deviation_event(d))
    for c in changes:
        if c.severity in ("notice", "warning"):
            bucket(c.ip, c.detected_at, "changement d'inventaire", _change_event(c))
    for (ip, hour), categories in per_ip.items():
        if len(categories) < 2:
            continue
        events = [e for group in categories.values() for e in group]
        counts = ", ".join(f"{len(v)} {k}" for k, v in sorted(categories.items()))
        reasoning = f"{ip} est impliquée dans plusieurs catégories d'événements dans la même heure ({counts}). {CAUSALITY_NOTE}"
        store.save("address_activity", f"{ip}:{hour}", by_ip[ip].id, ip, events, reasoning, "same_address",
                   0.3 + 0.1 * (len(categories) - 1))

    return store.stats
