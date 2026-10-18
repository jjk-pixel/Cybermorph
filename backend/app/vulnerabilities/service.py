"""
Inventaire logiciel et mise à jour des correspondances de vulnérabilités.

L'inventaire vient des services identifiés par Nmap -sV (produit, version, CPE, informations complémentaires),
conservés dans la classification de chaque actif. Sans CPE, aucun rapprochement n'est tenté : un nom de service ou un
port ne suffit pas à désigner un logiciel.
"""
from datetime import datetime, UTC

from sqlalchemy.orm import Session

from app.inventory.observations import get_setting, set_setting
from app.models.asset import Asset
from app.models.vulnerability import VulnerabilityFinding
from app.vulnerabilities.matcher import match
from app.vulnerabilities.sources import SourceUnavailable, VulnerabilitySource, configured_sources
from app.vulnerabilities.versions import parse_cpe

OPERATOR_STATUSES = ("confirmed", "rejected")
ACTIVE_STATUSES = ("probable", "uncertain", "confirmed")


def _parse_dt(value: str | None):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def software_inventory(db: Session) -> list[dict]:
    """Logiciels identifiés par actif et par port. `matchable` : un CPE avec éditeur et produit est connu."""
    items = []
    for asset in db.query(Asset).order_by(Asset.id).all():
        services = ((asset.classification or {}).get("services") or []) if isinstance(asset.classification, dict) else []
        for s in services:
            if not isinstance(s, dict) or not (s.get("product") or s.get("cpe")):
                continue
            cpe = parse_cpe(s.get("cpe"))
            version = s.get("version") or (cpe or {}).get("version")
            items.append({
                "asset_id": asset.id, "ip": asset.ip_address, "port": s.get("port"), "service": s.get("name"),
                "product": s.get("product"), "version": version, "cpe": s.get("cpe"),
                "vendor": (cpe or {}).get("vendor"), "cpe_product": (cpe or {}).get("product"),
                "banner": " ".join(x for x in (s.get("product"), s.get("version"), s.get("extrainfo")) if x),
                "matchable": cpe is not None,
            })
    return items


def refresh_findings(db: Session, sources: list[VulnerabilitySource] | None = None, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    sources = configured_sources() if sources is None else sources
    available = [s for s in sources if s.available()]
    stats = {"sources": [s.describe() for s in sources], "software": 0, "matchable": 0, "lookups": 0,
             "findings_new": 0, "findings_updated": 0, "not_observed": 0, "errors": []}
    if not available:
        stats["status"] = "skipped"
        stats["note"] = "Aucune source de vulnérabilités configurée : CVE non évaluées (ce n'est pas une absence de vulnérabilité)"
        set_setting(db, "vulnerability_last_run", {"at": now.isoformat(), **{k: v for k, v in stats.items() if k != "status"}})
        return stats

    inventory = software_inventory(db)
    stats["software"] = len(inventory)
    matchable = [i for i in inventory if i["matchable"]]
    stats["matchable"] = len(matchable)
    seen_keys: set[tuple] = set()
    checked_assets = {i["asset_id"] for i in matchable}
    cache: dict[tuple[str, str, str], list[dict]] = {}

    for item in matchable:
        for source in available:
            key = (source.name, item["vendor"], item["cpe_product"])
            if key not in cache:
                try:
                    cache[key] = source.lookup(item["vendor"], item["cpe_product"])
                    stats["lookups"] += 1
                except SourceUnavailable as e:
                    cache[key] = None
                    stats["errors"].append({"source": source.name, "error": str(e)[:200]})
            records = cache[key]
            if records is None:
                # Source en panne : les correspondances existantes de cet actif sont conservées telles quelles
                checked_assets.discard(item["asset_id"])
                continue
            for record in records:
                verdict = match({"vendor": item["vendor"], "product": item["cpe_product"], "version": item["version"],
                                 "banner": item["banner"]}, record)
                if not verdict:
                    continue
                seen_keys.add((item["asset_id"], item["port"], record["cve_id"]))
                finding = db.query(VulnerabilityFinding).filter_by(
                    asset_id=item["asset_id"], port=item["port"], cve_id=record["cve_id"]).first()
                if finding is None:
                    finding = VulnerabilityFinding(asset_id=item["asset_id"], port=item["port"], cve_id=record["cve_id"],
                                                   first_seen=now, status=verdict["status"])
                    db.add(finding)
                    stats["findings_new"] += 1
                else:
                    stats["findings_updated"] += 1
                finding.cpe, finding.product, finding.version = item["cpe"], item["product"], item["version"]
                finding.source = source.name
                finding.cvss_score, finding.cvss_vector, finding.severity = record["cvss_score"], record["cvss_vector"], record["severity"]
                finding.affected, finding.description, finding.references = verdict["range"], record["description"], record["references"]
                finding.published_at = _parse_dt(record.get("published"))
                finding.last_checked_at = now
                # Une décision de l'opérateur n'est jamais écrasée par un nouveau passage
                if finding.status not in OPERATOR_STATUSES:
                    finding.status, finding.status_reason = verdict["status"], verdict["reason"]
                db.flush()

    # Logiciel plus observé (mise à jour, service arrêté) : la correspondance est conservée mais n'est plus active
    for finding in db.query(VulnerabilityFinding).filter(VulnerabilityFinding.status.in_(("probable", "uncertain"))).all():
        if finding.asset_id in checked_assets and (finding.asset_id, finding.port, finding.cve_id) not in seen_keys:
            finding.status, finding.status_reason = "not_observed", "Logiciel ou version plus observé sur ce port"
            finding.last_checked_at = now
            stats["not_observed"] += 1
    if stats["errors"]:
        stats["status"] = "partial"
    set_setting(db, "vulnerability_last_run", {"at": now.isoformat(), **{k: v for k, v in stats.items() if k != "status"}})
    return stats


def finding_out(f: VulnerabilityFinding) -> dict:
    return {
        "id": f.id, "asset_id": f.asset_id, "port": f.port, "cpe": f.cpe, "product": f.product, "version": f.version,
        "cve_id": f.cve_id, "source": f.source, "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector,
        "severity": f.severity, "affected": f.affected, "description": f.description, "references": f.references or [],
        "published_at": f.published_at, "status": f.status, "status_reason": f.status_reason,
        "first_seen": f.first_seen, "last_checked_at": f.last_checked_at, "validated_at": f.validated_at,
        "validated_note": f.validated_note,
    }


def findings_by_asset(db: Session) -> dict[int, list[dict]]:
    """Correspondances actives par actif, pour le moteur de risque (seules les « confirmed » y comptent)."""
    result: dict[int, list[dict]] = {}
    try:
        rows = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.status.in_(ACTIVE_STATUSES)).all()
    except Exception:  # noqa: BLE001 — table absente (base non migrée) : pas de contexte vulnérabilités
        db.rollback()
        return result
    for f in rows:
        result.setdefault(f.asset_id, []).append(finding_out(f))
    return result


def sources_status(db: Session) -> dict:
    sources = configured_sources()
    return {"sources": [s.describe() for s in sources], "configured": bool(sources),
            "last_run": get_setting(db, "vulnerability_last_run")}
