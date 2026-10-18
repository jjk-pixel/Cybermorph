"""
Sources de vulnérabilités, derrière une interface commune. Aucune n'est interrogée si elle n'est pas configurée.

- `LocalFeedSource` : fichier(s) JSON au format de l'API NVD 2.0 (`{"vulnerabilities": [{"cve": …}]}`), déposés par
  l'opérateur (CYBERMORPH_VULN_FEED : fichier ou dossier). Hors ligne, reproductible.
- `NvdApiSource` : API publique NVD 2.0, désactivée par défaut (CYBERMORPH_NVD_ENABLED=1 pour l'activer ; clé
  facultative CYBERMORPH_NVD_API_KEY). Nombre de requêtes borné par passage, délai d'attente court ; une panne lève
  SourceUnavailable sans bloquer le reste du cycle.

Chaque source renvoie des enregistrements normalisés :
{cve_id, description, cvss_score, cvss_vector, severity, published, references[], ranges[{vendor, product, version,
start_including, start_excluding, end_including, end_excluding}]}.
"""
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

from app.vulnerabilities.versions import parse_cpe

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class SourceUnavailable(RuntimeError):
    """Source configurée mais injoignable ou illisible."""


def _metrics(cve: dict) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData") or {}
            if data.get("baseScore") is not None:
                return float(data["baseScore"]), data.get("vectorString"), data.get("baseSeverity") or entry.get("baseSeverity")
    return None, None, None


def normalize_nvd(cve: dict) -> dict | None:
    cve_id = cve.get("id")
    if not cve_id or not str(cve_id).startswith("CVE-"):
        return None
    ranges = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                cpe = parse_cpe(match.get("criteria"))
                if not cpe:
                    continue
                ranges.append({
                    "vendor": cpe["vendor"], "product": cpe["product"], "version": cpe["version"],
                    "start_including": match.get("versionStartIncluding"), "start_excluding": match.get("versionStartExcluding"),
                    "end_including": match.get("versionEndIncluding"), "end_excluding": match.get("versionEndExcluding"),
                })
    score, vector, severity = _metrics(cve)
    description = next((d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), None)
    return {
        "cve_id": cve_id, "description": (description or "")[:1000] or None, "cvss_score": score, "cvss_vector": vector,
        "severity": severity, "published": cve.get("published"),
        "references": [r["url"] for r in (cve.get("references") or [])[:10] if r.get("url")], "ranges": ranges,
    }


class VulnerabilitySource:
    name = "abstract"

    def available(self) -> bool:
        raise NotImplementedError

    def lookup(self, vendor: str, product: str) -> list[dict]:
        raise NotImplementedError

    def describe(self) -> dict:
        return {"name": self.name, "available": self.available()}


class LocalFeedSource(VulnerabilitySource):
    name = "local_feed"

    def __init__(self, path: str | None):
        self.path = Path(path) if path else None
        self._index: dict[tuple[str, str], list[dict]] | None = None

    def available(self) -> bool:
        return bool(self.path and self.path.exists())

    def _load(self) -> dict:
        if self._index is not None:
            return self._index
        files = sorted(self.path.glob("*.json")) if self.path.is_dir() else [self.path]
        index: dict[tuple[str, str], list[dict]] = {}
        for file in files:
            try:
                data = json.loads(file.read_text())
            except (OSError, ValueError) as e:
                raise SourceUnavailable(f"Flux illisible {file.name} : {e}") from e
            for item in data.get("vulnerabilities") or []:
                record = normalize_nvd(item.get("cve") or {})
                if not record:
                    continue
                for key in {(r["vendor"], r["product"]) for r in record["ranges"]}:
                    index.setdefault(key, []).append(record)
        self._index = index
        return index

    def lookup(self, vendor: str, product: str) -> list[dict]:
        return list(self._load().get((vendor.lower(), product.lower()), []))

    def describe(self) -> dict:
        return {"name": self.name, "available": self.available(), "path": str(self.path) if self.path else None}


class NvdApiSource(VulnerabilitySource):
    name = "nvd_api"

    def __init__(self, enabled: bool, api_key: str | None = None, max_lookups: int = 10, timeout: float = 15.0, opener=None):
        self.enabled, self.api_key, self.max_lookups, self.timeout = enabled, api_key, max_lookups, timeout
        self.opener = opener or urllib.request.urlopen
        self.lookups = 0

    def available(self) -> bool:
        return self.enabled

    def lookup(self, vendor: str, product: str) -> list[dict]:
        if self.lookups >= self.max_lookups:
            raise SourceUnavailable(f"Limite de {self.max_lookups} requêtes NVD atteinte pour ce passage")
        self.lookups += 1
        query = urllib.parse.urlencode({"virtualMatchString": f"cpe:2.3:a:{vendor}:{product}", "resultsPerPage": 200})
        request = urllib.request.Request(f"{NVD_URL}?{query}", headers={"apiKey": self.api_key} if self.api_key else {})
        try:
            with self.opener(request, timeout=self.timeout) as response:
                data = json.loads(response.read())
        except Exception as e:  # noqa: BLE001 — réseau, HTTP, JSON : la source est indisponible, rien de plus
            raise SourceUnavailable(f"API NVD indisponible : {type(e).__name__}") from e
        records = [normalize_nvd(item.get("cve") or {}) for item in data.get("vulnerabilities") or []]
        return [r for r in records if r]

    def describe(self) -> dict:
        return {"name": self.name, "available": self.available(), "max_lookups": self.max_lookups,
                "api_key": bool(self.api_key)}


def configured_sources() -> list[VulnerabilitySource]:
    sources: list[VulnerabilitySource] = []
    feed = os.getenv("CYBERMORPH_VULN_FEED")
    if feed:
        sources.append(LocalFeedSource(feed))
    if os.getenv("CYBERMORPH_NVD_ENABLED") == "1":
        sources.append(NvdApiSource(True, os.getenv("CYBERMORPH_NVD_API_KEY") or None,
                                    int(os.getenv("CYBERMORPH_NVD_MAX_LOOKUPS", "10"))))
    return sources
