"""
Correspondance logiciel observé ↔ enregistrement de vulnérabilité, avec un statut explicite.

- produit (vendor:product du CPE Nmap) différent → aucune correspondance ;
- version inconnue, ou impossible à situer dans la plage → « uncertain » ;
- version dans la plage, mais bannière de paquet de distribution (Ubuntu, Debian, RHEL…) → « uncertain » : les
  distributions rétroportent les correctifs sans changer le numéro de version amont ;
- version dans la plage, sans ambiguïté → « probable » (bannière annoncée, non vérifiée) ;
- « confirmed » n'est jamais automatique : c'est une décision de l'opérateur.
"""
import re

from app.vulnerabilities.versions import in_range

DISTRO_MARKERS = re.compile(r"ubuntu|debian|deb\d|\+deb|\bel\d|rhel|red hat|centos|rocky|alma|fedora|suse|alpine|raspbian", re.I)


def match(software: dict, record: dict) -> dict | None:
    """`software` : {vendor, product, version, banner}. Retourne {status, reason, range} ou None."""
    relevant = [r for r in record["ranges"] if r["vendor"] == software["vendor"] and r["product"] == software["product"]]
    if not relevant:
        return None
    version = software.get("version")
    if not version:
        return {"status": "uncertain", "reason": "Produit concerné, mais version non identifiée par Nmap", "range": relevant[0]}
    undecided = None
    for rng in relevant:
        verdict = in_range(version, rng)
        if verdict is True:
            if DISTRO_MARKERS.search(software.get("banner") or ""):
                return {"status": "uncertain", "range": rng,
                        "reason": f"Version {version} dans la plage affectée, mais paquet de distribution : correctif possiblement rétroporté"}
            return {"status": "probable", "range": rng,
                    "reason": f"Version annoncée {version} dans la plage affectée (bannière non vérifiée)"}
        if verdict is None:
            undecided = rng
    if undecided:
        return {"status": "uncertain", "range": undecided,
                "reason": f"Version {version} impossible à situer dans la plage publiée (formats différents)"}
    return None
