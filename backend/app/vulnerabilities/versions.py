"""
Comparaison prudente de versions logicielles et lecture des CPE (2.2 et 2.3).

Une version est découpée en segments numériques et alphabétiques (« 9.6p1 » → 9, 6, p, 1). Si deux versions ne se
comparent pas sans ambiguïté (formats différents), la comparaison renvoie None : la correspondance sera « incertaine »
plutôt que devinée.
"""
import re

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")


def tokens(version: str | None) -> list | None:
    if not version:
        return None
    parts = [int(t) if t.isdigit() else t.lower() for t in _TOKEN.findall(version)]
    return parts or None


def compare(a: str | None, b: str | None) -> int | None:
    """-1, 0 ou 1 ; None si l'une des versions est absente ou si les formats divergent."""
    ta, tb = tokens(a), tokens(b)
    if ta is None or tb is None:
        return None
    for x, y in zip(ta, tb):
        if type(x) is not type(y):
            return None
        if x != y:
            return -1 if x < y else 1
    if len(ta) == len(tb):
        return 0
    # « 9.6 » contre « 9.6.1 » : la plus courte précède ; « 9.6 » contre « 9.6p1 » : suffixe alphabétique, ambigu
    longer = ta if len(ta) > len(tb) else tb
    if isinstance(longer[min(len(ta), len(tb))], str):
        return None
    return -1 if len(ta) < len(tb) else 1


def in_range(version: str, rng: dict) -> bool | None:
    """La version est-elle dans la plage publiée ? None si on ne peut pas le dire."""
    if rng.get("version") not in (None, "*", "-", ""):
        c = compare(version, rng["version"])
        return None if c is None else c == 0
    checks = [
        ("start_including", lambda c: c >= 0), ("start_excluding", lambda c: c > 0),
        ("end_including", lambda c: c <= 0), ("end_excluding", lambda c: c < 0),
    ]
    bounded = False
    for key, ok in checks:
        bound = rng.get(key)
        if not bound:
            continue
        bounded = True
        c = compare(version, bound)
        if c is None:
            return None
        if not ok(c):
            return False
    # Aucune borne ni version précise : « toutes versions », trop vague pour conclure
    return True if bounded else None


def parse_cpe(cpe: str | None) -> dict | None:
    """{part, vendor, product, version} depuis « cpe:/a:openbsd:openssh:9.6p1 » ou « cpe:2.3:a:openbsd:openssh:9.6p1:… »."""
    if not cpe:
        return None
    if cpe.startswith("cpe:2.3:"):
        fields = cpe.split(":")[2:]
    elif cpe.startswith("cpe:/"):
        fields = cpe[5:].split(":")
    else:
        return None
    fields += [""] * (4 - len(fields))
    part, vendor, product, version = fields[:4]
    if not vendor or not product:
        return None
    version = None if version in ("", "*", "-") else version
    return {"part": part, "vendor": vendor.lower(), "product": product.lower(), "version": version}
