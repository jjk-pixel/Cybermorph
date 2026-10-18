"""
Journaux structurés : une ligne JSON par événement (horodatage UTC, niveau, journal, message, champs).

Les champs passés via `extra=` sont recopiés tels quels ; aucune donnée sensible n'y est mise (pas d'URL de base,
pas de jeton). Le fichier par défaut reste `backend/cybermorph.log` (CYBERMORPH_LOG_PATH).
"""
import json
import logging
import os
import re
from datetime import datetime, UTC

LOG_PATH = os.getenv("CYBERMORPH_LOG_PATH", "/opt/cybermorph/backend/cybermorph.log")
_RESERVED = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}
_URL_CREDENTIALS = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@")
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")


def redact(text: str) -> str:
    """Masque les identifiants d'URL (scheme://user:mot_de_passe@) et les jetons Bearer."""
    return _BEARER.sub(r"\1<masqué>", _URL_CREDENTIALS.sub(r"\1<identifiants masqués>@", text))


def describe_exception(exc: BaseException) -> dict:
    """Type, message masqué et lieu de l'exception : de quoi diagnostiquer sans recopier de secret."""
    tb = exc.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    where = f"{tb.tb_frame.f_code.co_filename.rsplit('/', 2)[-1]}:{tb.tb_lineno}" if tb is not None else None
    message = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
    return {"error_type": type(exc).__name__, "error": redact(message)[:500], "where": where}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        for key, value in vars(record).items():
            if key not in _RESERVED and not key.startswith("_"):
                entry[key] = redact(value) if isinstance(value, str) else value
        if record.exc_info and record.exc_info[1] is not None:
            entry.update(describe_exception(record.exc_info[1]))
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure_logging(path: str | None = None, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("cybermorph")
    if not any(getattr(h, "_cybermorph", False) for h in logger.handlers):
        try:
            handler = logging.FileHandler(path or LOG_PATH)
        except OSError:
            # Fichier non accessible (droits, chemin) : les événements restent visibles sur la sortie d'erreur
            handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        handler._cybermorph = True
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
