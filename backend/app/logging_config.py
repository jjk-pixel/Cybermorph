"""
Journaux structurés : une ligne JSON par événement (horodatage UTC, niveau, journal, message, champs).

Les champs passés via `extra=` sont recopiés tels quels ; aucune donnée sensible n'y est mise (pas d'URL de base,
pas de jeton). Le fichier par défaut reste `backend/cybermorph.log` (CYBERMORPH_LOG_PATH).
"""
import json
import logging
import os
from datetime import datetime, UTC

LOG_PATH = os.getenv("CYBERMORPH_LOG_PATH", "/opt/cybermorph/backend/cybermorph.log")
_RESERVED = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _RESERVED and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info).splitlines()[-1]
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
