"""
Exécution maîtrisée des cycles de collecte : verrou exclusif, arrêt propre, journal des exécutions.

- Un seul cycle à la fois : verrou `flock` non bloquant (CYBERMORPH_LOCK_PATH). Un second lancement (manuel ou timer)
  est enregistré comme « skipped » et s'arrête sans rien toucher.
- Arrêt propre : SIGTERM / SIGINT lèvent un drapeau que les collecteurs consultent entre deux hôtes ; l'étape en
  cours se termine « interrupted » et les étapes suivantes ne sont pas lancées.
- Chaque étape est tracée dans `collector_runs` (statut, durée, erreur tronquée, statistiques).
"""
import fcntl
import os
import signal
import threading
import time
from contextlib import contextmanager
from datetime import datetime, UTC

from app.database import SessionLocal
from app.models.collector import CollectorRun

LOCK_PATH = os.getenv("CYBERMORPH_LOCK_PATH", "/opt/cybermorph/backend/.cybermorph-cycle.lock")
ERROR_MAX_LENGTH = 500

stop_requested = threading.Event()


class CycleBusy(RuntimeError):
    """Un autre cycle détient le verrou."""


class Interrupted(RuntimeError):
    """Arrêt demandé pendant une étape."""


def install_signal_handlers():
    def handler(signum, _frame):
        stop_requested.set()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, handler)


def check_stop():
    if stop_requested.is_set():
        raise Interrupted("Arrêt demandé (signal reçu)")


@contextmanager
def cycle_lock(path: str = LOCK_PATH):
    handle = open(path, "a+")
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CycleBusy(f"Un cycle de collecte est déjà en cours (verrou {path})")
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        handle.close()


def sanitize_error(error: BaseException | str) -> str:
    """Message court et sans secret : l'URL de la base (mot de passe) n'est jamais recopiée."""
    text = str(error).strip()
    text = text.splitlines()[0] if text else (type(error).__name__ if isinstance(error, BaseException) else "")
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        text = text.replace(database_url, "<DATABASE_URL>")
    return text[:ERROR_MAX_LENGTH]


def record_run(collector: str, status: str, started_at: datetime, cycle_id: str | None = None,
               error: str | None = None, stats: dict | None = None, session_factory=SessionLocal) -> None:
    finished = datetime.now(UTC)
    db = session_factory()
    try:
        db.add(CollectorRun(
            cycle_id=cycle_id, collector=collector, status=status, started_at=started_at, finished_at=finished,
            duration_s=round((finished - started_at).total_seconds(), 2), error=error, stats=stats,
        ))
        db.commit()
    finally:
        db.close()


def run_step(collector: str, fn, cycle_id: str | None = None, logger=None, session_factory=SessionLocal) -> tuple[str, object]:
    """
    Exécute une étape et la trace. `fn` peut retourner un dict de statistiques, éventuellement avec une clé
    `status` (« partial », « interrupted »…) ; une exception est un échec, Interrupted une interruption.
    """
    started = datetime.now(UTC)
    t0 = time.monotonic()
    status, stats, error, result = "success", None, None, None
    try:
        result = fn()
        if isinstance(result, dict):
            stats = {k: v for k, v in result.items() if k not in ("status", "error")}
            status = result.get("status", "failed" if result.get("error") else "success")
            error = sanitize_error(result["error"]) if result.get("error") else None
    except Interrupted as e:
        status, error = "interrupted", sanitize_error(e)
    except Exception as e:  # noqa: BLE001 — une étape en échec ne doit pas arrêter les suivantes
        status, error = "failed", sanitize_error(e)
    if logger:
        logger.info("collector_step", extra={"collector": collector, "status": status, "cycle_id": cycle_id,
                                             "duration_s": round(time.monotonic() - t0, 2), "error": error})
    try:
        record_run(collector, status, started, cycle_id, error, stats, session_factory)
    except Exception as e:  # noqa: BLE001 — la base peut être la cause de l'échec
        if logger:
            logger.error("collector_run_not_recorded", extra={"collector": collector, "error": sanitize_error(e)})
    return status, result
