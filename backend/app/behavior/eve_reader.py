"""
Lecture incrémentale de Suricata eve.json (JSON lines), sans jamais modifier le fichier.

La position (inode, octet) est mémorisée en base. À la rotation (nouvel inode), la fin de l'ancien fichier est
relue dans l'archive `eve.json.1.gz` quand son début correspond à celui qu'on lisait (empreinte des premiers
octets) : aucun flux n'est perdu entre deux cycles. Une ligne incomplète (en cours d'écriture) n'est jamais lue.
"""
import gzip
import hashlib
import os
from pathlib import Path

HEAD_BYTES = 512
DEFAULT_MAX_BYTES = 64 * 1024 * 1024


def _head_hash(data: bytes) -> str:
    return hashlib.sha256(data[:HEAD_BYTES]).hexdigest()


def _complete_lines(chunk: bytes) -> tuple[list[str], int]:
    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        return [], 0
    complete = chunk[: last_newline + 1]
    return complete.decode("utf-8", errors="replace").splitlines(), len(complete)


def _read_rotated_tail(path: Path, state: dict, max_bytes: int) -> list[str]:
    """Fin de l'ancien fichier, retrouvée dans l'archive compressée si c'est bien le même fichier."""
    archive = Path(f"{path}.1.gz")
    plain = Path(f"{path}.1")
    try:
        if plain.exists() and plain.stat().st_ino == state.get("inode"):
            with open(plain, "rb") as f:
                f.seek(state["offset"])
                return _complete_lines(f.read(max_bytes))[0]
        if archive.exists():
            with gzip.open(archive, "rb") as f:
                if _head_hash(f.read(HEAD_BYTES)) != state.get("head"):
                    return []
                f.seek(state["offset"])
                return _complete_lines(f.read(max_bytes))[0]
    except (OSError, EOFError):
        return []
    return []


def read_new_lines(path: str | Path, state: dict | None, max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[list[str], dict, dict] | None:
    """
    Retourne (lignes, nouvel_état, infos) ou None si le fichier est absent.
    `max_bytes` borne une lecture (premier passage sur un gros fichier) : la suite est lue au cycle suivant.
    """
    path = Path(path)
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return None

    state = dict(state or {})
    info = {"rotated": False, "rotated_lines": 0, "truncated": False}
    lines: list[str] = []
    offset = state.get("offset", 0)

    if state.get("inode") is not None and state.get("inode") != stat.st_ino:
        info["rotated"] = True
        tail = _read_rotated_tail(path, state, max_bytes) if state.get("offset") else []
        info["rotated_lines"] = len(tail)
        lines.extend(tail)
        offset = 0
    elif stat.st_size < offset:
        info["truncated"] = True  # copytruncate : on repart du début
        offset = 0

    with open(path, "rb") as f:
        head = f.read(HEAD_BYTES)
        f.seek(offset)
        chunk = f.read(max_bytes)
    new_lines, consumed = _complete_lines(chunk)
    lines.extend(new_lines)
    return lines, {"inode": stat.st_ino, "offset": offset + consumed, "head": _head_hash(head)}, info
