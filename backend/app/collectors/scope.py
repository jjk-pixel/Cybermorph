"""
Portée autorisée de la découverte active (Nmap) et configuration explicite des scans.

- Les cibles (CYBERMORPH_SCAN_TARGETS, par défaut le sous-réseau de la route par défaut) doivent être des réseaux
  privés, inclus dans les réseaux autorisés (CYBERMORPH_SCAN_ALLOWED, par défaut ce même sous-réseau), et de taille
  bornée (CYBERMORPH_SCAN_MAX_HOSTS). Une cible hors portée arrête le scan avant tout envoi de paquet.
- Les options Nmap sont fixées et lisibles ; les options agressives ou intrusives (scripts NSE, -A, timings
  rapides, débit forcé) sont refusées : CYBERMORPH reste un outil d'observation défensive.
"""
import ipaddress
import os
import shlex

DEFAULT_DISCOVERY_ARGS = "-sn -T3 --max-retries 2"
DEFAULT_DETAIL_ARGS = "-sV -O -T3 --host-timeout 30s"
DISCOVERY_TIMEOUT_S = 180
DETAIL_TIMEOUT_S = 90

FORBIDDEN_ARGS = ("--script", "-sC", "-A", "-T4", "-T5", "--min-rate", "--max-parallelism", "-f", "--mtu",
                  "-D", "--spoof-mac", "-S", "--badsum", "--data-length", "-iR")


class ScopeError(ValueError):
    """Cible ou option de scan refusée : le scan n'est pas lancé."""


def _networks(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    try:
        return [ipaddress.ip_network(n.strip(), strict=False) for n in raw.split(",") if n.strip()]
    except ValueError as e:
        raise ScopeError(f"Réseau invalide dans la configuration : {e}") from e


def max_hosts() -> int:
    return int(os.getenv("CYBERMORPH_SCAN_MAX_HOSTS", "1024"))


def validate_targets(targets: list, allowed: list, limit: int | None = None) -> list:
    """Retourne les réseaux cibles validés, ou lève ScopeError avec la raison du refus."""
    limit = limit or max_hosts()
    if not targets:
        raise ScopeError("Aucune cible de scan configurée")
    if not allowed:
        raise ScopeError("Aucun réseau autorisé : définir CYBERMORPH_SCAN_ALLOWED")
    validated = []
    for target in targets:
        net = target if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else _networks(str(target))[0]
        if not net.is_private or net.is_loopback or net.is_multicast or net.is_unspecified:
            raise ScopeError(f"{net} n'est pas un réseau privé : refusé")
        if net.num_addresses > limit:
            raise ScopeError(f"{net} compte {net.num_addresses} adresses, au-delà de la limite de {limit}")
        if not any(net.version == a.version and net.subnet_of(a) for a in allowed):
            raise ScopeError(f"{net} est hors des réseaux autorisés ({', '.join(map(str, allowed))})")
        validated.append(net)
    return validated


def validate_args(args: str) -> str:
    tokens = shlex.split(args)
    for token in tokens:
        if any(token == f or token.startswith(f + "=") or (f.startswith("--") and token.startswith(f)) for f in FORBIDDEN_ARGS):
            raise ScopeError(f"Option Nmap refusée (agressive ou intrusive) : {token}")
    return " ".join(tokens)


def scan_configuration(default_subnet: str | None) -> dict:
    """Configuration effective et validée ; lève ScopeError si elle sort de la portée autorisée."""
    targets_raw = os.getenv("CYBERMORPH_SCAN_TARGETS") or default_subnet or ""
    allowed_raw = os.getenv("CYBERMORPH_SCAN_ALLOWED") or default_subnet or ""
    targets = validate_targets(_networks(targets_raw), _networks(allowed_raw))
    return {
        "targets": targets,
        "discovery_args": validate_args(os.getenv("CYBERMORPH_NMAP_DISCOVERY_ARGS", DEFAULT_DISCOVERY_ARGS)),
        "detail_args": validate_args(os.getenv("CYBERMORPH_NMAP_DETAIL_ARGS", DEFAULT_DETAIL_ARGS)),
        "discovery_timeout": int(os.getenv("CYBERMORPH_NMAP_DISCOVERY_TIMEOUT", DISCOVERY_TIMEOUT_S)),
        "detail_timeout": int(os.getenv("CYBERMORPH_NMAP_DETAIL_TIMEOUT", DETAIL_TIMEOUT_S)),
    }


def in_scope(ip: str, targets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in targets)
