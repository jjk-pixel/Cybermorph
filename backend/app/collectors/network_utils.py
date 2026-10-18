import subprocess
import re


def get_local_ip_and_interface():
    """Déduit l'IP locale et l'interface réseau à partir de la route par défaut."""
    result = subprocess.run(["ip", "route"], capture_output=True, text=True)
    for line in result.stdout.split("\n"):
        if line.startswith("default"):
            match = re.search(r"dev\s+(\S+).*src\s+([\d.]+)", line)
            if match:
                interface, ip = match.group(1), match.group(2)
                return ip, interface

    # Fallback si la ligne "default" n'a pas le bon format
    for line in result.stdout.split("\n"):
        match = re.search(r"dev\s+(\S+).*src\s+([\d.]+)", line)
        if match:
            return match.group(2), match.group(1)

    raise RuntimeError("Impossible de déterminer l'IP locale et l'interface réseau.")

def get_local_subnet():
    """Déduit le sous-réseau local (ex: 192.168.43.0/24) en se basant sur l'interface de la route par défaut."""
    _, interface = get_local_ip_and_interface()

    result = subprocess.run(["ip", "route"], capture_output=True, text=True)
    for line in result.stdout.split("\n"):
        if "default" in line:
            continue
        match = re.match(rf"^([\d.]+/\d+)\s+dev\s+{re.escape(interface)}\b", line)
        if match:
            return match.group(1)

    raise RuntimeError(f"Impossible de déterminer le sous-réseau local pour l'interface {interface}.")



def get_default_gateway() -> str | None:
    """IP de la passerelle par défaut (`ip route`), ou None : seul fait fiable qui désigne la passerelle du segment."""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    for line in result.stdout.split("\n"):
        match = re.match(r"^default\s+via\s+([\d.]+)", line)
        if match:
            return match.group(1)
    return None
