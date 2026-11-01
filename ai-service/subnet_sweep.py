import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

# Ports commonly answered by IoT / embedded / network equipment. The sweep is a
# lightweight TCP-connect pass only (no SYN, no privilege escalation), so it can
# run headless and without admin rights.
SWEEP_PORTS = [80, 443, 22, 554, 8080, 8443, 161, 1883, 8883, 3702, 1900, 5000, 5001, 8000, 8899, 8554, 37777, 102, 502, 1024]

# High-probability ports probed in the phase-1 liveness gate. A host answering any
# of these is alive and moves to the full port probe. Covers common web/SSH/RTSP,
# the closed-protocol camera ports (37777 Hikvision, 8554 RTSP, 3702 ONVIF), and
# IoT-only ports (1883/8883 MQTT, 9100 printer RAW, 502 Modbus, 102 S7 PLC) so a
# device exposing only an IoT port is not missed.
LIVENESS_PORTS = [80, 443, 22, 554, 8080, 8443, 5000, 37777, 8554, 1900, 3702, 1883, 8883, 9100, 502, 102]

MAX_SUBNET_ADDRESSES = 4096  # allow up to a /20

# Persistent probe pool. Recreating a fresh pool per sweep spawns ~256 threads at
# once, which starves the uvicorn request threadpool (progress polling included).
_SWEEP_EXECUTOR = ThreadPoolExecutor(max_workers=128, thread_name_prefix="sweep")


def _connect(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def sweep_subnet_hosts(cidr: str, ports: Optional[List[int]] = None, timeout: float = 0.25, max_workers: int = 128) -> List[Dict[str, Any]]:
    """Enumerate live hosts in a CIDR via two-phase parallel TCP-connect probes.

    Phase 1 probes a small high-probability port set for every address; only the
    hosts that answer move to Phase 2, which probes the full port list. This keeps
    the sweep fast even against ranges full of unreachable/filtered addresses,
    where the naive per-(ip, port) model burns one full connect timeout per port.

    Returns a list of {"ip", "openPorts"} for every host that answered at least
    one probe port, sorted by IP."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    if net.version != 4:
        raise ValueError("Only IPv4 subnets are supported for the sweep.")
    if net.num_addresses > MAX_SUBNET_ADDRESSES:
        raise ValueError(f"Subnet {cidr} is too large ({net.num_addresses} addresses). Maximum supported is /20 (4096).")

    port_list = list(dict.fromkeys(ports or SWEEP_PORTS))
    liveness = [p for p in LIVENESS_PORTS if p in port_list] or port_list[:4]
    ips = [str(h) for h in net.hosts()]
    if not ips or not port_list:
        return []

    # Phase 1: liveness gate (fast subset, full connect timeout).
    alive_ips = set()
    futures = {_SWEEP_EXECUTOR.submit(_connect, ip, p, timeout): (ip, p) for ip in ips for p in liveness}
    for fut in as_completed(futures):
        ip, p = futures[fut]
        try:
            if fut.result():
                alive_ips.add(ip)
        except Exception:
            pass

    # Phase 2: full port discovery on alive hosts only (short timeout - they answer quickly).
    open_by_ip: Dict[str, List[int]] = {}
    futures = {_SWEEP_EXECUTOR.submit(_connect, ip, p, min(timeout, 0.5)): (ip, p) for ip in alive_ips for p in port_list}
    for fut in as_completed(futures):
        ip, p = futures[fut]
        try:
            if fut.result():
                open_by_ip.setdefault(ip, []).append(p)
        except Exception:
            pass

    return [{"ip": ip, "openPorts": sorted(ps)} for ip, ps in sorted(open_by_ip.items(), key=lambda kv: [int(o) for o in kv[0].split(".")])]


def derive_cidr_from_ip(ip: str) -> str:
    """Derive the /24 of an IPv4 address (used to pre-scope Module 4 subnet scans)."""
    parts = ip.strip().split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    raise ValueError(f"Cannot derive a subnet from {ip!r}")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.0/30"
    t0 = time.time()
    found = sweep_subnet_hosts(target)
    print(f"swept {target} in {time.time() - t0:.2f}s -> {len(found)} live hosts")
    for h in found[:50]:
        print(" ", h["ip"], h["openPorts"])
