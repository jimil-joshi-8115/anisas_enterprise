"""Topology inference from scan data using graph analysis (networkx).

Builds a graph ONLY from discovered facts: swept assets, their subnets,
the ASN origin, WAF presence and role hints from banners. When only a
single target was scanned, the graph is honest about it - no phantom
devices are ever synthesized.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

import networkx as nx


def _role_of(asset: Dict[str, Any]) -> str:
    text = " ".join(str(asset.get(k, "")) for k in
                    ("banner", "service", "deviceType", "vendor", "software")).lower()
    ports = set(int(p) for p in (asset.get("ports") or asset.get("openPorts") or []))
    if any(k in text for k in ("rtsp", "onvif", "camera", "hikvision", "dahua")) or 554 in ports:
        return "IOT"
    if any(k in text for k in ("nginx", "apache", "squid", "proxy", "waf")):
        return "PROXY"
    if 8291 in ports or "routeros" in text or "mikrotik" in text:
        return "GATEWAY_CANDIDATE"
    if any(k in text for k in ("mysql", "postgres", "mongo", "redis", "mariadb")):
        return "BACKEND_DB"
    return "HOST"


def _asset_ip(asset: Dict[str, Any]) -> Optional[str]:
    for key in ("ip", "ipAddress", "host"):
        v = asset.get(key)
        if v:
            return str(v)
    return None


def _node_meta(asset: Dict[str, Any]) -> Dict[str, Any]:
    """Real measured facts only - feeds the UI tooltip."""
    ports = asset.get("ports") or asset.get("openPorts") or []
    return {
        "ip": _asset_ip(asset),
        "ports": [int(p) for p in ports][:12] if ports else [],
        "banner": str(asset.get("banner") or asset.get("service") or "")[:160] or None,
        "deviceType": asset.get("deviceType") or asset.get("vendor") or None,
    }


def infer(target_ip: str, asn_info: Dict[str, Any], waf_vendor: str,
          discovered_assets: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    assets = [a for a in (discovered_assets or []) if _asset_ip(a)]
    G = nx.Graph()
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    asn_number = asn_info.get("asnNumber") or asn_info.get("asn") or "N/A"
    org = asn_info.get("organization") or "Unknown Origin"
    nodes.append({"id": "node-asn", "label": f"AS{asn_number} ({org})", "type": "ASN", "risk": "LOW"})
    G.add_node("node-asn")

    # Subnet grouping from real observed addresses.
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for a in assets:
        ip = _asset_ip(a) or ""
        parts = ip.split(".")
        if len(parts) == 4:
            groups[f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"].append(a)

    inferred_subnets = sorted(groups.keys())
    confidence = min(0.95, 0.35 + 0.05 * len(assets)) if len(assets) >= 3 else (
        0.30 if assets else 0.10)

    prev_id = "node-asn"

    # WAF / perimeter edge when Module 3 detected one.
    if waf_vendor and str(waf_vendor).lower() not in ("none", "unknown", "not detected"):
        wid = "node-waf"
        nodes.append({"id": wid, "label": f"Perimeter {waf_vendor}", "type": "SECURITY", "risk": "LOW"})
        G.add_node(wid)
        edges.append({"source": prev_id, "target": wid, "label": "BGP Route"})
        G.add_edge(prev_id, wid)
        prev_id = wid

    if not assets:
        # Single-target reality: no sweep data -> no invented hosts.
        tid = "node-target"
        nodes.append({"id": tid, "label": f"Target Host ({target_ip})", "type": "HOST",
                      "risk": "MEDIUM", "meta": {"ip": target_ip, "ports": [], "banner": None}})
        G.add_node(tid)
        edges.append({"source": prev_id, "target": tid, "label": "Routed"})
        return {
            "inferredSubnets": [],  # nothing observed beyond the single /32
            "nodeCount": len(nodes), "edgeCount": len(edges),
            "nodes": nodes, "edges": edges,
            "inferenceConfidence": round(confidence, 2),
            "basis": f"{len(assets)} discovered host(s); single-target scan",
        }

    # One subnet node per observed /24 with the gateway candidate inside it.
    for subnet, members in sorted(groups.items()):
        sid = f"node-subnet-{subnet.replace('/', '_').replace('.', '-')}"
        nodes.append({"id": sid, "label": subnet, "type": "SUBNET",
                      "risk": "LOW", "hostCount": len(members)})
        G.add_node(sid)
        edges.append({"source": prev_id, "target": sid, "label": "Origin Route"})
        G.add_edge(prev_id, sid)

        gw_candidates = [m for m in members if _role_of(m) == "GATEWAY_CANDIDATE"]
        proxy_nodes = [m for m in members if _role_of(m) == "PROXY"]
        for m in members:
            ip = _asset_ip(m)
            hid = f"node-host-{ip.replace('.', '-')}"
            role = _role_of(m)
            risk = "HIGH" if role == "IOT" else "MEDIUM" if role in ("BACKEND_DB", "GATEWAY_CANDIDATE") else "LOW"
            # Real role drives node type so the UI can icon/color it properly.
            ntype = role if role != "HOST" else "HOST"
            label = f"{ip}" + (f"\n{role.replace('_', ' ').title()}" if role != "HOST" else "")
            nodes.append({"id": hid, "label": label, "type": ntype, "risk": risk,
                          "meta": _node_meta(m)})
            G.add_node(hid)
            edges.append({"source": sid, "target": hid, "label": "L2 Adjacency"})
            G.add_edge(sid, hid)

            if proxy_nodes and role in ("IOT", "BACKEND_DB", "HOST") and hid != f"node-host-{_asset_ip(proxy_nodes[0]).replace('.', '-')}":
                pid = f"node-host-{_asset_ip(proxy_nodes[0]).replace('.', '-')}"
                edges.append({"source": pid, "target": hid, "label": "Inferred Proxy Path"})
                G.add_edge(pid, hid)

    return {
        "inferredSubnets": inferred_subnets,
        "subnetCount": len(inferred_subnets),
        "discoveredHosts": len(assets),
        "nodeCount": len(G.nodes), "edgeCount": G.number_of_edges(),
        "nodes": nodes, "edges": edges,
        "graphDensity": round(nx.density(G), 4) if G.number_of_nodes() else 0.0,
        "connectedComponents": nx.number_connected_components(G) if G.number_of_nodes() else 0,
        "inferenceConfidence": round(confidence, 2),
        "basis": f"{len(assets)} discovered host(s) across {len(inferred_subnets)} subnet(s)",
    }
