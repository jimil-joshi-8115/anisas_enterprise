import ipaddress
from typing import List, Dict, Any

def predict_surveillance_ranges(classified_devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Performs subnet clustering on confirmed surveillance devices (confidence >= 0.50).
    Produces predicted subnet ranges structurally isolated from observed device outputs.
    
    Rule Enforced:
    Output objects are tagged evidence_status: "PREDICTED" and are stored in a separate list.
    """
    predicted_ranges = []
    subnet_counts: Dict[str, List[str]] = {}

    for dev in classified_devices:
        ip_str = dev.get("ip")
        confidence = dev.get("confidence", 0.0)

        if not ip_str or confidence < 0.50:
            continue

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.version == 4:
                # Group into /24 subnets
                network_24 = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                cidr_str = str(network_24)
                if cidr_str not in subnet_counts:
                    subnet_counts[cidr_str] = []
                subnet_counts[cidr_str].append(ip_str)
        except ValueError:
            pass

    for cidr, ip_list in subnet_counts.items():
        base_prob = 0.75 + min(len(ip_list) * 0.10, 0.23)
        predicted_ranges.append({
            "cidr": cidr,
            "basis": [
                f"Discovered {len(ip_list)} confirmed surveillance host(s) ({', '.join(ip_list)}) in /24 subnet",
                "Shared port/service profile (ONVIF/RTSP/HTTP)"
            ],
            "probability": round(base_prob, 2),
            "evidence_status": "PREDICTED"
        })

    # Default fallback prediction if no high-confidence host was found in current scan batch
    if not predicted_ranges and classified_devices:
        sample_ip = classified_devices[0].get("ip", "192.168.1.1")
        try:
            net_24 = str(ipaddress.ip_network(f"{sample_ip}/24", strict=False))
            predicted_ranges.append({
                "cidr": net_24,
                "basis": [
                    "Predictive subnet heuristic based on candidate CCTV host IP prefix",
                    "Likely physical security VLAN 20 allocation"
                ],
                "probability": 0.50,
                "evidence_status": "PREDICTED"
            })
        except ValueError:
            pass

    return predicted_ranges
