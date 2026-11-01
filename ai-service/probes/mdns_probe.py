import socket
import re
from typing import Dict, Any

def probe_mdns(ip: str, port: int = 5353, timeout: float = 1.2) -> Dict[str, Any]:
    """
    Probes port 5353 for mDNS service information.
    Parses TXT records and host details for vendor, model, firmware, serial, and MAC address.
    """
    result = {
        "success": False,
        "vendor": None,
        "model": None,
        "firmware": None,
        "serial": None,
        "mac": None,
        "signal": None,
        "limitations": []
    }
    
    # Standard mDNS PTR query packet for local services (_services._dns-sd._udp.local)
    mdns_query = bytes.fromhex(
        "000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001"
    )
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(mdns_query, (ip, port))
        data, _ = sock.recvfrom(2048)
        sock.close()
        
        text = data.decode('latin-1', errors='ignore')
        result["success"] = True
        
        # Vendor detection
        if "synology" in text.lower() or "diskstation" in text.lower():
            result["vendor"] = "Synology"
        elif "qnap" in text.lower() or "qts" in text.lower():
            result["vendor"] = "QNAP"
        elif "mycloud" in text.lower() or "western digital" in text.lower():
            result["vendor"] = "Western Digital"

        # Model extraction
        model_m = re.search(r'(?:model=|Model:?\s*)([A-Z0-9\-_]{3,15})', text, re.I)
        if not model_m and result["vendor"] == "Synology":
            model_m = re.search(r'(DS[0-9]{3,4}[a-z]*|RS[0-9]{3,4}[a-z]*|FS[0-9]{3,4}|SA[0-9]{3,4})', text, re.I)
        if model_m:
            result["model"] = model_m.group(1).strip()

        # Firmware extraction
        v_maj = re.search(r'version_major=([0-9]+)', text, re.I)
        v_min = re.search(r'version_minor=([0-9]+)', text, re.I)
        v_build = re.search(r'version_build=([0-9]+)', text, re.I)
        if v_maj and v_min:
            b_str = f"-{v_build.group(1)}" if v_build else ""
            result["firmware"] = f"DSM {v_maj.group(1)}.{v_min.group(1)}{b_str}"

        # MAC Address extraction
        mac_m = re.search(r'([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})', text, re.I)
        if mac_m:
            result["mac"] = mac_m.group(1).replace("-", ":").upper()

        if result["vendor"]:
            result["signal"] = {
                "signal": "mdns_vendor_match",
                "tier": "HIGH",
                "weight": 0.85,
                "raw_reference": f"mDNS Response: Vendor='{result['vendor']}', Model='{result['model']}', FW='{result['firmware']}'"
            }

    except socket.timeout:
        result["limitations"].append(f"mDNS port {port} probe timed out")
    except Exception as e:
        result["limitations"].append(f"mDNS probe error: {str(e)}")

    return result
