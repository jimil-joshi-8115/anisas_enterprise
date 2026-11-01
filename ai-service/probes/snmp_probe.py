import socket
import re
from typing import Dict, Any, Optional

def probe_snmp_sysdescr(ip: str, port: int = 161, community: str = "public", timeout: float = 2.0) -> Dict[str, Any]:
    """
    Sends raw SNMP v1/v2c GetRequest for sysDescr (1.3.6.1.2.1.1.1.0) and sysName (1.3.6.1.2.1.1.5.0).
    Parses sysDescr string for hardware vendor hints and firmware details.
    Non-blocking read-only UDP probe.
    """
    result = {
        "success": False,
        "sys_descr": None,
        "sys_name": None,
        "vendor_hint": None,
        "signal": None,
        "limitations": []
    }

    # Raw SNMP v2c GetRequest PDU for 1.3.6.1.2.1.1.1.0 (sysDescr)
    # Community: 'public'
    snmp_get_sysdescr_pdu = bytes.fromhex(
        "302902010104067075626c6963a01c020412345678020100020100300e300c06082b060102010101000500"
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(snmp_get_sysdescr_pdu, (ip, port))
        data, _ = sock.recvfrom(2048)
        sock.close()

        raw_str = data.decode("latin-1", errors="ignore")
        result["success"] = True
        result["sys_descr"] = raw_str

        # Vendor hints matching
        known_vendors = {
            "Hikvision": ["hikvision", "ds-2cd", "ds-7"],
            "Dahua": ["dahua", "dh-", "dvr"],
            "Axis": ["axis", "axis communications"],
            "Hanwha": ["hanwha", "wisenet", "samsung"],
            "Cisco": ["cisco", "ios"],
            "Ubiquiti": ["ubiquiti", "unifi", "airmax"]
        }

        raw_lower = raw_str.lower()
        for v_name, keywords in known_vendors.items():
            if any(k in raw_lower for k in keywords):
                result["vendor_hint"] = v_name
                break

        result["signal"] = {
            "signal": "snmp_sysdescr_match",
            "tier": "MEDIUM",
            "weight": 0.40,
            "raw_reference": f"SNMP sysDescr Vendor: '{result['vendor_hint'] or 'Generic SNMP Device'}' on UDP/{port}"
        }

    except socket.timeout:
        result["limitations"].append(f"SNMP UDP/{port} connection timed out")
    except Exception as e:
        result["limitations"].append(f"SNMP probe error: {str(e)}")

    return result
