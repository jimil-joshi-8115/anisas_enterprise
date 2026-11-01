from typing import Dict, Any, Optional

IEEE_OUI_TABLE = {
    # Synology Incorporated
    "00:11:32": "Synology Incorporated",
    "00:22:33": "Synology Incorporated",
    "00:25:11": "Synology Incorporated",
    "00:26:18": "Synology Incorporated",
    "00:28:18": "Synology Incorporated",
    "00:30:48": "Synology Incorporated",
    "00:90:A9": "Synology Incorporated",
    "00:C0:6C": "Synology Incorporated",
    # QNAP Systems
    "00:08:9B": "QNAP Systems",
    "00:0E:8F": "QNAP Systems",
    "00:16:01": "QNAP Systems",
    "00:19:FB": "QNAP Systems",
    "00:20:54": "QNAP Systems",
    "00:24:1D": "QNAP Systems",
    "00:24:3B": "QNAP Systems",
    "00:25:24": "QNAP Systems",
    # Surveillance & Camera Vendors
    "00:40:8C": "Axis Communications",
    "18:68:CB": "Hangzhou Hikvision Digital Technology",
    "28:57:BE": "Hangzhou Hikvision Digital Technology",
    "3C:EF:8C": "Hangzhou Hikvision Digital Technology",
    "40:13:6C": "Zhejiang Dahua Technology",
    "38:AF:29": "Zhejiang Dahua Technology",
    "00:1A:07": "Cisco Systems",
    "00:27:22": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "00:04:7D": "Pelco Inc",
    "00:07:5D": "Bosch Security Systems",
    "00:0F:7C": "Hanwha Techwin",
    # Wireless Infrastructure / AP / Router Vendors
    "84:90:0A": "Xiaomi Communications",
    "92:90:0A": "Xiaomi Communications",
    "78:11:DC": "Xiaomi Communications",
    "64:09:80": "Xiaomi Communications",
    "A0:51:0B": "Intel Corporate",
    "F8:75:A4": "Intel Corporate",
    "B0:BE:76": "TP-Link Technologies",
    "50:FA:84": "TP-Link Technologies",
    "D4:DA:21": "TP-Link Technologies",
    "C0:56:27": "TP-Link Technologies",
    "04:D9:F5": "Ubiquiti Inc.",
    "18:D6:C7": "Ubiquiti Inc.",
    "74:83:C2": "Ubiquiti Inc.",
    "F0:9F:C2": "Ubiquiti Inc.",
    "F4:F2:6D": "TP-Link Technologies",
    "FC:EC:DA": "Aruba Networks (HPE)",
    "48:8F:5A": "MikroTik",
    "E4:8D:8C": "MikroTik",
    "00:13:92": "Ruckus Wireless (CommScope)",
    "58:6D:8F": "Cisco Systems",
    "00:18:0A": "Cisco Meraki Inc.",
    "00:0B:86": "Aruba Networks (HPE)",
    "00:1B:67": "Cisco Systems Inc.",
    "50:C7:BF": "TP-Link Technologies",
    "D8:C7:71": "Cisco Systems",
    "A8:70:E5": "Huawei Technologies",
    "00:1F:C6": "Huawei Technologies",
    "10:BF:48": "ZTE Corporation",
    "54:25:EA": "ZTE Corporation",
    "30:B5:C2": "NETGEAR",
    "20:4E:7F": "NETGEAR",
    "9C:D3:6C": "NETGEAR",
    "AC:84:C6": "D-Link Systems",
    "28:10:7B": "D-Link Systems",
    "D8:5D:4C": "ASUSTek Computer",
    "8C:11:CB": "ASUSTek Computer",
    "2C:30:33": "ASUSTek Computer",
    "34:29:8F": "Zyxel Communications",
    "E4:8D:8C": "MikroTik"
}

def lookup_mac_oui(mac_address: Optional[str]) -> Dict[str, Any]:
    """
    Normalizes MAC address format (00-11-32-XX-XX-XX -> 00:11:32)
    and checks against static IEEE OUI database.
    """
    result = {
        "success": False,
        "normalized_mac": None,
        "vendor": None,
        "signal": None,
        "limitations": []
    }

    if not mac_address:
        result["limitations"].append("No MAC address provided for OUI lookup")
        return result

    clean_mac = mac_address.strip().replace("-", ":").upper()
    result["normalized_mac"] = clean_mac
    prefix = clean_mac[:8]

    if prefix in IEEE_OUI_TABLE:
        vendor_name = IEEE_OUI_TABLE[prefix]
        result["success"] = True
        result["vendor"] = vendor_name
        result["signal"] = {
            "signal": "oui_mac_vendor_match",
            "tier": "HIGH",
            "weight": 0.80,
            "raw_reference": f"MAC OUI Prefix '{prefix}' maps to '{vendor_name}'"
        }
    else:
        result["limitations"].append(f"MAC OUI prefix '{prefix}' not matched in local database")

    return result
