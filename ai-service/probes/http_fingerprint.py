import requests
import re
from typing import Dict, Any

KNOWN_HTTP_SIGNATURES = {
    "Synology": ["/webman/index.cgi", "synology", "diskstation", "dsm", "synology inc."],
    "QNAP": ["/cgi-bin/login.html", "qnap", "qts", "qnap systems"],
    "Western Digital": ["mycloud", "wd my cloud", "western digital"],
    "Media Server": ["twonky", "minidlna", "readydlna", "serviio", "plex", "emby"],
    "Hikvision": ["/doc/page/login.asp", "hikvision", "web3.0", "app-login-container"],
    "Dahua": ["/RPC2_Login", "dahua", "web_login", "dahua-based"],
    "Axis": ["axis communications", "axis camera", "axis video server"],
    "Hanwha": ["hanwha", "samsung techwin", "wisenet"],
    "NETSurveillance": ["netsurveillance", "web video server", "ucweb"],
    "Generic CCTV Console": ["ipcamera", "network video recorder", "dvr login", "cctv web"]
}

def probe_http_fingerprint(ip: str, ports: list = None, timeout: float = 0.8) -> Dict[str, Any]:
    """
    Performs HTTP GET request on candidate web ports (80, 443, 5000, 5001, 8080, 8443, 8200, 32400).
    Matches title tag, Server headers, and HTML content against static NAS and IoT vendor signatures.
    Extracts model and firmware version information.
    """
    ports = ports or [80, 443, 5000, 5001, 8080, 8443, 8200, 32400]
    result = {
        "success": False,
        "vendor_hint": None,
        "model": None,
        "firmware": None,
        "title": None,
        "server_header": None,
        "signal": None,
        "limitations": []
    }

    for port in ports:
        scheme = "https" if port in [443, 8443, 5001] else "http"
        url = f"{scheme}://{ip}:{port}/"
        try:
            res = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            if res.status_code < 500:
                result["success"] = True
                result["server_header"] = res.headers.get("Server") or ""
                
                title_match = re.search(r'<title>(.*?)</title>', res.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result["title"] = title_match.group(1).strip()
                
                combined_content = f"{result['title'] or ''} {result['server_header'] or ''} {res.text[:10240]}".lower()

                # Extract Model
                model_m = re.search(r'(DS[0-9]{3,4}[a-z]*|RS[0-9]{3,4}[a-z]*|TS-[0-9]{3,4}[A-Z]*|MyCloud[A-Z0-9\-]*|DS-[0-9A-Z\-]+)', res.text + " " + (result["title"] or ""), re.I)
                if model_m:
                    result["model"] = model_m.group(1).strip()

                # Extract Firmware
                fw_m = re.search(r'(?:DSM|QTS|Version|Firmware)\s*:?\s*([Vv0-9\.\_\-build]{3,20})', res.text + " " + result["server_header"], re.I)
                if fw_m:
                    result["firmware"] = fw_m.group(1).strip()

                for vendor, sigs in KNOWN_HTTP_SIGNATURES.items():
                    if any(sig in combined_content for sig in sigs):
                        result["vendor_hint"] = vendor
                        result["signal"] = {
                            "signal": "http_title_vendor_match",
                            "tier": "HIGH" if vendor in ["Synology", "QNAP", "Western Digital"] else "MEDIUM",
                            "weight": 0.75 if vendor in ["Synology", "QNAP", "Western Digital"] else 0.40,
                            "raw_reference": f"HTTP Vendor Signature: '{vendor}' on Port {port} (Title: '{result['title']}', Server: '{result['server_header']}')"
                        }
                        break
                
                if result["signal"]:
                    break
        except requests.exceptions.Timeout:
            result["limitations"].append(f"HTTP fingerprint port {port} timed out")
        except Exception as e:
            result["limitations"].append(f"HTTP fingerprint port {port} error: {str(e)}")

    if not result["success"]:
        result["limitations"].append("No accessible HTTP web service responded on candidate ports")

    return result
