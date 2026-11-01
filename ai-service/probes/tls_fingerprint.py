import socket
import ssl
from typing import Dict, Any

def probe_tls_cert(ip: str, ports: list = None, timeout: float = 0.8) -> Dict[str, Any]:
    """
    Inspects TLS/SSL certificate Common Name (CN) and Organization (O) fields on HTTPS ports.
    Emits low-medium tier signal if vendor keywords are detected in cert fields.
    """
    ports = ports or [443, 8443]
    result = {
        "success": False,
        "subject_cn": None,
        "organization": None,
        "vendor_hint": None,
        "signal": None,
        "limitations": []
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            ssl_sock = ctx.wrap_socket(sock, server_hostname=ip)
            ssl_sock.connect((ip, port))
            cert = ssl_sock.getpeercert(True)
            ssl_sock.close()

            # Parse cert binary structure if decoded dict is unavailable
            cert_text = str(cert)
            result["success"] = True

            known_vendors = ["hikvision", "dahua", "axis", "hanwha", "bosch", "foscam", "cp plus", "reolink", "vivotek"]
            for vendor in known_vendors:
                if vendor in cert_text.lower():
                    result["vendor_hint"] = vendor.title()
                    result["signal"] = {
                        "signal": "tls_cert_vendor_hint",
                        "tier": "LOW_MEDIUM",
                        "weight": 0.30,
                        "raw_reference": f"TLS Certificate Vendor Signature: '{result['vendor_hint']}' on Port {port}"
                    }
                    break
            if result["signal"]:
                break
        except socket.timeout:
            result["limitations"].append(f"TLS probe port {port} timed out")
        except Exception as e:
            result["limitations"].append(f"TLS probe port {port} error: {str(e)}")

    if not result["success"]:
        result["limitations"].append("No valid TLS certificate retrieved from candidate ports")

    return result
