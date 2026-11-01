import socket
import re
from typing import Dict, Any, Optional

def probe_rtsp(ip: str, port: int = 554, timeout: float = 0.8) -> Dict[str, Any]:
    """
    Sends RTSP OPTIONS request to candidate host.
    Parses Server: header and Public: methods.
    Returns structured signal dictionary and probe findings.
    """
    result = {
        "success": False,
        "rtsp_server": None,
        "public_methods": None,
        "signal": None,
        "limitations": []
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) == 0:
            request = (
                f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: ANISAS-Module4-RTSP-Probe/1.0\r\n\r\n"
            )
            sock.sendall(request.encode("utf-8"))
            response_bytes = sock.recv(2048)
            sock.close()
            
            raw_response = response_bytes.decode("utf-8", errors="ignore")
            result["success"] = True
            
            server_match = re.search(r'Server:\s*([^\r\n]+)', raw_response, re.IGNORECASE)
            if server_match:
                result["rtsp_server"] = server_match.group(1).strip()
            
            methods_match = re.search(r'Public:\s*([^\r\n]+)', raw_response, re.IGNORECASE)
            if methods_match:
                result["public_methods"] = methods_match.group(1).strip()
            
            banner_str = result["rtsp_server"] or "Generic RTSP Service"
            known_vendors = ["hikvision", "dahua", "gstreamer", "axis", "hanwha", "uniview", "reolink", "vivotek"]
            is_known = any(kv in banner_str.lower() for kv in known_vendors)
            
            result["signal"] = {
                "signal": "rtsp_server_banner_match" if is_known else "rtsp_port_open",
                "tier": "MEDIUM" if is_known else "LOW",
                "weight": 0.45 if is_known else 0.20,
                "raw_reference": f"RTSP Server: {banner_str}"
            }
        else:
            result["limitations"].append(f"RTSP port {port} connection refused")
    except socket.timeout:
        result["limitations"].append(f"RTSP port {port} connection timed out")
    except Exception as e:
        result["limitations"].append(f"RTSP probe error: {str(e)}")

    return result
