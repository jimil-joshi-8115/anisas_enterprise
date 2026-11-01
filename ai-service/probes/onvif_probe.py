import requests
import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional

SOAP_GET_DEV_INFO = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Body><tds:GetDeviceInformation xmlns:tds="http://www.onvif.org/ver10/device/wsdl"/></s:Body>'
    '</s:Envelope>'
)

def probe_onvif(ip: str, ports: list = None, timeout: float = 0.8) -> Dict[str, Any]:
    """
    POSTs ONVIF SOAP GetDeviceInformation probe to candidate ports.
    Parses Manufacturer, Model, FirmwareVersion, SerialNumber.
    Returns structured signal dictionary and probe findings.
    """
    ports = ports or [80, 8080, 8000, 8899]
    result = {
        "success": False,
        "manufacturer": None,
        "model": None,
        "firmware": None,
        "serial": None,
        "signal": None,
        "limitations": []
    }

    for port in ports:
        url = f"http://{ip}:{port}/onvif/device_service"
        try:
            res = requests.post(url, data=SOAP_GET_DEV_INFO, timeout=timeout, headers={"Content-Type": "application/soap+xml"})
            if res.status_code == 200 and ("Envelope" in res.text or "GetDeviceInformationResponse" in res.text):
                result["success"] = True
                
                # RegEx XML fallbacks for robust parsing
                mfr_match = re.search(r'<(?:[a-zA-Z0-9]+:)?Manufacturer>([^<]+)</', res.text, re.IGNORECASE)
                model_match = re.search(r'<(?:[a-zA-Z0-9]+:)?Model>([^<]+)</', res.text, re.IGNORECASE)
                fw_match = re.search(r'<(?:[a-zA-Z0-9]+:)?FirmwareVersion>([^<]+)</', res.text, re.IGNORECASE)
                serial_match = re.search(r'<(?:[a-zA-Z0-9]+:)?SerialNumber>([^<]+)</', res.text, re.IGNORECASE)

                if mfr_match:
                    result["manufacturer"] = mfr_match.group(1).strip()
                if model_match:
                    result["model"] = model_match.group(1).strip()
                if fw_match:
                    result["firmware"] = fw_match.group(1).strip()
                if serial_match:
                    result["serial"] = serial_match.group(1).strip()

                if result["manufacturer"] or result["model"]:
                    result["signal"] = {
                        "signal": "onvif_manufacturer_match",
                        "tier": "HIGH",
                        "weight": 0.85,
                        "raw_reference": f"ONVIF Manufacturer: {result['manufacturer']}, Model: {result['model']}, FW: {result['firmware']}"
                    }
                    break
        except requests.exceptions.Timeout:
            result["limitations"].append(f"ONVIF probe port {port} timed out")
        except Exception as e:
            result["limitations"].append(f"ONVIF probe port {port} error: {str(e)}")

    if not result["success"]:
        result["limitations"].append("No valid ONVIF SOAP GetDeviceInformation response received")

    return result
