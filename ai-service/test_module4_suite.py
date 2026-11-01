import unittest
from classifier import score_classification
from cve_correlation import correlate_cves
from oui_lookup import lookup_mac_oui
from module4_orchestrator import execute_module4_scan

class TestModule4Suite(unittest.TestCase):

    def test_zero_signals(self):
        """Test Case: Zero signals returns 0 confidence and 'not surveillance-related'."""
        res = score_classification([])
        self.assertEqual(res["confidence"], 0.0)
        self.assertEqual(res["classification"], "not surveillance-related")
        self.assertFalse(res["is_classified"])

    def test_oui_only_low_confidence(self):
        """Test Case: OUI-only signal is LOW tier and MUST remain capped <= 0.30."""
        signals = [{
            "signal": "oui_vendor_match",
            "tier": "LOW",
            "weight": 0.15,
            "raw_reference": "MAC OUI match"
        }]
        res = score_classification(signals)
        self.assertLessEqual(res["confidence"], 0.30)
        self.assertEqual(res["classification"], "unclassified - LOW tier evidence only")
        self.assertFalse(res["is_classified"])

    def test_rtsp_port_open_only(self):
        """Test Case: Single RTSP port open signal is capped <= 0.30."""
        signals = [{
            "signal": "rtsp_port_open",
            "tier": "LOW",
            "weight": 0.20,
            "raw_reference": "RTSP port 554 open"
        }]
        res = score_classification(signals)
        self.assertLessEqual(res["confidence"], 0.30)
        self.assertEqual(res["classification"], "unclassified - RTSP port open only")
        self.assertFalse(res["is_classified"])

    def test_onvif_only_high_confidence(self):
        """Test Case: ONVIF SOAP match produces HIGH confidence classified asset."""
        signals = [{
            "signal": "onvif_manufacturer_match",
            "tier": "HIGH",
            "weight": 0.85,
            "raw_reference": "ONVIF Manufacturer: Hikvision"
        }]
        res = score_classification(signals)
        self.assertGreaterEqual(res["confidence"], 0.50)
        self.assertTrue(res["is_classified"])

    def test_medium_signal_stacking(self):
        """Test Case: Multiple MEDIUM signals stack to cross the classification threshold >= 0.50."""
        signals = [
            {"signal": "rtsp_server_banner_match", "tier": "MEDIUM", "weight": 0.45, "raw_reference": "Hikvision-RTSP"},
            {"signal": "http_title_vendor_match", "tier": "MEDIUM", "weight": 0.40, "raw_reference": "Hikvision Login"}
        ]
        res = score_classification(signals)
        self.assertGreaterEqual(res["confidence"], 0.50)
        self.assertTrue(res["is_classified"])

    def test_cve_gating_missing_version(self):
        """Test Case: CVE correlation MUST NOT emit specific CVE IDs if version is missing."""
        res = correlate_cves(hardware_vendor="Hikvision", product="DS-2CD2143G0", firmware_version="Unknown")
        self.assertTrue(len(res["vulnerabilities"]) > 0)
        self.assertIsNone(res["vulnerabilities"][0]["cve_id"])
        self.assertEqual(res["vulnerabilities"][0]["confidence"], "LOW")
        self.assertIn("firmware version unavailable — cannot confirm affected-version range", res["limitations"])

    def test_cve_gating_confirmed_version(self):
        """Test Case: CVE correlation emits specific CVE IDs when vendor, product, and version are present."""
        res = correlate_cves(hardware_vendor="Hikvision", product="DS-2CD2143G0", firmware_version="V5.5.80")
        self.assertTrue(len(res["vulnerabilities"]) > 0)
        self.assertIsNotNone(res["vulnerabilities"][0]["cve_id"])
        self.assertEqual(res["vulnerabilities"][0]["confidence"], "HIGH")

    def test_network_owner_vs_hardware_vendor_isolation(self):
        """Test Case: hardware_vendor MUST NOT copy Module 1 network_owner (ISP) name."""
        mock_hosts = [{
            "ip": "127.0.0.1",
            "ports": [80, 554],
            "banners": {}
        }]
        scan_res = execute_module4_scan(mock_hosts, network_owner_org="Comcast Cable Network")
        host_surveillance = scan_res["hosts"][0]["surveillance"]
        self.assertEqual(host_surveillance["network_owner"], "Comcast Cable Network")
        # hardware_vendor must be None or populated strictly from hardware evidence, NEVER equal to Comcast Cable Network
        if host_surveillance["hardware_vendor"]:
            self.assertNotEqual(host_surveillance["hardware_vendor"]["name"], "Comcast Cable Network")

    def test_ip_range_prediction_structurally_isolated(self):
        """Test Case: predicted_surveillance_ranges must be structurally separate from host surveillance objects."""
        mock_hosts = [{
            "ip": "192.168.1.100",
            "ports": [80, 554],
            "banners": {}
        }]
        scan_res = execute_module4_scan(mock_hosts, network_owner_org="Local Subnet")
        self.assertIn("predicted_surveillance_ranges", scan_res)
        self.assertIsInstance(scan_res["predicted_surveillance_ranges"], list)
        if scan_res["predicted_surveillance_ranges"]:
            self.assertEqual(scan_res["predicted_surveillance_ranges"][0]["evidence_status"], "PREDICTED")

    def test_candidate_port_normalization_and_zero_device_regression(self):
        """Test Case: Asserts dict/string port formats are parsed and candidate host is attached properly."""
        mock_hosts = [
            {"ip": "192.168.1.200", "ports": [{"port": 554, "service": "RTSP"}], "banners": {"rtsp": "Hikvision-RTSP"}},
            {"ip": "192.168.1.201", "ports": ["80", "8080"], "banners": "ONVIF GetDeviceInformation"}
        ]
        scan_res = execute_module4_scan(mock_hosts, network_owner_org="Test Enterprise Network")
        processed = scan_res["hosts"]
        self.assertEqual(len(processed), 2)
        
        # Verify first candidate
        host1 = processed[0]
        self.assertIn("surveillance", host1)
        self.assertTrue(host1["surveillance"]["is_candidate"])
        self.assertGreaterEqual(host1["surveillance"]["confidence"], 0.20)
        self.assertIn("evidence_status", host1["surveillance"])

    def test_iot_assumption_multi_port_no_crash(self):
        """Test Case: A host exposing several IoT-profile ports (e.g. 1883+9000+502)
        must not raise IndexError in the port-assumption heuristic - regression for
        the subnet sweep dropping hosts like 118.213.34.133 (only 3 of 5 shown)."""
        from main import _assume_iot_from_ports
        res = _assume_iot_from_ports([80, 443, 1883, 8000, 9000, 502, 4840])
        self.assertIsNotNone(res)
        self.assertTrue(res["isAssumed"])
        self.assertIn("confidence", res)
        self.assertGreater(res["confidence"], 0)
        # Highest-confidence profile must win (1883 MQTT = 0.88 beats 502/4840/9000).
        self.assertEqual(res["deviceCategory"], "IoT Gateway")
        # Single-profile port list must still resolve normally.
        res2 = _assume_iot_from_ports([554])
        self.assertEqual(res2["deviceType"], "RTSP IP Camera")

if __name__ == "__main__":
    unittest.main()
