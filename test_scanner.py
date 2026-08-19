"""
tests/test_scanner.py — Unit tests for Smart Port Scanner
Run with: python -m pytest tests/ -v
      or: python -m unittest discover tests/
"""

import unittest
import sys
import os

# Allow imports from parent
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.scanner import get_service_name, SERVICE_MAP
from core.banner  import fingerprint, guess_os
from core.vuln    import analyze, risk_summary, Risk, Finding
from core.recon   import parse_whois_fields


# ─────────────────────────────────────────────────────────
class TestServiceMapping(unittest.TestCase):

    def test_known_port_returns_service(self):
        self.assertEqual(get_service_name(22),  "SSH")
        self.assertEqual(get_service_name(80),  "HTTP")
        self.assertEqual(get_service_name(443), "HTTPS")
        self.assertEqual(get_service_name(3306),"MySQL")

    def test_unknown_port_returns_unknown_or_socket_name(self):
        result = get_service_name(9999)
        self.assertIsInstance(result, str)

    def test_service_map_contains_critical_ports(self):
        critical = [21, 22, 23, 25, 80, 443, 3306, 3389]
        for port in critical:
            self.assertIn(port, SERVICE_MAP,
                          f"Port {port} missing from SERVICE_MAP")


# ─────────────────────────────────────────────────────────
class TestBannerFingerprinting(unittest.TestCase):

    def test_openssh_fingerprint(self):
        svc, ver = fingerprint("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
        self.assertEqual(svc, "OpenSSH")
        self.assertIn("8.9", ver)

    def test_apache_fingerprint(self):
        svc, ver = fingerprint("HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)")
        self.assertEqual(svc, "Apache")
        self.assertIn("2.4", ver)

    def test_nginx_fingerprint(self):
        svc, ver = fingerprint("Server: nginx/1.24.0")
        self.assertEqual(svc, "nginx")
        self.assertIn("1.24", ver)

    def test_vsftpd_fingerprint(self):
        svc, ver = fingerprint("220 (vsFTPd 3.0.3)")
        self.assertEqual(svc, "vsFTPd")
        self.assertIn("3.0.3", ver)

    def test_redis_pong(self):
        svc, _ = fingerprint("+PONG")
        self.assertEqual(svc, "Redis")

    def test_empty_banner_returns_unknown(self):
        svc, ver = fingerprint("")
        self.assertEqual(svc, "Unknown")
        self.assertEqual(ver, "")

    def test_no_banner_string(self):
        svc, ver = fingerprint("No banner")
        self.assertEqual(svc, "Unknown")

    def test_os_linux_detection(self):
        banners = ["SSH-2.0-OpenSSH_8.9 Ubuntu", "Apache/2.4 Ubuntu"]
        self.assertIn("Linux", guess_os(banners))

    def test_os_windows_detection(self):
        banners = ["Microsoft-IIS/10.0", "Windows Server 2019"]
        self.assertIn("Windows", guess_os(banners))

    def test_os_unknown(self):
        self.assertEqual(guess_os([]), "Unknown")


# ─────────────────────────────────────────────────────────
class TestVulnerabilityDetection(unittest.TestCase):

    def _make_result(self, port, banner="No banner"):
        return {"port": port, "state": "open", "protocol": "tcp",
                "service": "Test", "banner": banner}

    def test_telnet_is_critical(self):
        findings = analyze([self._make_result(23)])
        risks = [f.risk for f in findings]
        self.assertIn(Risk.CRITICAL, risks)

    def test_ftp_is_high(self):
        findings = analyze([self._make_result(21)])
        risks = [f.risk for f in findings]
        self.assertIn(Risk.HIGH, risks)

    def test_redis_is_high(self):
        findings = analyze([self._make_result(6379, "+PONG")])
        risks = [f.risk for f in findings]
        self.assertIn(Risk.HIGH, risks)

    def test_vsftpd_backdoor_detected(self):
        results = [self._make_result(21, "220 (vsFTPd 2.3.4)")]
        findings = analyze(results)
        titles = [f.title for f in findings]
        self.assertTrue(any("backdoor" in t.lower() or "vsFTPd" in t
                            for t in titles))

    def test_clean_port_no_findings(self):
        # Port 9999 has no rules
        findings = analyze([self._make_result(9999)])
        self.assertEqual(len(findings), 0)

    def test_risk_summary_counts(self):
        findings = [
            Finding(22, Risk.HIGH,    "Test", "desc"),
            Finding(23, Risk.CRITICAL,"Test", "desc"),
            Finding(80, Risk.INFO,    "Test", "desc"),
        ]
        counts = risk_summary(findings)
        self.assertEqual(counts[Risk.HIGH], 1)
        self.assertEqual(counts[Risk.CRITICAL], 1)
        self.assertEqual(counts[Risk.INFO], 1)
        self.assertEqual(counts[Risk.MEDIUM], 0)

    def test_no_duplicate_findings(self):
        # Same port, same rule → deduplicated
        results = [self._make_result(21), self._make_result(21)]
        findings = analyze(results)
        ftp_findings = [f for f in findings if f.port == 21]
        titles = [f.title for f in ftp_findings]
        self.assertEqual(len(titles), len(set(titles)))

    def test_findings_sorted_by_severity(self):
        results = [self._make_result(80), self._make_result(23),
                   self._make_result(21)]
        findings = analyze(results)
        if len(findings) >= 2:
            from core.vuln import RISK_ORDER
            for i in range(len(findings) - 1):
                self.assertGreaterEqual(
                    RISK_ORDER[findings[i].risk],
                    RISK_ORDER[findings[i+1].risk]
                )


# ─────────────────────────────────────────────────────────
class TestPortParsing(unittest.TestCase):

    def _parse_range(self, s: str):
        parts = s.split("-")
        return (int(parts[0]), int(parts[1]))

    def test_valid_range(self):
        lo, hi = self._parse_range("1-1000")
        self.assertEqual(lo, 1)
        self.assertEqual(hi, 1000)

    def test_single_port_range(self):
        lo, hi = self._parse_range("80-80")
        self.assertEqual(lo, hi)

    def test_range_boundary(self):
        lo, hi = self._parse_range("1-65535")
        self.assertEqual(lo, 1)
        self.assertEqual(hi, 65535)


# ─────────────────────────────────────────────────────────
class TestWhoisParser(unittest.TestCase):

    RAW = """
    netname:        EXAMPLE-NET
    country:        US
    descr:          Example Organisation
    abuse-mailbox:  abuse@example.com
    """

    def test_parses_netname(self):
        fields = parse_whois_fields(self.RAW)
        self.assertIn("Network Name", fields)

    def test_parses_country(self):
        fields = parse_whois_fields(self.RAW)
        self.assertIn("Country", fields)
        self.assertEqual(fields["Country"], "US")

    def test_parses_abuse(self):
        fields = parse_whois_fields(self.RAW)
        self.assertIn("Abuse Contact", fields)

    def test_empty_input(self):
        fields = parse_whois_fields("")
        self.assertIsInstance(fields, dict)


# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    unittest.main(verbosity=2)
