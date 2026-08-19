"""
core/vuln.py — Vulnerability detection and risk classification
Maps open ports + banners to known risks and CVE hints.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("portscanner.vuln")


# ─────────────────────────────────────────────────────────
#  Risk levels
# ─────────────────────────────────────────────────────────
class Risk:
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

RISK_ORDER = {Risk.CRITICAL: 4, Risk.HIGH: 3, Risk.MEDIUM: 2, Risk.LOW: 1, Risk.INFO: 0}


@dataclass
class Finding:
    port:        int
    risk:        str
    title:       str
    description: str
    cve_hint:    Optional[str] = None
    remediation: str = ""


# ─────────────────────────────────────────────────────────
#  Static port-based rules
# ─────────────────────────────────────────────────────────
PORT_RULES = [
    {
        "ports": [23],
        "risk": Risk.CRITICAL,
        "title": "Telnet Detected — Plaintext Protocol",
        "description": "Telnet transmits credentials and data in plaintext. "
                       "Trivially sniffable on any network.",
        "cve_hint": "CVE-1999-0619",
        "remediation": "Disable Telnet immediately. Replace with SSH.",
    },
    {
        "ports": [21],
        "risk": Risk.HIGH,
        "title": "FTP Detected — Plaintext Credentials",
        "description": "FTP sends usernames and passwords in cleartext. "
                       "Anonymous FTP login may also be enabled.",
        "cve_hint": "CVE-1999-0497",
        "remediation": "Replace with SFTP or FTPS. Disable anonymous access.",
    },
    {
        "ports": [445, 139],
        "risk": Risk.HIGH,
        "title": "SMB Exposed",
        "description": "SMB/NetBIOS exposed to network. EternalBlue and other "
                       "critical RCE vulnerabilities target this service.",
        "cve_hint": "CVE-2017-0144 (EternalBlue)",
        "remediation": "Patch immediately. Block port 445 at the firewall. "
                       "Disable SMBv1.",
    },
    {
        "ports": [3389],
        "risk": Risk.HIGH,
        "title": "RDP Exposed",
        "description": "Remote Desktop Protocol is exposed. BlueKeep and "
                       "DejaBlue are critical RCE vulnerabilities targeting RDP.",
        "cve_hint": "CVE-2019-0708 (BlueKeep)",
        "remediation": "Restrict RDP to VPN only. Enable NLA. Patch Windows.",
    },
    {
        "ports": [3306],
        "risk": Risk.MEDIUM,
        "title": "MySQL Exposed to Network",
        "description": "MySQL database port is reachable externally. "
                       "Should only listen on localhost or private interfaces.",
        "remediation": "Bind MySQL to 127.0.0.1. Use firewall rules. "
                       "Disable remote root login.",
    },
    {
        "ports": [5432],
        "risk": Risk.MEDIUM,
        "title": "PostgreSQL Exposed to Network",
        "description": "PostgreSQL is reachable from external hosts.",
        "remediation": "Restrict access via pg_hba.conf. Bind to localhost.",
    },
    {
        "ports": [27017],
        "risk": Risk.HIGH,
        "title": "MongoDB Exposed — Likely Unauthenticated",
        "description": "MongoDB with no auth is a common breach vector. "
                       "Thousands of databases have been wiped via this misconfiguration.",
        "remediation": "Enable authentication. Bind to localhost. Use firewall.",
    },
    {
        "ports": [6379],
        "risk": Risk.HIGH,
        "title": "Redis Exposed — No Authentication by Default",
        "description": "Redis commonly runs without authentication. "
                       "Allows arbitrary command execution and data theft.",
        "cve_hint": "CVE-2022-0543",
        "remediation": "Set a strong requirepass. Bind to 127.0.0.1. "
                       "Use firewall rules.",
    },
    {
        "ports": [9200, 9300],
        "risk": Risk.HIGH,
        "title": "Elasticsearch Exposed",
        "description": "Elasticsearch has no authentication by default on older versions. "
                       "Full data access without credentials.",
        "remediation": "Enable X-Pack security. Restrict with firewall.",
    },
    {
        "ports": [5900],
        "risk": Risk.MEDIUM,
        "title": "VNC Exposed",
        "description": "VNC provides remote desktop access. "
                       "Often misconfigured with weak or no passwords.",
        "remediation": "Use a strong VNC password. Tunnel over SSH. "
                       "Block publicly.",
    },
    {
        "ports": [161, 162],
        "risk": Risk.MEDIUM,
        "title": "SNMP Exposed",
        "description": "SNMP v1/v2c use community strings (default: 'public') "
                       "instead of real authentication.",
        "remediation": "Use SNMPv3 with auth. Change community strings. "
                       "Firewall the port.",
    },
    {
        "ports": [25],
        "risk": Risk.LOW,
        "title": "SMTP Open Relay Risk",
        "description": "Public SMTP ports may be tested for open relay "
                       "which enables spam abuse.",
        "remediation": "Ensure relay authentication is required. "
                       "Use SPF/DKIM/DMARC.",
    },
    {
        "ports": [80],
        "risk": Risk.INFO,
        "title": "HTTP (Unencrypted)",
        "description": "Serving content over plain HTTP. Traffic can be intercepted.",
        "remediation": "Redirect all HTTP traffic to HTTPS.",
    },
]


# ─────────────────────────────────────────────────────────
#  Banner-based vulnerability patterns
# ─────────────────────────────────────────────────────────
BANNER_VULN_PATTERNS = [
    {
        "pattern": r"Apache/(1\.|2\.[0-3]\.)",
        "risk": Risk.HIGH,
        "title": "Outdated Apache Version",
        "description": "Apache versions below 2.4 contain known critical vulnerabilities.",
        "cve_hint": "Multiple CVEs",
        "remediation": "Upgrade to Apache 2.4.x latest stable release.",
    },
    {
        "pattern": r"OpenSSH[_\s](5\.|6\.|7\.[0-5])",
        "risk": Risk.MEDIUM,
        "title": "Outdated OpenSSH Version",
        "description": "This OpenSSH version may contain user enumeration "
                       "and other vulnerabilities.",
        "cve_hint": "CVE-2018-15473",
        "remediation": "Upgrade to OpenSSH 8.x or later.",
    },
    {
        "pattern": r"nginx/(0\.|1\.[0-9]\.|1\.1[0-5]\.)",
        "risk": Risk.MEDIUM,
        "title": "Outdated nginx Version",
        "description": "This nginx version may contain known security issues.",
        "remediation": "Upgrade to nginx 1.24+ stable.",
    },
    {
        "pattern": r"PHP/(4\.|5\.[0-5])",
        "risk": Risk.CRITICAL,
        "title": "End-of-Life PHP Version in Banner",
        "description": "PHP 4.x and 5.x are EOL with no security patches. "
                       "Extremely high risk.",
        "cve_hint": "Multiple critical CVEs",
        "remediation": "Upgrade to PHP 8.x immediately.",
    },
    {
        "pattern": r"vsFTPd 2\.3\.4",
        "risk": Risk.CRITICAL,
        "title": "vsFTPd 2.3.4 Backdoor!",
        "description": "This specific version contains a backdoor that allows "
                       "unauthenticated root shell access on port 6200.",
        "cve_hint": "CVE-2011-2523",
        "remediation": "Remove and reinstall vsFTPd from trusted source immediately.",
    },
]


# ─────────────────────────────────────────────────────────
#  Main analysis function
# ─────────────────────────────────────────────────────────
def analyze(scan_results: list) -> List[Finding]:
    """
    Takes list of scan result dicts (port, state, service, banner, ...).
    Returns sorted list of Finding objects.
    """
    findings: List[Finding] = []
    open_ports = {r["port"] for r in scan_results if r.get("state") == "open"}

    # Port-based rules
    for rule in PORT_RULES:
        matched = [p for p in rule["ports"] if p in open_ports]
        if matched:
            for port in matched:
                findings.append(Finding(
                    port=port,
                    risk=rule["risk"],
                    title=rule["title"],
                    description=rule["description"],
                    cve_hint=rule.get("cve_hint"),
                    remediation=rule.get("remediation", ""),
                ))

    # Banner-based rules
    for result in scan_results:
        banner = result.get("banner", "")
        if not banner or banner == "No banner":
            continue
        for rule in BANNER_VULN_PATTERNS:
            if re.search(rule["pattern"], banner, re.IGNORECASE):
                findings.append(Finding(
                    port=result["port"],
                    risk=rule["risk"],
                    title=rule["title"],
                    description=rule["description"],
                    cve_hint=rule.get("cve_hint"),
                    remediation=rule.get("remediation", ""),
                ))

    # Deduplicate by (port, title)
    seen = set()
    unique = []
    for f in findings:
        key = (f.port, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort: CRITICAL first
    unique.sort(key=lambda f: RISK_ORDER.get(f.risk, 0), reverse=True)
    return unique


def risk_summary(findings: List[Finding]) -> dict:
    counts = {Risk.CRITICAL: 0, Risk.HIGH: 0, Risk.MEDIUM: 0,
              Risk.LOW: 0, Risk.INFO: 0}
    for f in findings:
        counts[f.risk] = counts.get(f.risk, 0) + 1
    return counts
