"""
core/banner.py — Banner grabbing + intelligent service fingerprinting
"""

import socket
import re
import logging
from typing import Tuple

logger = logging.getLogger("portscanner.banner")

# ─────────────────────────────────────────────────────────
#  HTTP probe for web ports
# ─────────────────────────────────────────────────────────
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"

BANNER_PROBES = {
    80:   HTTP_PROBE,
    443:  HTTP_PROBE,
    8080: HTTP_PROBE,
    8443: HTTP_PROBE,
    8888: HTTP_PROBE,
    21:   None,   # auto-sends
    22:   None,
    25:   None,
    110:  None,
    143:  None,
    3306: None,
    5432: None,
    6379: b"PING\r\n",
    27017:None,
}


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Connect to port and retrieve the service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            probe = BANNER_PROBES.get(port, b"\r\n")
            if probe is not None:
                probe = probe.replace(b"{host}", host.encode())
                s.sendall(probe)

            raw = s.recv(2048).decode("utf-8", errors="ignore").strip()
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            return lines[0] if lines else "No banner"
    except Exception as e:
        logger.debug("Banner grab failed on port %d: %s", port, e)
        return "No banner"


# ─────────────────────────────────────────────────────────
#  Fingerprint patterns  →  (detected_service, version_hint)
# ─────────────────────────────────────────────────────────
FINGERPRINTS = [
    # SSH — specific patterns BEFORE generic
    (r"OpenSSH[_\s]([\d.p\w]+)",            "OpenSSH",     lambda m: m.group(1)),
    (r"SSH-(\S+)",                          "SSH",         lambda m: m.group(1)),
    # FTP
    (r"vsFTPd\s*([\d.]+)",                  "vsFTPd",      lambda m: m.group(1)),
    (r"ProFTPD\s*([\d.]+)",                 "ProFTPD",     lambda m: m.group(1)),
    (r"FileZilla Server",                   "FileZilla FTP", lambda m: ""),
    (r"220.*FTP",                           "FTP",         lambda m: ""),
    # HTTP servers
    (r"Server:\s*Apache/([\d.]+)",          "Apache",      lambda m: m.group(1)),
    (r"Server:\s*nginx/([\d.]+)",           "nginx",       lambda m: m.group(1)),
    (r"Server:\s*Microsoft-IIS/([\d.]+)",   "IIS",         lambda m: m.group(1)),
    (r"Server:\s*LiteSpeed",                "LiteSpeed",   lambda m: ""),
    (r"Server:\s*Jetty\(([\d.]+)\)",        "Jetty",       lambda m: m.group(1)),
    (r"Server:\s*Tomcat",                   "Tomcat",      lambda m: ""),
    (r"Server:\s*([\w\-/. ]+)",             "HTTP",        lambda m: m.group(1).strip()),
    # Databases
    (r"([\d.]+)-MySQL",                     "MySQL",       lambda m: m.group(1)),
    (r"MariaDB",                            "MariaDB",     lambda m: ""),
    (r"\+PONG",                             "Redis",       lambda m: ""),
    (r"MongoDB",                            "MongoDB",     lambda m: ""),
    # Mail
    (r"Postfix",                            "Postfix SMTP",lambda m: ""),
    (r"Exim\s*([\d.]+)",                    "Exim",        lambda m: m.group(1)),
    (r"Sendmail",                           "Sendmail",    lambda m: ""),
    (r"Dovecot",                            "Dovecot",     lambda m: ""),
    # Misc
    (r"SMB",                                "SMB",         lambda m: ""),
    (r"RFB\s*([\d.]+)",                     "VNC",         lambda m: m.group(1)),
    (r"Elasticsearch",                      "Elasticsearch",lambda m: ""),
    (r"PostgreSQL",                         "PostgreSQL",  lambda m: ""),
]


def fingerprint(banner: str) -> Tuple[str, str]:
    """
    Returns (detected_service, version).
    Falls back to ("Unknown", "") if nothing matches.
    """
    if not banner or banner == "No banner":
        return "Unknown", ""

    for pattern, service, version_fn in FINGERPRINTS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            try:
                version = version_fn(m)
            except Exception:
                version = ""
            return service, version.strip() if version else ""

    return "Unknown", ""


# ─────────────────────────────────────────────────────────
#  OS Detection (heuristic, from banner strings)
# ─────────────────────────────────────────────────────────
OS_PATTERNS = [
    (r"ubuntu",        "Linux (Ubuntu)"),
    (r"debian",        "Linux (Debian)"),
    (r"centos",        "Linux (CentOS)"),
    (r"fedora",        "Linux (Fedora)"),
    (r"red hat",       "Linux (Red Hat)"),
    (r"freebsd",       "FreeBSD"),
    (r"windows",       "Windows"),
    (r"win32",         "Windows"),
    (r"microsoft",     "Windows"),
    (r"darwin",        "macOS"),
    (r"unix",          "Unix"),
    (r"linux",         "Linux"),
]

def guess_os(banners: list) -> str:
    """Infer OS from a list of banner strings collected during the scan."""
    combined = " ".join(banners).lower()
    for pattern, os_name in OS_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return os_name
    return "Unknown"
