"""
core/recon.py — WHOIS + DNS reconnaissance helpers
Uses only standard library (socket, struct) — no external deps.
"""

import socket
import logging
from typing import List, Dict

logger = logging.getLogger("portscanner.recon")


def resolve_host(target: str) -> str:
    """Resolve hostname to IP. Returns IP string or raises SystemExit."""
    try:
        ip = socket.gethostbyname(target)
        logger.info("Resolved %s → %s", target, ip)
        return ip
    except socket.gaierror as e:
        logger.error("Cannot resolve %s: %s", target, e)
        raise SystemExit(f"[!] Could not resolve host: {target}")


def reverse_dns(ip: str) -> str:
    """PTR record lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return "N/A"


def dns_records(target: str) -> Dict[str, str]:
    """
    Basic DNS info using only socket.
    Returns dict of what we can discover without dnspython.
    """
    info: Dict[str, str] = {}
    try:
        ip = socket.gethostbyname(target)
        info["A"] = ip
    except Exception:
        info["A"] = "N/A"

    try:
        results = socket.getaddrinfo(target, None)
        ipv6 = [r[4][0] for r in results if r[0] == socket.AF_INET6]
        info["AAAA"] = ipv6[0] if ipv6 else "N/A"
    except Exception:
        info["AAAA"] = "N/A"

    try:
        ptr = reverse_dns(info.get("A", target))
        info["PTR"] = ptr
    except Exception:
        info["PTR"] = "N/A"

    return info


def whois_raw(ip: str) -> str:
    """
    Minimal WHOIS query via raw socket to whois.iana.org then follow referral.
    Returns raw WHOIS text (first ~3KB).
    """
    def _query(server: str, query: str) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((server, 43))
                s.sendall((query + "\r\n").encode())
                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                return resp.decode("utf-8", errors="ignore")
        except Exception as e:
            return f"WHOIS unavailable: {e}"

    # Step 1: ask IANA
    raw = _query("whois.iana.org", ip)

    # Step 2: follow referral if present
    referral = None
    for line in raw.splitlines():
        if line.lower().startswith("refer:"):
            referral = line.split(":", 1)[1].strip()
            break

    if referral and referral != "whois.iana.org":
        raw = _query(referral, ip)

    # Return first 3000 chars of cleaned output
    lines = [l for l in raw.splitlines()
             if l.strip() and not l.startswith("%") and not l.startswith("#")]
    return "\n".join(lines[:40])


def parse_whois_fields(raw: str) -> Dict[str, str]:
    """Extract key fields from raw WHOIS text."""
    fields = {}
    want = {
        "netname": "Network Name",
        "orgname": "Organisation",
        "org-name": "Organisation",
        "country": "Country",
        "descr": "Description",
        "inetnum": "IP Range",
        "netrange": "IP Range",
        "cidr": "CIDR",
        "abuse-mailbox": "Abuse Contact",
        "orgabuseemail": "Abuse Contact",
    }
    for line in raw.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower()
            if key in want and want[key] not in fields:
                fields[want[key]] = val.strip()
    return fields
