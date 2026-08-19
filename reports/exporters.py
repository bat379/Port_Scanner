"""
reports/exporters.py — JSON and CSV report writers
"""

import json
import csv
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict

logger = logging.getLogger("portscanner.exporters")


def save_json(target: str, host_ip: str, scan_time: str, elapsed: float,
              port_results: List[dict], vuln_findings: list,
              dns_info: Dict, whois_fields: Dict, os_guess: str,
              risk_counts: Dict, filename: str):

    report = {
        "meta": {
            "target":    target,
            "host_ip":   host_ip,
            "os_guess":  os_guess,
            "scan_time": scan_time,
            "elapsed_s": round(elapsed, 2),
            "tool":      "Smart Port Scanner v2.0",
        },
        "dns":   dns_info,
        "whois": whois_fields,
        "risk_summary": risk_counts,
        "open_ports": len(port_results),
        "ports": port_results,
        "vulnerabilities": [
            {
                "port":        f.port,
                "risk":        f.risk,
                "title":       f.title,
                "description": f.description,
                "cve_hint":    f.cve_hint,
                "remediation": f.remediation,
            }
            for f in vuln_findings
        ],
    }

    Path(filename).write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("JSON report saved → %s", filename)


def save_csv(port_results: List[dict], vuln_findings: list, base: str):
    # Ports CSV
    ports_file = f"{base}_ports.csv"
    with open(ports_file, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["port", "state", "protocol",
                                           "service", "fingerprint",
                                           "version", "banner"])
        w.writeheader()
        for r in port_results:
            w.writerow({k: r.get(k, "") for k in w.fieldnames})
    logger.info("CSV (ports) saved → %s", ports_file)

    # Vulns CSV
    vulns_file = f"{base}_vulns.csv"
    with open(vulns_file, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["port", "risk", "title",
                                           "description", "cve_hint",
                                           "remediation"])
        w.writeheader()
        for fnd in vuln_findings:
            w.writerow({
                "port": fnd.port, "risk": fnd.risk, "title": fnd.title,
                "description": fnd.description,
                "cve_hint": fnd.cve_hint or "",
                "remediation": fnd.remediation,
            })
    logger.info("CSV (vulns) saved → %s", vulns_file)
