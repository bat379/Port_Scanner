"""
reports/html_report.py — Generates a self-contained HTML scan report
"""

import json
from datetime import datetime
from typing import List, Dict
from pathlib import Path


RISK_COLORS = {
    "CRITICAL": ("#7f1d1d", "#fca5a5"),
    "HIGH":     ("#7c2d12", "#fdba74"),
    "MEDIUM":   ("#78350f", "#fde68a"),
    "LOW":      ("#14532d", "#86efac"),
    "INFO":     ("#1e3a5f", "#93c5fd"),
}

RISK_BADGE = {
    "CRITICAL": "background:#ef4444;color:#fff",
    "HIGH":     "background:#f97316;color:#fff",
    "MEDIUM":   "background:#eab308;color:#000",
    "LOW":      "background:#22c55e;color:#fff",
    "INFO":     "background:#3b82f6;color:#fff",
}


def _badge(risk: str) -> str:
    style = RISK_BADGE.get(risk, "background:#6b7280;color:#fff")
    return (f'<span style="{style};padding:2px 10px;border-radius:999px;'
            f'font-size:11px;font-weight:600;letter-spacing:.04em">{risk}</span>')


def generate_html(
    target: str,
    host_ip: str,
    scan_time: str,
    elapsed: float,
    scan_mode: str,
    port_results: List[dict],
    vuln_findings: List,
    dns_info: Dict,
    whois_fields: Dict,
    os_guess: str,
    risk_counts: Dict,
) -> str:

    total_open = len(port_results)
    total_vulns = len(vuln_findings)

    # Build port rows
    port_rows = ""
    for r in port_results:
        svc  = r.get("service", "Unknown")
        bnr  = r.get("banner", "No banner")
        fp   = r.get("fingerprint", "")
        ver  = r.get("version", "")
        proto= r.get("protocol", "tcp").upper()
        detected = fp if fp and fp != "Unknown" else svc
        version_str = f" <span style='color:#6b7280;font-size:12px'>v{ver}</span>" if ver else ""
        port_rows += f"""
        <tr>
          <td style='font-family:monospace;font-weight:600;color:#3b82f6'>{r['port']}</td>
          <td><span style='background:#d1fae5;color:#065f46;padding:2px 8px;border-radius:4px;font-size:12px'>{r['state'].upper()}</span></td>
          <td>{proto}</td>
          <td>{detected}{version_str}</td>
          <td style='font-family:monospace;font-size:12px;color:#6b7280;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap' title='{bnr}'>{bnr}</td>
        </tr>"""

    # Build vuln rows
    vuln_rows = ""
    for f in vuln_findings:
        colors = RISK_COLORS.get(f.risk, ("#374151", "#e5e7eb"))
        cve = (f'<span style="font-size:11px;font-family:monospace;color:#9ca3af">'
               f'{f.cve_hint}</span>' if f.cve_hint else "")
        vuln_rows += f"""
        <tr style='border-left:4px solid {colors[1]}'>
          <td style='font-family:monospace;font-weight:600;color:#3b82f6'>{f.port}</td>
          <td>{_badge(f.risk)}</td>
          <td><strong>{f.title}</strong><br>
              <span style='font-size:12px;color:#6b7280'>{f.description}</span><br>
              {cve}</td>
          <td style='font-size:12px;color:#374151'>{f.remediation}</td>
        </tr>"""

    # DNS rows
    dns_rows = "".join(
        f"<tr><td style='color:#6b7280;font-size:13px'>{k}</td>"
        f"<td style='font-family:monospace;font-size:13px'>{v}</td></tr>"
        for k, v in dns_info.items()
    )

    # WHOIS rows
    whois_rows = "".join(
        f"<tr><td style='color:#6b7280;font-size:13px'>{k}</td>"
        f"<td style='font-size:13px'>{v}</td></tr>"
        for k, v in whois_fields.items()
    ) or "<tr><td colspan='2' style='color:#9ca3af'>Not available</td></tr>"

    # Risk summary bar
    risk_bar_items = ""
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = risk_counts.get(risk, 0)
        if count:
            style = RISK_BADGE[risk]
            risk_bar_items += (f'<div style="{style};padding:4px 14px;border-radius:6px;'
                               f'font-size:13px;font-weight:600">{risk}: {count}</div>')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scan Report — {target}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
  .topbar{{background:#020617;border-bottom:1px solid #1e293b;padding:12px 32px;display:flex;align-items:center;gap:12px}}
  .topbar h1{{font-size:15px;font-weight:600;letter-spacing:.02em}}
  .dot{{width:8px;height:8px;border-radius:50%;background:#22c55e}}
  .container{{max-width:1100px;margin:0 auto;padding:32px 24px}}
  .hero{{background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid #1e293b;border-radius:12px;padding:28px 32px;margin-bottom:24px}}
  .hero-grid{{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:16px;margin-top:20px}}
  .stat{{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:14px 18px}}
  .stat-label{{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.06em}}
  .stat-val{{font-size:26px;font-weight:700;margin-top:4px}}
  .section{{background:#1e293b;border:1px solid #334155;border-radius:12px;margin-bottom:24px;overflow:hidden}}
  .section-header{{background:#0f172a;padding:14px 20px;font-size:14px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid #334155}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#0f172a;padding:10px 16px;text-align:left;font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;font-weight:500}}
  td{{padding:10px 16px;border-bottom:1px solid #1e293b;vertical-align:top;font-size:13px}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#1e293b88}}
  .risk-bar{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}}
  .footer{{text-align:center;color:#475569;font-size:12px;padding:24px 0;border-top:1px solid #1e293b;margin-top:8px}}
  @media(max-width:700px){{.hero-grid{{grid-template-columns:1fr 1fr}}}}
</style>
</head>
<body>

<div class="topbar">
  <div class="dot"></div>
  <h1>Smart Port Scanner — Scan Report</h1>
  <span style="margin-left:auto;font-size:12px;color:#64748b">{scan_time}</span>
</div>

<div class="container">

  <!-- Hero -->
  <div class="hero">
    <div style="display:flex;align-items:center;gap:12px">
      <div>
        <div style="font-size:22px;font-weight:700">{target}</div>
        <div style="color:#64748b;font-size:14px;margin-top:2px">{host_ip} &nbsp;·&nbsp; {os_guess} &nbsp;·&nbsp; {scan_mode}</div>
      </div>
    </div>
    <div class="hero-grid">
      <div class="stat"><div class="stat-label">Open Ports</div><div class="stat-val" style="color:#22c55e">{total_open}</div></div>
      <div class="stat"><div class="stat-label">Vulnerabilities</div><div class="stat-val" style="color:#ef4444">{total_vulns}</div></div>
      <div class="stat"><div class="stat-label">Elapsed</div><div class="stat-val" style="color:#3b82f6">{elapsed:.1f}s</div></div>
      <div class="stat"><div class="stat-label">Risk Score</div>
        <div class="stat-val" style="color:{'#ef4444' if risk_counts.get('CRITICAL',0) else '#f97316' if risk_counts.get('HIGH',0) else '#eab308' if risk_counts.get('MEDIUM',0) else '#22c55e'}">
          {'CRITICAL' if risk_counts.get('CRITICAL',0) else 'HIGH' if risk_counts.get('HIGH',0) else 'MEDIUM' if risk_counts.get('MEDIUM',0) else 'LOW' if risk_counts.get('LOW',0) else 'CLEAN'}
        </div>
      </div>
    </div>
  </div>

  <!-- Risk bar -->
  {'<div class="risk-bar">' + risk_bar_items + '</div>' if risk_bar_items else ''}

  <!-- Recon -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px">
    <div class="section">
      <div class="section-header">DNS Info</div>
      <table><tr><th>Record</th><th>Value</th></tr>{dns_rows}</table>
    </div>
    <div class="section">
      <div class="section-header">WHOIS</div>
      <table><tr><th>Field</th><th>Value</th></tr>{whois_rows}</table>
    </div>
  </div>

  <!-- Open Ports -->
  <div class="section">
    <div class="section-header">Open Ports ({total_open})</div>
    <table>
      <tr><th>Port</th><th>State</th><th>Proto</th><th>Service / Fingerprint</th><th>Banner</th></tr>
      {port_rows if port_rows else '<tr><td colspan="5" style="color:#64748b;text-align:center;padding:24px">No open ports found</td></tr>'}
    </table>
  </div>

  <!-- Vulnerabilities -->
  <div class="section">
    <div class="section-header">Vulnerability Findings ({total_vulns})</div>
    <table>
      <tr><th>Port</th><th>Risk</th><th>Finding</th><th>Remediation</th></tr>
      {vuln_rows if vuln_rows else '<tr><td colspan="4" style="color:#22c55e;text-align:center;padding:24px">&#10003; No vulnerabilities detected</td></tr>'}
    </table>
  </div>

  <div class="footer">
    Generated by Smart Port Scanner &nbsp;·&nbsp; Ethical use only &nbsp;·&nbsp; {scan_time}
  </div>
</div>
</body>
</html>"""

    return html


def save_html(html: str, filename: str):
    Path(filename).write_text(html, encoding="utf-8")
