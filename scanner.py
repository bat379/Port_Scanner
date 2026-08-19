#!/usr/bin/env python3
"""
Port Scanner v2.0 — Professional Edition
─────────────────────────────────────────
Made by Batsaikhan Narangerel
Run: python scanner.py  (fully interactive — no flags needed)

Features: 3-D radar globe animation · Banner grabbing · OS detection
          Vuln analysis · DNS/WHOIS recon · JSON/CSV/HTML reports
          Progress bar · Threaded & Async engines
"""

import logging, sys, time, os, threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from core.scanner   import TCPScanner, AsyncScanner, udp_scan
from core.banner    import grab_banner, fingerprint, guess_os
from core.vuln      import analyze, risk_summary, Risk
from core.recon     import resolve_host, dns_records, whois_raw, parse_whois_fields
from core.animation import ScanAnimation
from reports.html_report import generate_html, save_html
from reports.exporters   import save_json, save_csv


# ── ANSI colors (for post-scan output) ──────────────────
class C:
    RESET   = "\033[0m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    BLUE    = "\033[94m"

RISK_COLORS = {
    Risk.CRITICAL: C.RED,
    Risk.HIGH:     C.RED,
    Risk.MEDIUM:   C.YELLOW,
    Risk.LOW:      C.GREEN,
    Risk.INFO:     C.CYAN,
}

def setup_logging(log_file="scan.log", verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stderr) if verbose else logging.NullHandler(),
        ])
    if not verbose:
        logging.getLogger("portscanner.banner").setLevel(logging.WARNING)
        logging.getLogger("portscanner.recon").setLevel(logging.WARNING)

logger = logging.getLogger("portscanner.main")


# ── Pretty printers (used after animation stops) ─────────
def print_section(title: str):
    print(f"\n{C.BOLD}{C.BLUE}{'─'*58}")
    print(f"  {title}")
    print(f"{'─'*58}{C.RESET}")

def print_open(port, service, fp, ver, banner):
    detected    = fp if fp and fp != "Unknown" else service
    version_str = f" {C.DIM}v{ver}{C.RESET}" if ver else ""
    print(f"  {C.GREEN}{C.BOLD}[OPEN]{C.RESET}  Port {C.YELLOW}{port:<6}{C.RESET} → {C.CYAN}{detected}{C.RESET}{version_str}")
    if banner and banner != "No banner":
        print(f"          {C.DIM}↳ {banner[:92]}{C.RESET}")

def print_finding(f):
    color = RISK_COLORS.get(f.risk, C.RESET)
    cve   = f" ({f.cve_hint})" if f.cve_hint else ""
    print(f"  {color}[{f.risk}]{C.RESET}  Port {C.YELLOW}{f.port}{C.RESET}  {f.title}{C.DIM}{cve}{C.RESET}")
    print(f"            {C.DIM}↳ {f.description[:82]}{C.RESET}")
    if f.remediation:
        print(f"            {C.DIM}Fix: {f.remediation[:76]}{C.RESET}")


# ── Interactive menus ────────────────────────────────────
def ask_target() -> str:
    while True:
        t = input(f"\n{C.BOLD}  Enter target (IP or domain): {C.RESET}").strip()
        if t: return t
        print(f"  {C.RED}Target cannot be empty.{C.RESET}")

def ask_port_range() -> tuple:
    print(f"\n{C.BOLD}  Select Port Range:{C.RESET}")
    print(f"    {C.YELLOW}1.{C.RESET} Quick scan      {C.DIM}(1 – 100){C.RESET}")
    print(f"    {C.YELLOW}2.{C.RESET} Standard scan   {C.DIM}(1 – 1,000){C.RESET}")
    print(f"    {C.YELLOW}3.{C.RESET} Extended scan   {C.DIM}(1 – 10,000){C.RESET}")
    print(f"    {C.YELLOW}4.{C.RESET} Full scan       {C.DIM}(1 – 65,535){C.RESET}")
    print(f"    {C.YELLOW}5.{C.RESET} Custom range    {C.DIM}(you choose){C.RESET}")
    presets = {"1":(1,100),"2":(1,1000),"3":(1,10000),"4":(1,65535)}
    while True:
        c = input(f"\n  {C.CYAN}Choice [1-5]: {C.RESET}").strip()
        if c in presets:
            lo, hi = presets[c]
            print(f"  {C.DIM}→ Ports {lo}–{hi}{C.RESET}")
            return lo, hi
        elif c == "5":
            try:
                lo = int(input(f"  {C.CYAN}Start port: {C.RESET}").strip())
                hi = int(input(f"  {C.CYAN}End port:   {C.RESET}").strip())
                if 1 <= lo <= hi <= 65535:
                    print(f"  {C.DIM}→ Ports {lo}–{hi}{C.RESET}")
                    return lo, hi
                print(f"  {C.RED}Must be 1 ≤ start ≤ end ≤ 65535.{C.RESET}")
            except ValueError:
                print(f"  {C.RED}Numbers only.{C.RESET}")
        else:
            print(f"  {C.RED}Enter 1–5.{C.RESET}")

def ask_scan_mode() -> str:
    print(f"\n{C.BOLD}  Select Scan Mode:{C.RESET}")
    print(f"    {C.YELLOW}1.{C.RESET} Threaded  {C.DIM}(balanced, good for most targets){C.RESET}")
    print(f"    {C.YELLOW}2.{C.RESET} Async     {C.DIM}(faster for large port ranges){C.RESET}")
    while True:
        c = input(f"\n  {C.CYAN}Choice [1-2]: {C.RESET}").strip()
        if c == "1": return "thread"
        if c == "2": return "async"
        print(f"  {C.RED}Enter 1 or 2.{C.RESET}")

def ask_extras() -> dict:
    print(f"\n{C.BOLD}  Optional Features:{C.RESET}")
    def yn(prompt, default="y") -> bool:
        hint = "[Y/n]" if default == "y" else "[y/N]"
        ans  = input(f"    {prompt} {C.DIM}{hint}{C.RESET}: ").strip().lower()
        return (default=="y") if not ans else ans.startswith("y")
    udp    = yn("Scan common UDP ports?",       default="n")
    banner = yn("Grab service banners?",         default="y")
    vuln   = yn("Run vulnerability analysis?",  default="y")
    recon  = yn("Run DNS / WHOIS recon?",        default="y")
    print(f"\n{C.BOLD}  Report format:{C.RESET}")
    print(f"    {C.YELLOW}1.{C.RESET} HTML  {C.DIM}(default){C.RESET}")
    print(f"    {C.YELLOW}2.{C.RESET} JSON")
    print(f"    {C.YELLOW}3.{C.RESET} CSV")
    print(f"    {C.YELLOW}4.{C.RESET} All formats")
    print(f"    {C.YELLOW}5.{C.RESET} No report")
    out_map = {"1":"html","2":"json","3":"csv","4":"all","5":"none"}
    output  = out_map.get(input(f"\n  {C.CYAN}Choice [1-5, default=1]: {C.RESET}").strip(), "html")
    return {"udp":udp,"banner":banner,"vuln":vuln,"recon":recon,"output":output}


# ── Main ──────────────────────────────────────────────────
def main():
    # ── Collect user input ───────────────────────────────
    # Show a compact pre-animation banner for the menus
    print(f"\n{C.CYAN}{C.BOLD}  ╔══════════════════════════════════════════════════╗")
    print(f"  ║  PORT SCANNER v2.0  —  Made by Batsaikhan N.   ║")
    print(f"  ╚══════════════════════════════════════════════════╝{C.RESET}\n")

    target = ask_target()
    lo, hi = ask_port_range()
    mode   = ask_scan_mode()
    extras = ask_extras()

    outdir   = "."
    os.makedirs(outdir, exist_ok=True)
    log_path = os.path.join(outdir, "scan.log")
    setup_logging(log_path)

    port_range = range(lo, hi + 1)
    scan_time  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name  = os.path.join(outdir, f"scan_{target.replace('.','_')}_{ts}")
    timeout    = 1.0

    # ── Resolve target ───────────────────────────────────
    print(f"\n{C.CYAN}[*] Resolving target...{C.RESET}", end=" ", flush=True)
    try:
        host_ip = resolve_host(target)
    except SystemExit as e:
        print(f"\n{C.RED}{e}{C.RESET}"); sys.exit(1)
    print(f"{C.GREEN}{host_ip}{C.RESET}")
    logger.info("Scan started: %s (%s) ports %d-%d mode=%s", target, host_ip, lo, hi, mode)

    # ── DNS + WHOIS (before animation) ───────────────────
    dns_info, whois_fields = {}, {}
    if extras["recon"]:
        print(f"{C.DIM}[*] DNS & WHOIS recon...{C.RESET}", end=" ", flush=True)
        try:
            dns_info     = dns_records(target)
            whois_fields = parse_whois_fields(whois_raw(host_ip))
            print(f"{C.GREEN}done{C.RESET}")
        except Exception as e:
            print(f"{C.YELLOW}skipped ({e}){C.RESET}")

    print(f"\n{C.DIM}  Starting radar animation...{C.RESET}\n")

    # ── Launch animation ─────────────────────────────────
    anim = ScanAnimation()
    anim.set_info(target, host_ip, lo, hi, mode)
    anim.start()   # captures stdout from this point

    # ── TCP Scan ─────────────────────────────────────────
    # scanner.results is populated live; we pass it to anim.update()
    start_time = time.time()

    if mode == "async":
        scanner = AsyncScanner(host_ip, port_range, timeout=timeout, concurrency=500)
    else:
        scanner = TCPScanner(host_ip, port_range, threads=150, timeout=timeout)

    # Attach progress callback that feeds both the scanner's internal state
    # and the animation's live stats
    def progress_cb(scanned: int, total: int):
        anim.update(scanned, total, scanner.results)

    scanner.progress_cb = progress_cb

    tcp_results = scanner.run()

    # ── UDP ───────────────────────────────────────────────
    udp_results = []
    if extras["udp"]:
        udp_results = udp_scan(host_ip, timeout=timeout + 1)

    all_results = tcp_results + udp_results
    elapsed     = time.time() - start_time

    # ── Banner grabbing ────────────────────────────────────
    all_banners = []
    if extras["banner"] and all_results:
        for r in all_results:
            if r.get("protocol","tcp") == "tcp":
                bnr      = grab_banner(host_ip, r["port"], timeout + 1.5)
                svc, ver = fingerprint(bnr)
                r["banner"]      = bnr
                r["fingerprint"] = svc
                r["version"]     = ver
                all_banners.append(bnr)
            else:
                r["banner"] = r["fingerprint"] = r["version"] = ""

    # Final animation update with all open ports + banner info
    anim.update(len(port_range), len(port_range), all_results)

    # ── Stop animation — get buffered output ──────────────
    _captured = anim.stop()  # restores stdout; _captured holds any buffered text

    # ── OS Detection ─────────────────────────────────────
    os_guess = guess_os(all_banners) if all_banners else "Unknown"

    # ── Vulnerability analysis ────────────────────────────
    vuln_findings, risk_counts = [], {}
    if extras["vuln"] and all_results:
        vuln_findings = analyze(all_results)
        risk_counts   = risk_summary(vuln_findings)

    # ── Print full results ────────────────────────────────
    print_section(f"Open Ports  (TCP {lo}–{hi}  ·  {mode.upper()} scan)")

    if all_results:
        for r in all_results:
            print_open(r["port"], r.get("service","?"),
                       r.get("fingerprint",""), r.get("version",""),
                       r.get("banner",""))
    else:
        print(f"  {C.DIM}No open ports found.{C.RESET}")

    if os_guess != "Unknown":
        print(f"\n  {C.DIM}[OS Guess] {os_guess}{C.RESET}")

    if extras["vuln"] and vuln_findings:
        print_section("Vulnerability Analysis")
        for f in vuln_findings: print_finding(f)
        print(f"\n  {C.DIM}Summary: "
              + "  ".join(f"{k}: {v}" for k, v in risk_counts.items() if v)
              + C.RESET)
    elif extras["vuln"]:
        print(f"\n  {C.GREEN}✓  No known vulnerabilities detected{C.RESET}")

    # ── Summary ───────────────────────────────────────────
    print(f"\n{'═'*58}")
    print(f"{C.BOLD}  Scan complete in {elapsed:.2f}s{C.RESET}")
    print(f"  Open TCP ports  : {C.GREEN}{len(tcp_results)}{C.RESET}")
    if extras["udp"]:
        print(f"  Open UDP ports  : {C.GREEN}{len(udp_results)}{C.RESET}")
    if os_guess != "Unknown":
        print(f"  OS (heuristic)  : {C.CYAN}{os_guess}{C.RESET}")
    if vuln_findings:
        crit  = risk_counts.get(Risk.CRITICAL,0)
        high  = risk_counts.get(Risk.HIGH,0)
        color = C.RED if crit else C.YELLOW if high else C.GREEN
        print(f"  Vulnerabilities : {color}{len(vuln_findings)}{C.RESET}")

    # ── Reports ───────────────────────────────────────────
    output = extras["output"]
    if output != "none":
        print()
        if output in ("json","all"):
            fname = f"{base_name}.json"
            save_json(target, host_ip, scan_time, elapsed, all_results,
                      vuln_findings, dns_info, whois_fields, os_guess, risk_counts, fname)
            print(f"  {C.MAGENTA}[+] JSON  → {fname}{C.RESET}")
        if output in ("csv","all"):
            save_csv(all_results, vuln_findings, base_name)
            print(f"  {C.MAGENTA}[+] CSV   → {base_name}_ports.csv{C.RESET}")
        if output in ("html","all"):
            html = generate_html(target=target, host_ip=host_ip, scan_time=scan_time,
                                  elapsed=elapsed, scan_mode=f"{mode.upper()} / Radar",
                                  port_results=all_results, vuln_findings=vuln_findings,
                                  dns_info=dns_info, whois_fields=whois_fields,
                                  os_guess=os_guess, risk_counts=risk_counts)
            fname = f"{base_name}.html"
            save_html(html, fname)
            print(f"  {C.MAGENTA}[+] HTML  → {fname}{C.RESET}")
        print(f"  {C.DIM}[+] Log   → {log_path}{C.RESET}")

    print(f"\n{C.DIM}  Reminder: Only scan systems you own or have permission to test.{C.RESET}\n")
    logger.info("Scan finished. Open=%d Vulns=%d Elapsed=%.2fs",
                len(all_results), len(vuln_findings), elapsed)


if __name__ == "__main__":
    main()
