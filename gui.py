#!/usr/bin/env python3
"""
gui.py — Port Scanner GUI (Tkinter)
Made by Batsaikhan Narangerel
Run: python gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import sys
import os
import time
import queue
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from core.scanner  import TCPScanner, AsyncScanner, udp_scan
from core.banner   import grab_banner, fingerprint, guess_os
from core.vuln     import analyze, risk_summary, Risk
from core.recon    import resolve_host, dns_records, whois_raw, parse_whois_fields
from reports.html_report import generate_html, save_html
from reports.exporters   import save_json, save_csv


# ── Color palette ────────────────────────────────────────
BG       = "#0d1117"
BG2      = "#161b22"
BG3      = "#21262d"
BORDER   = "#30363d"
CYAN     = "#58a6ff"
GREEN    = "#3fb950"
RED      = "#f85149"
YELLOW   = "#d29922"
MAGENTA  = "#bc8cff"
DIM      = "#8b949e"
WHITE    = "#e6edf3"
BOLD_FG  = "#ffffff"


class PortScannerGUI:
    def __init__(self, root: tk.Tk):
        self.root      = root
        self.scan_thread  = None
        self.stop_flag    = threading.Event()
        self.msg_queue    = queue.Queue()  # thread → UI messages

        self._build_window()
        self._build_header()
        self._build_form()
        self._build_controls()
        self._build_progress()
        self._build_output()
        self._build_status_bar()

        # Start queue poller
        self.root.after(100, self._poll_queue)

    # ── Window setup ─────────────────────────────────────
    def _build_window(self):
        self.root.title("Port Scanner v2.0  —  Made by Batsaikhan Narangerel")
        self.root.configure(bg=BG)
        self.root.geometry("900x760")
        self.root.minsize(780, 650)
        self.root.option_add("*Font", ("Consolas", 10))

    # ── Header ────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG2, pady=10)
        hdr.pack(fill="x")

        tk.Label(hdr, text="PORT SCANNER  v2.0",
                 bg=BG2, fg=CYAN,
                 font=("Consolas", 18, "bold")).pack()
        tk.Label(hdr, text="Made by Batsaikhan Narangerel",
                 bg=BG2, fg=DIM,
                 font=("Consolas", 9)).pack()
        tk.Label(hdr,
                 text="Banner Grabbing  ·  Service Detection  ·  OS Detection  ·  Vuln Analysis  ·  Reports",
                 bg=BG2, fg=DIM,
                 font=("Consolas", 8)).pack()

        # separator
        ttk.Separator(self.root, orient="horizontal").pack(fill="x")

    # ── Form ─────────────────────────────────────────────
    def _build_form(self):
        form = tk.Frame(self.root, bg=BG, padx=16, pady=10)
        form.pack(fill="x")

        # ── Target ──────────────────────────────────────
        row0 = tk.Frame(form, bg=BG)
        row0.pack(fill="x", pady=(0, 8))
        tk.Label(row0, text="Target (IP / domain):", bg=BG, fg=WHITE,
                 width=22, anchor="w").pack(side="left")
        self.target_var = tk.StringVar()
        tk.Entry(row0, textvariable=self.target_var, bg=BG3, fg=WHITE,
                 insertbackground=WHITE, relief="flat",
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=CYAN, width=42).pack(side="left", padx=(0, 6))

        # ── Port range + Scan mode (side by side) ────────
        cols = tk.Frame(form, bg=BG)
        cols.pack(fill="x")

        # Port range column
        pf = tk.LabelFrame(cols, text=" Port Range ", bg=BG, fg=CYAN,
                            font=("Consolas", 9, "bold"),
                            relief="flat", highlightthickness=1,
                            highlightbackground=BORDER, padx=10, pady=6)
        pf.pack(side="left", fill="y", padx=(0, 10))

        self.port_choice = tk.IntVar(value=2)
        ranges = [
            (1, "Quick scan      (1 – 100)"),
            (2, "Standard scan   (1 – 1,000)"),
            (3, "Extended scan   (1 – 10,000)"),
            (4, "Full scan       (1 – 65,535)"),
            (5, "Custom range"),
        ]
        for val, label in ranges:
            tk.Radiobutton(pf, text=label, variable=self.port_choice, value=val,
                           bg=BG, fg=WHITE, selectcolor=BG3, activebackground=BG,
                           activeforeground=CYAN,
                           command=self._toggle_custom).pack(anchor="w")

        custom_row = tk.Frame(pf, bg=BG)
        custom_row.pack(anchor="w", pady=(2, 0))
        tk.Label(custom_row, text="  Start:", bg=BG, fg=DIM).pack(side="left")
        self.custom_start = tk.Entry(custom_row, width=7, bg=BG3, fg=WHITE,
                                     insertbackground=WHITE, relief="flat",
                                     state="disabled")
        self.custom_start.pack(side="left", padx=2)
        tk.Label(custom_row, text="End:", bg=BG, fg=DIM).pack(side="left")
        self.custom_end = tk.Entry(custom_row, width=7, bg=BG3, fg=WHITE,
                                   insertbackground=WHITE, relief="flat",
                                   state="disabled")
        self.custom_end.pack(side="left", padx=2)

        # Scan mode + Options column
        right = tk.Frame(cols, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        mf = tk.LabelFrame(right, text=" Scan Mode ", bg=BG, fg=CYAN,
                            font=("Consolas", 9, "bold"),
                            relief="flat", highlightthickness=1,
                            highlightbackground=BORDER, padx=10, pady=6)
        mf.pack(fill="x", pady=(0, 8))
        self.mode_var = tk.StringVar(value="thread")
        tk.Radiobutton(mf, text="Threaded  (balanced, most targets)", variable=self.mode_var,
                       value="thread", bg=BG, fg=WHITE, selectcolor=BG3,
                       activebackground=BG, activeforeground=CYAN).pack(anchor="w")
        tk.Radiobutton(mf, text="Async     (faster for large ranges)", variable=self.mode_var,
                       value="async", bg=BG, fg=WHITE, selectcolor=BG3,
                       activebackground=BG, activeforeground=CYAN).pack(anchor="w")

        of = tk.LabelFrame(right, text=" Options ", bg=BG, fg=CYAN,
                           font=("Consolas", 9, "bold"),
                           relief="flat", highlightthickness=1,
                           highlightbackground=BORDER, padx=10, pady=6)
        of.pack(fill="x", pady=(0, 8))

        self.opt_udp    = tk.BooleanVar(value=False)
        self.opt_banner = tk.BooleanVar(value=True)
        self.opt_vuln   = tk.BooleanVar(value=True)
        self.opt_recon  = tk.BooleanVar(value=True)

        opts = [
            (self.opt_banner, "Banner grabbing + service detection"),
            (self.opt_vuln,   "Vulnerability analysis"),
            (self.opt_recon,  "DNS / WHOIS recon"),
            (self.opt_udp,    "UDP common ports scan"),
        ]
        for var, label in opts:
            tk.Checkbutton(of, text=label, variable=var,
                           bg=BG, fg=WHITE, selectcolor=BG3,
                           activebackground=BG, activeforeground=CYAN).pack(anchor="w")

        # Output format row
        outf = tk.LabelFrame(right, text=" Save Report ", bg=BG, fg=CYAN,
                             font=("Consolas", 9, "bold"),
                             relief="flat", highlightthickness=1,
                             highlightbackground=BORDER, padx=10, pady=4)
        outf.pack(fill="x")
        self.output_var = tk.StringVar(value="html")
        for val, label in [("html","HTML"), ("json","JSON"),
                           ("csv","CSV"), ("all","All"), ("none","None")]:
            tk.Radiobutton(outf, text=label, variable=self.output_var, value=val,
                           bg=BG, fg=WHITE, selectcolor=BG3,
                           activebackground=BG, activeforeground=CYAN).pack(side="left", padx=4)

    def _toggle_custom(self):
        state = "normal" if self.port_choice.get() == 5 else "disabled"
        self.custom_start.configure(state=state)
        self.custom_end.configure(state=state)

    # ── Buttons ───────────────────────────────────────────
    def _build_controls(self):
        cf = tk.Frame(self.root, bg=BG, pady=6)
        cf.pack(fill="x", padx=16)

        self.btn_scan = tk.Button(cf, text="▶  START SCAN",
                                  bg=CYAN, fg=BG, font=("Consolas", 11, "bold"),
                                  relief="flat", padx=20, pady=6,
                                  cursor="hand2", command=self._start_scan)
        self.btn_scan.pack(side="left", padx=(0, 8))

        self.btn_stop = tk.Button(cf, text="■  STOP",
                                  bg=RED, fg=WHITE, font=("Consolas", 10, "bold"),
                                  relief="flat", padx=14, pady=6,
                                  cursor="hand2", state="disabled",
                                  command=self._stop_scan)
        self.btn_stop.pack(side="left", padx=(0, 8))

        tk.Button(cf, text="✕  CLEAR", bg=BG3, fg=DIM,
                  font=("Consolas", 10), relief="flat", padx=12, pady=6,
                  cursor="hand2", command=self._clear_output).pack(side="left")

        tk.Button(cf, text="💾  SAVE LOG", bg=BG3, fg=DIM,
                  font=("Consolas", 10), relief="flat", padx=12, pady=6,
                  cursor="hand2", command=self._save_log).pack(side="right")

    # ── Progress bar ─────────────────────────────────────
    def _build_progress(self):
        pf = tk.Frame(self.root, bg=BG, padx=16)
        pf.pack(fill="x")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Scan.Horizontal.TProgressbar",
                        troughcolor=BG3, background=CYAN,
                        lightcolor=CYAN, darkcolor=CYAN, bordercolor=BG3)

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(pf, variable=self.progress_var,
                                            maximum=100, length=100,
                                            style="Scan.Horizontal.TProgressbar")
        self.progress_bar.pack(fill="x", pady=(0, 2))

        self.progress_label = tk.Label(pf, text="Ready", bg=BG, fg=DIM,
                                       font=("Consolas", 8), anchor="w")
        self.progress_label.pack(fill="x")

    # ── Output text area ─────────────────────────────────
    def _build_output(self):
        frame = tk.Frame(self.root, bg=BG, padx=16, pady=4)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="Scan Output", bg=BG, fg=DIM,
                 font=("Consolas", 8)).pack(anchor="w")

        self.output = scrolledtext.ScrolledText(
            frame, bg=BG2, fg=WHITE, insertbackground=WHITE,
            font=("Consolas", 10), relief="flat",
            highlightthickness=1, highlightbackground=BORDER,
            wrap="word", state="disabled"
        )
        self.output.pack(fill="both", expand=True)

        # Color tags
        self.output.tag_config("open",    foreground=GREEN)
        self.output.tag_config("section", foreground=CYAN,    font=("Consolas",10,"bold"))
        self.output.tag_config("vuln",    foreground=RED)
        self.output.tag_config("warn",    foreground=YELLOW)
        self.output.tag_config("dim",     foreground=DIM)
        self.output.tag_config("info",    foreground=MAGENTA)
        self.output.tag_config("bold",    foreground=BOLD_FG, font=("Consolas",10,"bold"))
        self.output.tag_config("title",   foreground=CYAN,    font=("Consolas",13,"bold"))

    # ── Status bar ────────────────────────────────────────
    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Idle")
        sb = tk.Label(self.root, textvariable=self.status_var,
                      bg=BG3, fg=DIM, font=("Consolas", 8),
                      anchor="w", padx=8, pady=3)
        sb.pack(fill="x", side="bottom")

    # ── Output helpers ────────────────────────────────────
    def _write(self, text: str, tag: str = ""):
        self.output.configure(state="normal")
        if tag:
            self.output.insert("end", text, tag)
        else:
            self.output.insert("end", text)
        self.output.see("end")
        self.output.configure(state="disabled")

    def _clear_output(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self.progress_var.set(0)
        self.progress_label.configure(text="Ready")
        self.status_var.set("Idle")

    def _save_log(self):
        text = self.output.get("1.0", "end")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt"),("All files","*.*")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self.status_var.set(f"Log saved → {path}")

    # ── Queue polling (UI thread safe updates) ────────────
    def _poll_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                kind = msg.get("kind")
                if kind == "text":
                    self._write(msg["text"], msg.get("tag",""))
                elif kind == "progress":
                    pct = msg["pct"]
                    self.progress_var.set(pct)
                    self.progress_label.configure(
                        text=f"Scanning... {msg['done']}/{msg['total']} ports  ({pct:.1f}%)")
                elif kind == "progress_done":
                    self.progress_var.set(100)
                    self.progress_label.configure(text="Scan complete")
                elif kind == "status":
                    self.status_var.set(msg["text"])
                elif kind == "done":
                    self._on_scan_done()
        except queue.Empty:
            pass
        self.root.after(80, self._poll_queue)

    # ── Scan control ──────────────────────────────────────
    def _start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target."); return

        # Validate port range
        choice = self.port_choice.get()
        presets = {1:(1,100), 2:(1,1000), 3:(1,10000), 4:(1,65535)}
        if choice in presets:
            lo, hi = presets[choice]
        else:
            try:
                lo = int(self.custom_start.get())
                hi = int(self.custom_end.get())
                assert 1 <= lo <= hi <= 65535
            except Exception:
                messagebox.showerror("Error", "Invalid custom range (1 ≤ start ≤ end ≤ 65535)")
                return

        self.stop_flag.clear()
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self._clear_output()

        opts = {
            "mode":   self.mode_var.get(),
            "udp":    self.opt_udp.get(),
            "banner": self.opt_banner.get(),
            "vuln":   self.opt_vuln.get(),
            "recon":  self.opt_recon.get(),
            "output": self.output_var.get(),
        }

        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(target, lo, hi, opts),
            daemon=True
        )
        self.scan_thread.start()

    def _stop_scan(self):
        self.stop_flag.set()
        self.status_var.set("Stopping...")

    def _on_scan_done(self):
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    # ── Background scan thread ────────────────────────────
    def _put(self, kind: str, **kwargs):
        self.msg_queue.put({"kind": kind, **kwargs})

    def _log(self, text: str, tag: str = ""):
        self._put("text", text=text, tag=tag)

    def _run_scan(self, target: str, lo: int, hi: int, opts: dict):
        try:
            self._run_scan_inner(target, lo, hi, opts)
        except Exception as e:
            self._log(f"\n[ERROR] {e}\n", "vuln")
        finally:
            self._put("done")

    def _run_scan_inner(self, target: str, lo: int, hi: int, opts: dict):
        timeout   = 1.0
        mode      = opts["mode"]
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        base      = f"scan_{target.replace('.','_')}_{ts}"

        self._log("  PORT SCANNER v2.0  —  Made by Batsaikhan Narangerel\n", "title")
        self._log(f"  Target : {target}\n", "bold")
        self._log(f"  Ports  : {lo}–{hi}   Mode: {mode.upper()}\n", "dim")
        self._log(f"  Time   : {scan_time}\n\n", "dim")

        # ── Resolve ───────────────────────────────────────
        self._put("status", text="Resolving target...")
        self._log("→ Resolving... ", "dim")
        try:
            host_ip = resolve_host(target)
        except SystemExit as e:
            self._log(f"FAILED: {e}\n", "vuln"); return
        self._log(f"{host_ip}\n", "open")

        if self.stop_flag.is_set():
            self._log("\n[Scan stopped by user]\n", "warn"); return

        # ── DNS + WHOIS ───────────────────────────────────
        dns_info, whois_fields = {}, {}
        if opts["recon"]:
            self._put("status", text="Running DNS & WHOIS recon...")
            self._log("→ DNS & WHOIS recon... ", "dim")
            try:
                dns_info     = dns_records(target)
                whois_fields = parse_whois_fields(whois_raw(host_ip))
                self._log("done\n", "open")
                for k, v in dns_info.items():
                    self._log(f"   {k}: {v}\n", "dim")
                for k, v in list(whois_fields.items())[:4]:
                    self._log(f"   {k}: {v}\n", "dim")
            except Exception as e:
                self._log(f"skipped ({e})\n", "warn")

        if self.stop_flag.is_set():
            self._log("\n[Scan stopped by user]\n", "warn"); return

        # ── TCP Scan ──────────────────────────────────────
        self._log(f"\n── TCP Scan ({mode.upper()}) — Ports {lo}–{hi} ──────────────\n", "section")
        self._put("status", text=f"Scanning {lo}–{hi} ports...")
        port_range = range(lo, hi + 1)
        total      = len(port_range)

        def progress_cb(done, _total):
            if self.stop_flag.is_set():
                return
            pct = done / _total * 100
            self._put("progress", pct=pct, done=done, total=_total)

        start_time = time.time()
        if mode == "async":
            scanner = AsyncScanner(host_ip, port_range,
                                   timeout=timeout, concurrency=500,
                                   progress_cb=progress_cb)
        else:
            scanner = TCPScanner(host_ip, port_range,
                                 threads=150, timeout=timeout,
                                 progress_cb=progress_cb)

        tcp_results = scanner.run()
        self._put("progress_done")

        # ── UDP ───────────────────────────────────────────
        udp_results = []
        if opts["udp"] and not self.stop_flag.is_set():
            self._log("\n→ UDP scan on common ports... ", "dim")
            try:
                udp_results = udp_scan(host_ip, timeout=timeout + 1)
                self._log(f"{len(udp_results)} open|filtered\n", "open")
            except Exception as e:
                self._log(f"failed ({e})\n", "warn")

        all_results  = tcp_results + udp_results
        elapsed      = time.time() - start_time

        # ── Print open ports ─────────────────────────────
        if all_results:
            self._log(f"\n  Found {len(all_results)} open port(s):\n\n", "bold")
        else:
            self._log("\n  No open ports found.\n", "warn")

        # ── Banner grabbing ───────────────────────────────
        all_banners = []
        if opts["banner"] and all_results and not self.stop_flag.is_set():
            self._log("→ Grabbing banners...\n", "dim")
            self._put("status", text="Grabbing service banners...")
            for r in all_results:
                if self.stop_flag.is_set(): break
                if r.get("protocol","tcp") == "tcp":
                    bnr      = grab_banner(host_ip, r["port"], timeout + 1.5)
                    svc, ver = fingerprint(bnr)
                    r["banner"]      = bnr
                    r["fingerprint"] = svc
                    r["version"]     = ver
                    all_banners.append(bnr)
                else:
                    r["banner"] = r["fingerprint"] = r["version"] = ""

        for r in all_results:
            svc  = r.get("fingerprint","") or r.get("service","?")
            ver  = f" v{r['version']}" if r.get("version") else ""
            bnr  = r.get("banner","")
            line = f"  [OPEN]  Port {r['port']:<6} → {svc}{ver}\n"
            self._log(line, "open")
            if bnr and bnr != "No banner":
                self._log(f"          ↳ {bnr[:90]}\n", "dim")

        # ── OS Detection ─────────────────────────────────
        os_guess = guess_os(all_banners) if all_banners else "Unknown"
        if os_guess != "Unknown":
            self._log(f"\n  [OS Guess] {os_guess}\n", "info")

        # ── Vulnerability analysis ────────────────────────
        vuln_findings, risk_counts = [], {}
        if opts["vuln"] and all_results and not self.stop_flag.is_set():
            self._put("status", text="Running vulnerability analysis...")
            self._log("\n── Vulnerability Analysis ──────────────────────────\n", "section")
            try:
                vuln_findings = analyze(all_results)
                risk_counts   = risk_summary(vuln_findings)
                if vuln_findings:
                    for f in vuln_findings:
                        cve  = f" ({f.cve_hint})" if f.cve_hint else ""
                        tag  = "vuln" if str(f.risk) in ("CRITICAL","HIGH") else "warn"
                        self._log(f"  [{f.risk}]  Port {f.port}  {f.title}{cve}\n", tag)
                        self._log(f"          ↳ {f.description[:82]}\n", "dim")
                        if f.remediation:
                            self._log(f"          Fix: {f.remediation[:76]}\n", "dim")
                    summary = "  Summary: " + "  ".join(
                        f"{k}: {v}" for k, v in risk_counts.items() if v) + "\n"
                    self._log(summary, "warn")
                else:
                    self._log("  ✓ No known vulnerabilities detected\n", "open")
            except Exception as e:
                self._log(f"  Vuln analysis error: {e}\n", "warn")

        # ── Summary ───────────────────────────────────────
        self._log(f"\n{'═'*58}\n", "dim")
        self._log(f"  Scan complete in {elapsed:.2f}s\n", "bold")
        self._log(f"  Open TCP ports  : {len(tcp_results)}\n", "open")
        if opts["udp"]:
            self._log(f"  Open UDP ports  : {len(udp_results)}\n", "open")
        if os_guess != "Unknown":
            self._log(f"  OS (heuristic)  : {os_guess}\n", "info")
        if vuln_findings:
            self._log(f"  Vulnerabilities : {len(vuln_findings)}\n", "vuln")

        # ── Reports ───────────────────────────────────────
        output = opts["output"]
        if output != "none" and all_results:
            self._put("status", text="Saving reports...")
            self._log("\n  Saving reports...\n", "dim")
            try:
                if output in ("json","all"):
                    fname = f"{base}.json"
                    save_json(target, host_ip, scan_time, elapsed, all_results,
                              vuln_findings, dns_info, whois_fields, os_guess,
                              risk_counts, fname)
                    self._log(f"  [+] JSON  → {fname}\n", "info")
                if output in ("csv","all"):
                    save_csv(all_results, vuln_findings, base)
                    self._log(f"  [+] CSV   → {base}_ports.csv\n", "info")
                if output in ("html","all"):
                    html = generate_html(
                        target=target, host_ip=host_ip, scan_time=scan_time,
                        elapsed=elapsed, scan_mode=f"{mode.upper()} / GUI",
                        port_results=all_results, vuln_findings=vuln_findings,
                        dns_info=dns_info, whois_fields=whois_fields,
                        os_guess=os_guess, risk_counts=risk_counts,
                    )
                    fname = f"{base}.html"
                    save_html(html, fname)
                    self._log(f"  [+] HTML  → {fname}\n", "info")
            except Exception as e:
                self._log(f"  Report error: {e}\n", "warn")

        self._log(f"\n  Reminder: Only scan systems you own or have permission to test.\n", "dim")
        self._put("status", text=f"Done — {len(tcp_results)} open TCP port(s) in {elapsed:.1f}s")


def main():
    root = tk.Tk()
    app  = PortScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
