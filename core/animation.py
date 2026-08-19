"""
core/animation.py
──────────────────────────────────────────────────────────────
Hacker-style terminal animation for Port Scanner
  ·  3-D rotating globe  (orthographic projection)
  ·  Radar sweep with glowing trail
  ·  Matrix rain side columns
  ·  Live progress bar with neon pulse/flicker
  ·  Thread-safe stat updates
  ·  Stdout capture so scan prints don't corrupt the display

Usage:
    anim = ScanAnimation()
    anim.set_info(target, ip, lo, hi, mode)
    anim.start()                               # grabs stdout
    # … scanning …
    anim.update(scanned, total, open_results)  # call from progress_cb
    captured = anim.stop()                     # releases stdout, returns buffered text
    print(captured, end="")                    # show full results
"""

import sys, math, time, threading, random, shutil, re, io, os

# ── ANSI helpers ─────────────────────────────────────────
ESC = "\033"
RST  = f"{ESC}[0m"
BOLD = f"{ESC}[1m"
HIDE = f"{ESC}[?25l"
SHOW = f"{ESC}[?25h"

def _rgb(r, g, b): return f"{ESC}[38;2;{r};{g};{b}m"
def _up(n):        return f"{ESC}[{n}A"
def _clrln():      return f"{ESC}[2K"

# Neon-green palette
C_NEON   = _rgb(0,  255, 70)
C_BRIGHT = _rgb(0,  210, 50)
C_MID    = _rgb(0,  150, 35)
C_FAINT  = _rgb(0,   75, 18)
C_DIMMER = _rgb(0,   35,  8)
C_SWEEP  = _rgb(0,  255,200)    # cyan-green sweep head
C_WHITE  = _rgb(220,255,220)    # matrix head
C_BORDER = _rgb(0,  165, 40)
C_LABEL  = _rgb(0,  200, 55)
C_INFO   = _rgb(0,  230, 75)
C_DONE   = _rgb(80, 255,120)

def _strip(s):  return re.sub(r'\x1b\[[0-9;]*[mHJKABCDsu]|\x1b\[[\?]*[0-9;]*[lh]', '', s)
def _vlen(s):   return len(_strip(s))
def _pad(s, w): return s + ' ' * max(0, w - _vlen(s))


# ── Globe constants ──────────────────────────────────────
GW  = 23       # visible width
GH  = 11       # visible height  (GW ≈ 2 × GH for near-circle in terminal)
GCX = GW // 2  # centre x = 11
GCY = GH // 2  # centre y =  5
GRX = 10       # x radius
GRY =  5       # y radius

def _globe(rot: float, sweep: float, frame: int) -> list:
    """
    Returns GH colored strings, each GW visible chars wide.
    rot   – globe Y-axis rotation (radians)
    sweep – radar sweep angle (radians)
    frame – frame counter (flicker)
    """
    # grid: (char, depth)
    grid = [[(' ', -9.0)] * GW for _ in range(GH)]

    # ── latitude rings ──────────────────────────────────
    for lat_d in range(0, 181, 20):
        for lon_d in range(0, 360, 4):
            lat = math.radians(lat_d)
            lon = math.radians(lon_d) + rot
            x3  = math.sin(lat) * math.cos(lon)
            y3  = math.cos(lat)
            z3  = math.sin(lat) * math.sin(lon)
            sx  = int(GCX + GRX * x3 * 0.9)
            sy  = int(GCY - GRY * y3)
            if 0 <= sx < GW and 0 <= sy < GH:
                if z3 > grid[sy][sx][1]:
                    grid[sy][sx] = ('·', z3)

    # ── longitude lines ──────────────────────────────────
    for lon_d in range(0, 180, 20):
        for lat_d in range(0, 181, 3):
            lat = math.radians(lat_d)
            lon = math.radians(lon_d) + rot
            x3  = math.sin(lat) * math.cos(lon)
            y3  = math.cos(lat)
            z3  = math.sin(lat) * math.sin(lon)
            sx  = int(GCX + GRX * x3 * 0.9)
            sy  = int(GCY - GRY * y3)
            if 0 <= sx < GW and 0 <= sy < GH:
                if z3 > grid[sy][sx][1]:
                    grid[sy][sx] = ('+', z3)

    # ── radar sweep + trail ──────────────────────────────
    TRAIL = 110  # degrees of fading trail
    for td in range(0, TRAIL + 1, 2):
        angle  = sweep - math.radians(td)
        intens = 1.0 - (td / TRAIL)
        for r in range(1, min(GRX, GRY) + 1):
            sx = int(GCX + r * math.cos(angle))
            sy = int(GCY + r * 0.5 * math.sin(angle))
            if 0 <= sx < GW and 0 <= sy < GH:
                if td == 0:
                    grid[sy][sx] = ('█', 99.0)
                elif intens > 0.55:
                    grid[sy][sx] = ('▓', 98.0)
                elif intens > 0.28:
                    grid[sy][sx] = ('░', 97.0)
                else:
                    grid[sy][sx] = ('·', 96.0)

    grid[GCY][GCX] = ('◎', 100.0)  # centre dot always on top

    # ── colorise ─────────────────────────────────────────
    flk   = (frame % 8 < 6)   # flicker: true most of the time
    lines = []
    for row in grid:
        line = ''
        for ch, d in row:
            if d >= 99.0:                        # sweep head
                line += (C_SWEEP if flk else C_BRIGHT) + ch + RST
            elif d >= 97.0:                      # sweep trail
                line += (C_NEON if d >= 98.0 else C_MID) + ch + RST
            elif d >= 96.0:
                line += C_FAINT + ch + RST
            else:                                # globe surface (depth shading)
                if   d > 0.55: line += C_NEON   + ch + RST
                elif d > 0.15: line += C_BRIGHT  + ch + RST
                elif d > -0.2: line += C_MID     + ch + RST
                elif d > -0.6: line += C_FAINT   + ch + RST
                else:          line += C_DIMMER  + ch + RST
        lines.append(line)
    return lines


# ── Matrix rain ──────────────────────────────────────────
_MCHARS = list("0123456789012345678901234567890123456789")

class _MatCol:
    def __init__(self, h: int):
        self.h     = h
        self.chars = [random.choice(_MCHARS) for _ in range(h)]
        self.head  = random.randint(0, h - 1)
        self._t    = random.uniform(0, 0.4)
        self._spd  = random.uniform(0.12, 0.45)

    def tick(self, dt: float):
        self._t += dt
        if self._t >= self._spd:
            self._t   = 0.0
            self.head = (self.head + 1) % self.h
            self.chars[random.randint(0, self.h - 1)] = random.choice(_MCHARS)

    def render(self, row: int) -> str:
        c    = self.chars[row]
        dist = (self.head - row) % self.h
        if   row  == self.head: return C_WHITE  + BOLD + c + RST
        elif dist <  3:         return C_NEON   + c + RST
        elif dist <  6:         return C_BRIGHT + c + RST
        elif dist < 10:         return C_MID    + c + RST
        else:                   return C_DIMMER + c + RST


# ── Main animation class ─────────────────────────────────
class ScanAnimation:
    NLINES  = 23     # terminal lines the animation occupies
    FPS     = 12
    MAT_N   = 7      # matrix columns per side (= 7 visible chars each side)
    # Fixed overhead per row: ║·(2) + mat(7) + ·(1) + globe(23) + ·(1) + mat(7) + ··(2) = 43
    _OVERHEAD = 2 + MAT_N + 1 + GW + 1 + MAT_N + 2   # = 43

    def __init__(self):
        self._stop   = threading.Event()
        self._thread = None
        self._lock   = threading.Lock()
        self._stats  = dict(target="—", ip="—", lo=1, hi=1000,
                            mode="THREAD", scanned=0, total=1000,
                            open=[], elapsed=0.0, status="INIT")
        self._rot    = 0.0
        self._sweep  = 0.0
        self._frame  = 0
        self._t0     = None
        self._real   = sys.stdout   # reference to the real terminal
        self._buf    = None         # StringIO for captured scan prints
        self._mat_L  = [_MatCol(GH) for _ in range(self.MAT_N)]
        self._mat_R  = [_MatCol(GH) for _ in range(self.MAT_N)]

    # ── Public API ────────────────────────────────────────
    def set_info(self, target: str, ip: str, lo: int, hi: int, mode: str):
        with self._lock:
            self._stats.update(target=target, ip=ip, lo=lo, hi=hi,
                               total=hi-lo+1, mode=mode.upper(), status="SCANNING")

    def update(self, scanned: int, total: int, open_ports: list = None):
        with self._lock:
            self._stats["scanned"] = scanned
            self._stats["total"]   = total
            if open_ports is not None:
                self._stats["open"] = list(open_ports)
            if self._t0:
                self._stats["elapsed"] = time.time() - self._t0

    def start(self):
        """Reserve terminal space, capture stdout, start animation thread."""
        self._real = sys.stdout
        # Reserve NLINES rows on the real terminal
        self._real.write(HIDE + "\n" * self.NLINES)
        self._real.flush()
        # Redirect future prints to buffer (scan output captured, not lost)
        self._buf  = io.StringIO()
        sys.stdout = self._buf
        self._stop.clear()
        self._t0     = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> str:
        """
        Stop animation, restore stdout.
        Returns the text that was printed to stdout during scanning.
        """
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        # Draw COMPLETE frame on real terminal
        with self._lock:
            self._stats["status"] = "COMPLETE"
            self._stats["elapsed"] = time.time() - self._t0 if self._t0 else 0.0
        self._draw_now()
        # Restore stdout
        captured = self._buf.getvalue() if self._buf else ""
        sys.stdout = self._real
        self._real.write(SHOW + "\n")
        self._real.flush()
        return captured

    # ── Internal ─────────────────────────────────────────
    def _loop(self):
        interval = 1.0 / self.FPS
        while not self._stop.is_set():
            t0 = time.time()
            self._rot   += math.radians(4)
            self._sweep += math.radians(7)
            self._frame += 1
            dt = interval
            for mc in self._mat_L + self._mat_R:
                mc.tick(dt)
            self._draw_now()
            sleep = interval - (time.time() - t0)
            if sleep > 0:
                time.sleep(sleep)

    def _draw_now(self):
        with self._lock:
            s = dict(self._stats)
        W    = min(shutil.get_terminal_size((82, 24)).columns - 2, 92)
        W    = max(W, 76)
        IW   = W - 2
        INFO = max(IW - self._OVERHEAD, 28)   # info panel width
        lines = self._build(s, W, IW, INFO)
        buf   = [f"\r{_up(self.NLINES)}"]
        for i, ln in enumerate(lines[:self.NLINES]):
            buf.append(f"{_clrln()}{ln}")
            if i < self.NLINES - 1:
                buf.append("\n")
        self._real.write("".join(buf))
        self._real.flush()

    def _build(self, s, W, IW, INFO) -> list:
        lines = []
        BDR   = C_BORDER
        R     = RST

        # ── top border ──────────────────────────────────────
        lines.append(f"{BDR}╔{'═'*IW}╗{R}")

        # ── title row ────────────────────────────────────────
        t_left  = f"  {C_NEON}{BOLD}PORT SCANNER v2.0{R}{BDR}"
        _SPIN_GLOBE = ["◐","◓","◑","◒"]
        _spin_char  = C_NEON + BOLD + _SPIN_GLOBE[self._frame % 4] + RST + BDR
        t_right = f"{C_BRIGHT}Made by {C_NEON}{BOLD}Batsaikhan Naragel{RST}{BDR}  {_spin_char}  "
        lines.append(_pad(f"{BDR}║{t_left}  {t_right}", W-1) + f"║{R}")

        # ── subtitle row ─────────────────────────────────────
        sub = f"  {C_DIMMER}Banner Grab · Radar Sweep · OS Detect · Vuln Scan · Reports{R}{BDR}"
        lines.append(_pad(f"{BDR}║{sub}", W-1) + f"║{R}")

        # ── separator ────────────────────────────────────────
        lines.append(f"{BDR}╠{'═'*IW}╣{R}")

        # ── globe + matrix + info section ────────────────────
        globe    = _globe(self._rot, self._sweep, self._frame)
        open_p   = s["open"]
        info_r   = [
            f"{C_LABEL}TARGET {R}: {C_INFO}{s['target']}{R}",
            f"{C_LABEL}IP     {R}: {C_INFO}{s['ip']}{R}",
            f"{C_LABEL}PORTS  {R}: {C_INFO}{s['lo']} – {s['hi']}{R}",
            f"{C_LABEL}MODE   {R}: {C_INFO}{s['mode']}{R}",
            f"{C_LABEL}ELAPSED{R}: {C_INFO}{s['elapsed']:.1f}s{R}",
            "",
            f"{C_LABEL}OPEN   {R}: {C_NEON}{BOLD}{len(open_p)}{R} port(s)",
        ]
        for p in open_p[-4:]:
            pt  = p.get("port","?")
            svc = p.get("service","?")
            info_r.append(f"  {C_SWEEP}◎ {pt:<5}{R}{C_MID}{svc}{R}")
        while len(info_r) < GH:
            info_r.append("")

        for i in range(GH):
            ml = "".join(mc.render(i) for mc in self._mat_L)
            mr = "".join(mc.render(i) for mc in self._mat_R)
            gl = globe[i] if i < len(globe) else " " * GW
            ir = _pad(info_r[i] if i < len(info_r) else "", INFO)
            lines.append(f"{BDR}║ {R}{ml} {gl} {mr}  {ir}{BDR}║{R}")

        # ── middle separator ─────────────────────────────────
        lines.append(f"{BDR}╠{'═'*IW}╣{R}")

        # ── progress bar ─────────────────────────────────────
        sc, tot  = s["scanned"], s["total"]
        pct      = sc / tot * 100 if tot else 0
        BAR_W    = max(IW - 26, 10)
        filled   = int(BAR_W * pct / 100)
        empty    = BAR_W - filled
        flk      = C_NEON if self._frame % 6 < 4 else C_BRIGHT  # pulse
        bar      = flk + "█"*filled + C_DIMMER + "░"*empty + R
        prog     = f"{BDR}║ {R}{C_LABEL}PROGRESS {R}[{bar}] {C_NEON}{pct:5.1f}%{R}  {C_FAINT}{sc}/{tot}{R}"
        lines.append(_pad(prog, W-1) + f"{BDR}║{R}")

        # ── status line ──────────────────────────────────────
        st   = s["status"]
        SPIN = ["◐","◓","◑","◒"]
        if st == "COMPLETE":
            icon = C_DONE   + "✔" + R
            stxt = C_DONE   + BOLD + " SCAN COMPLETE" + R
        elif st == "SCANNING":
            icon = C_SWEEP  + SPIN[self._frame % 4] + R
            stxt = C_BRIGHT + " SCANNING" + R + C_FAINT + "  live radar active" + R
        else:
            icon = C_MID    + "◌" + R
            stxt = C_MID    + f" {st}" + R

        stat_row = f"{BDR}║ {R}{icon}{stxt}  {C_FAINT}found: {len(open_p)} port(s){R}"
        lines.append(_pad(stat_row, W-1) + f"{BDR}║{R}")

        # ── bottom border ────────────────────────────────────
        lines.append(f"{BDR}╚{'═'*IW}╝{R}")

        while len(lines) < self.NLINES:
            lines.append("")
        return lines
