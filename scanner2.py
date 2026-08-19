"""
core/scanner.py — Port scanning engine
Supports: TCP Connect (threaded), Async, UDP
Progress callback: pass progress_cb=fn(scanned, total) to get live updates
"""

import socket
import asyncio
import threading
import logging
from queue import Queue
from typing import List, Callable, Optional

logger = logging.getLogger("portscanner.scanner")


# ── Service name map ─────────────────────────────────────
SERVICE_MAP = {
    20:"FTP-Data", 21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
    53:"DNS", 67:"DHCP", 69:"TFTP", 80:"HTTP", 110:"POP3",
    119:"NNTP", 123:"NTP", 143:"IMAP", 161:"SNMP", 194:"IRC",
    443:"HTTPS", 445:"SMB", 465:"SMTPS", 514:"Syslog", 587:"SMTP",
    631:"IPP", 636:"LDAPS", 993:"IMAPS", 995:"POP3S", 1080:"SOCKS",
    1194:"OpenVPN", 1433:"MSSQL", 1521:"Oracle", 3306:"MySQL",
    3389:"RDP", 5432:"PostgreSQL", 5900:"VNC", 6379:"Redis",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt", 8888:"Jupyter",
    9200:"Elasticsearch", 27017:"MongoDB",
}

def get_service_name(port: int) -> str:
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "Unknown"


# ── Threaded TCP Scanner ─────────────────────────────────
class TCPScanner:
    def __init__(self, host_ip: str, ports: range, threads: int = 150,
                 timeout: float = 1.0, verbose: bool = False,
                 progress_cb: Optional[Callable] = None):
        self.host_ip     = host_ip
        self.ports       = ports
        self.threads     = min(threads, len(ports))
        self.timeout     = timeout
        self.verbose     = verbose
        self.progress_cb = progress_cb      # fn(scanned_count, total)
        self.results: List[dict] = []
        self._lock       = threading.Lock()
        self._queue      = Queue()
        self._scanned    = 0                # progress counter
        self._total      = len(ports)

    def _scan_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((self.host_ip, port)) == 0:
                    with self._lock:
                        self.results.append({"port": port, "state": "open",
                                             "protocol": "tcp",
                                             "service": get_service_name(port)})
                    logger.debug("TCP open: port %d", port)
                elif self.verbose:
                    logger.debug("TCP closed: port %d", port)
        except socket.error as e:
            logger.debug("Socket error on port %d: %s", port, e)
        finally:
            # Update progress after every port regardless of result
            with self._lock:
                self._scanned += 1
                if self.progress_cb:
                    self.progress_cb(self._scanned, self._total)

    def _worker(self):
        while not self._queue.empty():
            port = self._queue.get()
            self._scan_port(port)
            self._queue.task_done()

    def run(self) -> List[dict]:
        for p in self.ports:
            self._queue.put(p)
        pool = [threading.Thread(target=self._worker, daemon=True)
                for _ in range(self.threads)]
        for t in pool: t.start()
        for t in pool: t.join()
        self.results.sort(key=lambda x: x["port"])
        return self.results


# ── Async TCP Scanner ────────────────────────────────────
class AsyncScanner:
    def __init__(self, host_ip: str, ports: range,
                 timeout: float = 1.0, concurrency: int = 500,
                 progress_cb: Optional[Callable] = None):
        self.host_ip     = host_ip
        self.ports       = ports
        self.timeout     = timeout
        self.concurrency = concurrency
        self.progress_cb = progress_cb      # fn(scanned_count, total)
        self.results: List[dict] = []
        self._scanned    = 0
        self._total      = len(ports)
        self._lock       = asyncio.Lock() if False else None  # set in run()

    async def _scan_port(self, port: int, sem: asyncio.Semaphore):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host_ip, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                self.results.append({"port": port, "state": "open",
                                     "protocol": "tcp",
                                     "service": get_service_name(port)})
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
            finally:
                self._scanned += 1
                if self.progress_cb:
                    self.progress_cb(self._scanned, self._total)

    async def _run_async(self):
        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self._scan_port(p, sem) for p in self.ports]
        await asyncio.gather(*tasks)

    def run(self) -> List[dict]:
        self._scanned = 0
        asyncio.run(self._run_async())
        self.results.sort(key=lambda x: x["port"])
        return self.results


# ── UDP Scan (best-effort) ───────────────────────────────
UDP_COMMON = [53, 67, 69, 123, 161, 500, 514, 1194, 5353]

def udp_scan(host_ip: str, ports: List[int] = UDP_COMMON,
             timeout: float = 2.0) -> List[dict]:
    results = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(b"\x00" * 8, (host_ip, port))
                try:
                    s.recvfrom(1024)
                    results.append({"port": port, "state": "open|filtered",
                                    "protocol": "udp",
                                    "service": get_service_name(port)})
                except socket.timeout:
                    results.append({"port": port, "state": "open|filtered",
                                    "protocol": "udp",
                                    "service": get_service_name(port)})
        except PermissionError:
            logger.warning("UDP scan needs elevated privileges on some systems.")
            break
        except OSError as e:
            if "unreachable" in str(e).lower() or e.errno in (10054, 111):
                pass  # ICMP port-unreachable = closed
    return results
