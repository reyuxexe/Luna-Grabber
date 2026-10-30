"""Polling real-time monitor: evaluates newly started processes and new open handles."""
from __future__ import annotations

import logging
import threading
from typing import Callable

from sentinel.core.models import Finding
from sentinel.core.signatures import IOCDatabase
from sentinel.scanners.process_scanner import evaluate_process, snapshot_processes

log = logging.getLogger("sentinel.realtime")


class RealtimeMonitor:
    def __init__(self, ioc: IOCDatabase, on_finding: Callable[[Finding], None], interval: float = 3.0):
        self.ioc, self.on_finding, self.interval = ioc, on_finding, interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: set[tuple] = set()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="rt-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        first = True
        while not self._stop.is_set():
            try:
                for pi in snapshot_processes():
                    key = (pi.pid, pi.exe)
                    # Baseline pass: remember existing processes' exe scans, still alert on handles
                    for f in evaluate_process(pi, self.ioc, scan_exe=key not in self._seen):
                        fk = (f.title, f.target)
                        if fk not in self._seen:
                            self._seen.add(fk)
                            self.on_finding(f)
                    self._seen.add(key)
            except ImportError:
                log.error("psutil missing; real-time protection disabled")
                return
            except Exception:
                log.exception("monitor cycle failed")
            first = False
            self._stop.wait(self.interval)
