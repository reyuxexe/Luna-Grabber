"""Orchestrates all scanners."""
from __future__ import annotations

import logging
import os
from typing import Callable

from sentinel.core.models import Finding
from sentinel.core.signatures import IOCDatabase
from sentinel.scanners import browser_scanner, discord_scanner, file_scanner, process_scanner, startup_scanner

log = logging.getLogger("sentinel.engine")


def default_file_roots() -> list[str]:
    cands = [r"%TEMP%", r"%APPDATA%", r"%LOCALAPPDATA%\Temp", r"%USERPROFILE%\Downloads", r"%PUBLIC%"]
    return [p for p in (os.path.expandvars(c) for c in cands) if os.path.isdir(p)]


def run_full_scan(ioc: IOCDatabase, roots: list[str],
                  on_stage: Callable[[str, int], None] = lambda s, p: None,
                  on_status: Callable[[str], None] = lambda s: None,
                  should_stop: Callable[[], bool] = lambda: False) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    stages = [
        ("Processes", lambda: process_scanner.scan_processes(ioc, lambda i, n: on_status(f"Process: {n}"), should_stop)),
        ("Startup & persistence", lambda: startup_scanner.scan_startup(ioc)),
        ("Browser extensions", browser_scanner.scan_extensions),
        ("Discord client", discord_scanner.scan_discord_injection),
    ]
    total = len(stages) + 1
    for i, (name, fn) in enumerate(stages):
        if should_stop():
            return findings, 0
        on_stage(name, int(100 * i / total))
        try:
            findings.extend(fn())
        except Exception:
            log.exception("stage %s failed", name)
    on_stage("Files", int(100 * len(stages) / total))
    ff, n = file_scanner.scan_paths(roots, ioc, lambda c, p: on_status(f"File {c}: {p}"), should_stop)
    findings.extend(ff)
    on_stage("Done", 100)
    return findings, n
