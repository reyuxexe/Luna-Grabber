"""Process audit + access to browser/Discord data stores (file paths only, never contents)."""
from __future__ import annotations

import logging
import ntpath
import os
import re
from dataclasses import dataclass, field

from sentinel.core.models import Finding, Severity, Verdict
from sentinel.core.signatures import (BROWSER_PROCESS_NAMES, DISCORD_PROCESS_NAMES, IOCDatabase,
                                      LOLBIN_NAMES, SENSITIVE_BROWSER_FILES, SUSPICIOUS_DIR_FRAGMENTS)
from sentinel.scanners.file_scanner import scan_file

log = logging.getLogger("sentinel.process")
_SUSP_CMD = re.compile(r"-enc(odedcommand)?\s+\S{40,}|-w(indowstyle)?\s+hidden|downloadstring|frombase64string|"
                       r"add-mppreference|disablerealtimemonitoring", re.I)


@dataclass
class ProcInfo:
    pid: int
    name: str
    exe: str = ""
    cmdline: list[str] = field(default_factory=list)
    parent_name: str = ""
    open_paths: list[str] = field(default_factory=list)


def sensitive_store_kind(path: str) -> str | None:
    """Classify a path as a browser/Discord credential store, or None."""
    p = path.replace("/", "\\").lower()
    base = ntpath.basename(p)
    if "\\discord" in p and "\\local storage\\leveldb" in p:
        return "Discord token store"
    if base in SENSITIVE_BROWSER_FILES and any(s in p for s in (
            "\\user data\\", "\\mozilla\\firefox\\profiles\\", "\\opera software\\")):
        return "Browser credential/session store"
    return None


def evaluate_process(pi: ProcInfo, ioc: IOCDatabase | None = None, scan_exe: bool = True) -> list[Finding]:
    out: list[Finding] = []
    name = pi.name.lower()
    label = f"{pi.name} (PID {pi.pid})"
    ind: list[str] = []
    sev = Severity.LOW
    sha = None
    exe_low = pi.exe.lower()
    if exe_low and any(f in exe_low for f in SUSPICIOUS_DIR_FRAGMENTS) and name not in BROWSER_PROCESS_NAMES | DISCORD_PROCESS_NAMES:
        ind.append(f"Executable runs from user-writable path: {pi.exe}")
        sev = Severity.MEDIUM
    cmd = " ".join(pi.cmdline)
    if name in LOLBIN_NAMES and _SUSP_CMD.search(cmd):
        ind.append("Script host launched with encoded/hidden/download arguments")
        sev = max(sev, Severity.HIGH)
    if scan_exe and pi.exe and os.path.isfile(pi.exe) and not exe_low.startswith(
            os.path.expandvars(r"%windir%").lower() + "\\"):
        f = scan_file(pi.exe, ioc)
        if f and f.verdict == Verdict.CONFIRMED:
            return [Finding("process", f"Running process matches known malware: {label}", Verdict.CONFIRMED,
                            Severity.CRITICAL, pi.exe, f.indicators, f.sha256)]
        if f and f.verdict == Verdict.SUSPICIOUS:
            ind.extend(f"Image content: {i}" for i in f.indicators)
            sha, sev = f.sha256, max(sev, f.severity)
    if ind and sev >= Severity.MEDIUM:
        out.append(Finding("process", f"Suspicious process: {label}", Verdict.SUSPICIOUS, sev,
                           pi.exe or pi.name, ind, sha,
                           details="Heuristic indicators only; verify the process is expected."))
    # Access to credential stores by a non-owner application
    if name not in BROWSER_PROCESS_NAMES and name not in DISCORD_PROCESS_NAMES:
        for pth in pi.open_paths:
            kind = sensitive_store_kind(pth)
            if kind:
                cat = "discord" if "Discord" in kind else "browser"
                out.append(Finding(cat, f"{label} has open handle to {kind}", Verdict.SUSPICIOUS,
                                   Severity.HIGH, pth, ["Non-owner process holding credential store file open"],
                                   details="Only the file path was observed; contents were not read. "
                                           "Backup/AV tools can cause this legitimately."))
    return out


def snapshot_processes(with_files: bool = True) -> list[ProcInfo]:
    import psutil
    procs: dict[int, psutil.Process] = {}
    result = []
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
        try:
            info = p.info
            pi = ProcInfo(info["pid"], info["name"] or "?", info["exe"] or "", info["cmdline"] or [])
            if with_files:
                try:
                    pi.open_paths = [f.path for f in p.open_files()]
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    pass
            result.append(pi)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return result


def scan_processes(ioc: IOCDatabase | None = None, progress=None, should_stop=lambda: False) -> list[Finding]:
    try:
        procs = snapshot_processes()
    except ImportError:
        return [Finding("process", "Process scan unavailable", Verdict.UNKNOWN, Severity.INFO, "psutil",
                        details="psutil is not installed.")]
    findings: list[Finding] = []
    for i, pi in enumerate(procs, 1):
        if should_stop():
            break
        if progress:
            progress(i, pi.name)
        try:
            findings.extend(evaluate_process(pi, ioc))
        except Exception:
            log.exception("process eval failed pid=%s", pi.pid)
    return findings
