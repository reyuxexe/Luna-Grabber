"""Persistence audit: Run keys, Winlogon, IFEO debuggers, Startup folders."""
from __future__ import annotations

import logging
import ntpath
import os
import re
import sys

from sentinel.core.models import Finding, Severity, Verdict
from sentinel.core.signatures import IOCDatabase, LOLBIN_NAMES, SUSPICIOUS_DIR_FRAGMENTS
from sentinel.scanners.file_scanner import scan_file

log = logging.getLogger("sentinel.startup")
_EXE_RE = re.compile(r'^\s*"?([A-Za-z]:\\[^"]*?\.(?:exe|bat|cmd|ps1|vbs|js|dll))"?', re.I)

RUN_KEYS = [("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")]


def extract_path(command: str) -> str | None:
    m = _EXE_RE.match(os.path.expandvars(command))
    return m.group(1) if m else None


def evaluate_command(location: str, name: str, command: str, ioc: IOCDatabase | None) -> Finding | None:
    """Evaluate one autostart entry. Entries in normal locations produce no finding."""
    ind: list[str] = []
    sev = Severity.LOW
    low = os.path.expandvars(command).lower()
    path = extract_path(command)
    sha = None
    if path and any(f in path.lower() for f in SUSPICIOUS_DIR_FRAGMENTS):
        ind.append(f"Runs from user-writable location: {path}")
        sev = Severity.MEDIUM
    first = ntpath.basename(path).lower() if path else ""
    if first in LOLBIN_NAMES and re.search(r"-enc|-w(indowstyle)?\s+hidden|downloadstring|http[s]?://|\.vbs|\.js", low):
        ind.append("Script host / LOLBin with hidden, encoded or remote arguments")
        sev = Severity.HIGH
    if path and not os.path.exists(path):
        ind.append("Target file does not exist (dangling entry)")
    if path and os.path.isfile(path):
        f = scan_file(path, ioc)
        if f and f.verdict == Verdict.CONFIRMED:
            return Finding("startup", f"Autostart entry runs known malware: {name}", Verdict.CONFIRMED,
                           Severity.CRITICAL, f"{location} -> {command}", f.indicators, f.sha256)
        if f and f.verdict == Verdict.SUSPICIOUS:
            ind.extend(f"Target content: {i}" for i in f.indicators)
            sha = f.sha256
            sev = max(sev, f.severity)
    if not ind or ind == ["Target file does not exist (dangling entry)"]:
        return None
    return Finding("startup", f"Suspicious autostart entry: {name}", Verdict.SUSPICIOUS, sev,
                   f"{location} -> {command}", ind, sha,
                   details="Persistence mechanism with suspicious traits; verify you installed it.")


def scan_startup(ioc: IOCDatabase | None = None) -> list[Finding]:
    findings: list[Finding] = []
    if sys.platform != "win32":
        return [Finding("startup", "Startup audit unavailable", Verdict.UNKNOWN, Severity.INFO,
                        "registry", details="Windows-only check; not run on this OS.")]
    import winreg
    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    for hive, sub in RUN_KEYS:
        try:
            with winreg.OpenKey(hives[hive], sub) as k:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    f = evaluate_command(f"{hive}\\{sub}", n, str(v), ioc)
                    if f:
                        findings.append(f)
        except OSError:
            continue
    # Winlogon Shell / Userinit hijack
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") as k:
            for name, expected in (("Shell", "explorer.exe"), ("Userinit", r"c:\windows\system32\userinit.exe,")):
                try:
                    v = str(winreg.QueryValueEx(k, name)[0])
                except OSError:
                    continue
                if v.strip().lower() != expected:
                    findings.append(Finding("startup", f"Winlogon {name} modified", Verdict.SUSPICIOUS,
                                            Severity.HIGH, f"Winlogon\\{name} = {v}",
                                            [f"Expected '{expected}'"], details="Unauthorized system modification possible."))
    except OSError as exc:
        log.debug("winlogon: %s", exc)
    # IFEO debugger hijacks
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options") as k:
            i = 0
            while True:
                try:
                    sk = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(k, sk) as s:
                        dbg = winreg.QueryValueEx(s, "Debugger")[0]
                        findings.append(Finding("startup", f"IFEO debugger set for {sk}", Verdict.SUSPICIOUS,
                                                Severity.HIGH, f"IFEO\\{sk}", [f"Debugger = {dbg}"],
                                                details="Can hijack program launch; legitimate for some debuggers."))
                except OSError:
                    continue
    except OSError as exc:
        log.debug("ifeo: %s", exc)
    # Startup folders
    dirs = [os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")]
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            p = os.path.join(d, fn)
            if fn.lower() == "desktop.ini" or not os.path.isfile(p):
                continue
            if fn.lower().endswith((".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll")):
                f = scan_file(p, ioc)
                if f and f.verdict in (Verdict.CONFIRMED, Verdict.SUSPICIOUS):
                    f.category = "startup"
                    findings.append(f)
                else:
                    findings.append(Finding("startup", f"Executable/script in Startup folder: {fn}",
                                            Verdict.INFO, Severity.LOW, p, ["Auto-runs at logon"]))
    return findings
