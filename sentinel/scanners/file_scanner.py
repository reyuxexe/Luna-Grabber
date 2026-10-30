"""Static file scanner: SHA-256, IOC lookup, content heuristics. Never executes files."""
from __future__ import annotations

import logging
import os
import re
from typing import Callable, Iterator

from sentinel.core.hashing import sha256_file
from sentinel.core.models import Finding, Severity, Verdict
from sentinel.core.signatures import (CONTENT_PATTERNS, SCAN_EXTENSIONS, IOCDatabase)

log = logging.getLogger("sentinel.file")
MAX_READ = 20 * 1024 * 1024
_BYTES_PATTERNS = [(p, re.compile(p.regex.pattern.encode(), re.I)) for p in CONTENT_PATTERNS]


def score_content(data: bytes) -> tuple[int, set[str], list[str]]:
    """Return (score, groups, indicator names). Also tries UTF-16 text (PowerShell, PE strings)."""
    variants = [data]
    if b"\x00" in data[:4096]:
        variants.append(data.replace(b"\x00", b""))
    score, groups, names = 0, set(), []
    for p, rx in _BYTES_PATTERNS:
        if any(rx.search(v) for v in variants):
            score += p.weight
            groups.add(p.group)
            names.append(p.name)
    return score, groups, names


def classify(score: int, groups: set[str]) -> tuple[Severity, str] | None:
    """Heuristic thresholds. Single weak hits are ignored to limit false positives."""
    if ("credstore" in groups or "discord" in groups) and "exfil" in groups:
        return Severity.HIGH, "Credential/token-store access combined with exfiltration indicators"
    if score >= 6:
        return Severity.HIGH, "Multiple strong suspicious indicators"
    if score >= 3:
        return Severity.MEDIUM, "Some suspicious indicators"
    return None


def scan_file(path: str, ioc: IOCDatabase | None = None) -> Finding | None:
    try:
        digest = sha256_file(path)
    except OSError as exc:
        log.warning("cannot read %s: %s", path, exc)
        return Finding("file", "File could not be read", Verdict.UNKNOWN, Severity.INFO, path,
                       details=f"{type(exc).__name__}: {exc}")
    if ioc:
        name = ioc.lookup(digest)
        if name:
            return Finding("file", f"Known malware hash match: {name}", Verdict.CONFIRMED,
                           Severity.CRITICAL, path, ["SHA-256 matches IOC database entry"], digest)
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_READ)
    except OSError as exc:
        return Finding("file", "File could not be read", Verdict.UNKNOWN, Severity.INFO, path,
                       sha256=digest, details=str(exc))
    score, groups, names = score_content(data)
    result = classify(score, groups)
    if not result:
        return None
    sev, why = result
    return Finding("file", "Suspicious file content", Verdict.SUSPICIOUS, sev, path, names, digest,
                   details=why + ". Heuristic only - review before acting; not a confirmed detection.")


def iter_files(roots: list[str], should_stop: Callable[[], bool] = lambda: False) -> Iterator[str]:
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dp, dn, fn in os.walk(root, onerror=lambda e: log.debug("walk: %s", e)):
            if should_stop():
                return
            dn[:] = [d for d in dn if d.lower() not in {"node_modules", ".git", "winsxs"}]
            for f in fn:
                if os.path.splitext(f)[1].lower() in SCAN_EXTENSIONS:
                    yield os.path.join(dp, f)


def scan_paths(roots: list[str], ioc: IOCDatabase | None = None,
               progress: Callable[[int, str], None] | None = None,
               should_stop: Callable[[], bool] = lambda: False) -> tuple[list[Finding], int]:
    findings, count = [], 0
    for p in iter_files(roots, should_stop):
        count += 1
        if progress:
            progress(count, p)
        try:
            f = scan_file(p, ioc)
        except Exception:  # keep scanning on unexpected per-file errors
            log.exception("scan failed: %s", p)
            continue
        if f:
            findings.append(f)
    return findings, count
