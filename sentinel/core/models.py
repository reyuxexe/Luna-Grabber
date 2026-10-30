"""Result data model.

Verdicts are deliberately separated so the tool never overstates a result:
  CONFIRMED  - exact match against a known-bad SHA-256 in the IOC database.
  SUSPICIOUS - heuristic indicators; needs human review, may be benign.
  UNKNOWN    - could not be fully assessed (e.g. access denied).
  INFO       - informational audit note, not a threat.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum, IntEnum


class Verdict(str, Enum):
    CONFIRMED = "Confirmed"
    SUSPICIOUS = "Suspicious"
    UNKNOWN = "Unknown"
    INFO = "Info"


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    category: str            # process | file | startup | browser | discord | extension
    title: str
    verdict: Verdict
    severity: Severity
    target: str              # path, pid description, registry key...
    indicators: list[str] = field(default_factory=list)
    sha256: str | None = None
    details: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["severity"] = self.severity.name
        return d


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def findings_to_text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings.\n"
    out = []
    for f in sorted(findings, key=lambda x: -x.severity):
        out.append(f"[{f.severity.name}] [{f.verdict.value}] {f.title}")
        out.append(f"  Category : {f.category}")
        out.append(f"  Target   : {f.target}")
        if f.sha256:
            out.append(f"  SHA-256  : {f.sha256}")
        for i in f.indicators:
            out.append(f"  - {i}")
        if f.details:
            out.append(f"  Note     : {f.details}")
        out.append("")
    return "\n".join(out)
