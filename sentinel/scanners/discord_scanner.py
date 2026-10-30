"""Discord client integrity audit: looks for injected code in the client's JS modules."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from sentinel.core.models import Finding, Severity, Verdict
from sentinel.scanners.file_scanner import classify, score_content

log = logging.getLogger("sentinel.discord")
CLIENTS = ("Discord", "DiscordCanary", "DiscordPTB", "DiscordDevelopment")


def scan_discord_injection() -> list[Finding]:
    findings: list[Finding] = []
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        return findings
    for c in CLIENTS:
        root = Path(base) / c
        if not root.is_dir():
            continue
        for js in root.glob("app-*/modules/discord_desktop_core-*/discord_desktop_core/*.js"):
            try:
                data = js.read_bytes()[:5_000_000]
            except OSError as exc:
                log.debug("read %s: %s", js, exc)
                continue
            score, groups, names = score_content(data)
            # Stock core files never contain webhooks/token regexes/exfil endpoints.
            if groups & {"exfil", "discord"} and score >= 3:
                sev = classify(score, groups)
                findings.append(Finding("discord", f"Possible Discord client injection in {js.name}",
                                        Verdict.SUSPICIOUS, sev[0] if sev else Severity.MEDIUM, str(js), names,
                                        details="Core client script contains token/exfiltration patterns. "
                                                "Reinstall Discord and change your password if unexpected."))
    return findings
