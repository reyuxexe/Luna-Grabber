"""Browser extension audit by manifest permissions only. No profile data is read."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from sentinel.core.models import Finding, Severity, Verdict

log = logging.getLogger("sentinel.browser")

PROFILE_ROOTS = {
    "Chrome": r"%LOCALAPPDATA%\Google\Chrome\User Data",
    "Edge": r"%LOCALAPPDATA%\Microsoft\Edge\User Data",
    "Brave": r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",
    "Opera": r"%APPDATA%\Opera Software\Opera Stable",
    "Vivaldi": r"%LOCALAPPDATA%\Vivaldi\User Data",
}
BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def evaluate_manifest(manifest: dict) -> tuple[Severity, list[str]] | None:
    perms = {str(p) for p in manifest.get("permissions", []) if isinstance(p, str)}
    hosts = {str(p) for p in manifest.get("host_permissions", []) if isinstance(p, str)} | perms
    for cs in manifest.get("content_scripts", []) or []:
        hosts |= {str(m) for m in cs.get("matches", [])}
    broad = bool(hosts & BROAD_HOSTS)
    ind = []
    if "cookies" in perms and broad:
        ind.append("Can read cookies for all sites ('cookies' + broad host access)")
    if "webRequest" in perms and ("webRequestBlocking" in perms or "webRequestAuthProvider" in perms) and broad:
        ind.append("Can intercept/modify requests and auth for all sites")
    if "nativeMessaging" in perms:
        ind.append("Can communicate with native programs on this PC")
    if "debugger" in perms:
        ind.append("Uses the 'debugger' permission (full page access)")
    if "clipboardRead" in perms and broad:
        ind.append("Reads clipboard with broad site access")
    if not ind:
        return None
    strong = sum(1 for i in ind if i.startswith(("Can read cookies", "Can intercept", "Uses the")))
    return (Severity.MEDIUM if strong >= 2 else Severity.LOW), ind


def scan_extensions() -> list[Finding]:
    findings: list[Finding] = []
    for browser, root in PROFILE_ROOTS.items():
        base = Path(os.path.expandvars(root))
        if not base.is_dir():
            continue
        for ext_dir in base.glob("*/Extensions/*"):
            try:
                versions = sorted(v for v in ext_dir.iterdir() if v.is_dir())
                if not versions:
                    continue
                mf = json.loads((versions[-1] / "manifest.json").read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as exc:
                log.debug("manifest %s: %s", ext_dir, exc)
                continue
            res = evaluate_manifest(mf)
            if res:
                sev, ind = res
                name = str(mf.get("name", ext_dir.name))
                findings.append(Finding("extension", f"{browser} extension with sensitive permissions: {name}",
                                        Verdict.SUSPICIOUS, sev, str(versions[-1]), ind,
                                        details="Powerful permissions are common in legitimate extensions "
                                                "(password managers, ad blockers). Review whether you trust it."))
    return findings
