"""Detection knowledge base.

Known-bad hashes: NO hashes are bundled (shipping unverified hashes would be
fabricated data). Load your own from a text file (one SHA-256 per line, optional
'  # name' comment) via the IOC database; matches are the only CONFIRMED verdicts.

Content/behaviour patterns are heuristics => SUSPICIOUS only. Each carries a
weight; categories are combined by the file scanner to reduce false positives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Pattern:
    name: str
    group: str      # credstore | discord | exfil | obfusc | persist | evasion
    weight: int
    regex: re.Pattern


def _p(name, group, weight, rx):
    return Pattern(name, group, weight, re.compile(rx, re.I))


CONTENT_PATTERNS: list[Pattern] = [
    _p("Browser 'Login Data' credential DB reference", "credstore", 3, r"Login Data"),
    _p("Browser cookie DB reference", "credstore", 2, r"User Data[\\/ ]+.{0,40}(Cookies|Network)"),
    _p("Chromium 'Local State' / encrypted_key access", "credstore", 3, r"encrypted_key|os_crypt"),
    _p("Firefox key4.db / logins.json reference", "credstore", 3, r"key4\.db|logins\.json"),
    _p("DPAPI decrypt call", "credstore", 2, r"CryptUnprotectData"),
    _p("Discord token storage path", "discord", 3, r"discord(canary|ptb|development)?[\\/ ]+.{0,10}Local Storage[\\/ ]+leveldb|Local Storage[\\/]leveldb"),
    _p("Discord token regex", "discord", 3, r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}|mfa\.[\w-]{84}"),
    _p("Discord injection / webhook", "exfil", 3, r"discord(app)?\.com/api/webhooks/\d+/[\w-]+"),
    _p("Telegram bot API upload", "exfil", 3, r"api\.telegram\.org/bot"),
    _p("Anonymous file host upload", "exfil", 2, r"gofile\.io|anonfiles|transfer\.sh|file\.io"),
    _p("Clipboard / keystroke hooks", "exfil", 1, r"SetWindowsHookEx|GetAsyncKeyState|pyperclip"),
    _p("Screenshot capture", "exfil", 1, r"ImageGrab\.grab|CopyFromScreen"),
    _p("Encoded PowerShell command", "obfusc", 2, r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}"),
    _p("Base64 decode + exec/eval", "obfusc", 2, r"(exec|eval)\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads)"),
    _p("PowerShell download cradle", "obfusc", 2, r"IEX\s*\(?.{0,30}(DownloadString|Net\.WebClient)|Invoke-Expression.{0,40}DownloadString"),
    _p("JS eval(atob()) / fromCharCode obfuscation", "obfusc", 2, r"eval\s*\(\s*atob|String\.fromCharCode\(.{0,200}\)\s*\)"),
    _p("Registry Run key write", "persist", 2, r"CurrentVersion[\\/]+Run\b"),
    _p("Defender exclusion / disable", "evasion", 3, r"Add-MpPreference.{0,40}Exclusion|DisableRealtimeMonitoring"),
    _p("Anti-VM / sandbox checks", "evasion", 1, r"VBoxService|vmtoolsd|SbieDll|wireshark"),
    _p("Hidden window process spawn", "evasion", 1, r"-WindowStyle\s+Hidden|CREATE_NO_WINDOW"),
]

BROWSER_PROCESS_NAMES = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
                         "vivaldi.exe", "chromium.exe", "msedgewebview2.exe", "iexplore.exe"}
DISCORD_PROCESS_NAMES = {"discord.exe", "discordcanary.exe", "discordptb.exe", "update.exe"}

# Sensitive browser files (relative names). Accessing these from a non-browser is notable.
SENSITIVE_BROWSER_FILES = {"login data", "cookies", "web data", "local state", "key4.db",
                           "key3.db", "logins.json", "cookies.sqlite", "login data for account"}

LOLBIN_NAMES = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "regsvr32.exe", "rundll32.exe", "cmd.exe", "bitsadmin.exe", "certutil.exe"}

SUSPICIOUS_DIR_FRAGMENTS = ("\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\users\\public\\",
                            "\\programdata\\", "\\downloads\\", "\\$recycle.bin\\")

SCAN_EXTENSIONS = {".exe", ".dll", ".py", ".pyw", ".js", ".ps1", ".vbs", ".bat", ".cmd"}
TEXT_EXTENSIONS = {".py", ".pyw", ".js", ".ps1", ".vbs", ".bat", ".cmd"}

_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class IOCDatabase:
    """User-supplied known-bad SHA-256 set."""

    def __init__(self) -> None:
        self.hashes: dict[str, str] = {}

    def load_file(self, path: str | Path) -> int:
        n = 0
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            body, _, name = line.partition("#")
            body = body.strip()
            if _HASH_RE.match(body):
                self.hashes[body.lower()] = name.strip() or "user-supplied IOC"
                n += 1
        return n

    def lookup(self, sha256: str) -> str | None:
        return self.hashes.get(sha256.lower())
