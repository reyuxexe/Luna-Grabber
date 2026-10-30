# Sentinel Security Auditor

Defensive Windows scanner for infostealers, token grabbers and browser-session theft. Static analysis only: it never executes samples and never reads, shows or sends passwords, cookies or tokens (it only inspects file *paths*, extension manifests and file bytes for patterns). No network access.

## Verdicts
- **Confirmed** - SHA-256 equals an entry in an IOC list *you load* (Settings). No hashes are bundled, so none are fabricated.
- **Suspicious** - heuristic indicators (credential-store strings + exfil endpoints, encoded PowerShell, Run-key persistence from temp/AppData, non-browser process holding a browser/Discord store open, extensions with cookie+all-sites permissions...). May be benign.
- **Unknown** - couldn't be assessed (access denied, psutil/registry unavailable).

## Run
    pip install -r sentinel_requirements.txt   (Python 3.12+, Windows 10/11)
    python -m sentinel

Tests: `pip install pytest && pytest tests`

## Build the .exe (on Windows)
    build_exe.bat
or manually:
    pyinstaller --noconfirm --onefile --windowed --name Sentinel --collect-submodules sentinel sentinel\main.py
Result: `dist\Sentinel.exe`. Run as Administrator for full process-handle visibility.

## Limitations
Heuristic, polling-based real-time monitor (3 s); short-lived processes can be missed. Quarantine moves files into `%LOCALAPPDATA%\Sentinel\Quarantine` only after you confirm. Logs: `%LOCALAPPDATA%\Sentinel\sentinel.log`.
PySide6/psutil GUI and Windows registry code could not be executed in the build sandbox (Linux, no package index); only core logic was tested.
