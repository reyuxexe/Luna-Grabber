import logging
import logging.handlers
import os
from pathlib import Path


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    p = Path(base) / "Sentinel"
    p.mkdir(parents=True, exist_ok=True)
    return p


def setup_logging() -> logging.Logger:
    log = logging.getLogger("sentinel")
    if log.handlers:
        return log
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        fh = logging.handlers.RotatingFileHandler(
            data_dir() / "sentinel.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except OSError:
        pass
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    log.addHandler(sh)
    return log
