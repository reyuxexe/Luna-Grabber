"""Quarantine: moves a file into a vault with metadata. Requires explicit confirmation."""
from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

from sentinel.core.hashing import sha256_file
from sentinel.core.logging_setup import data_dir


class QuarantineError(Exception):
    pass


class Quarantine:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root else data_dir() / "Quarantine"
        self.root.mkdir(parents=True, exist_ok=True)

    def quarantine(self, path: str, confirmed_by_user: bool) -> Path:
        if not confirmed_by_user:
            raise QuarantineError("User confirmation required")
        src = Path(path)
        if not src.is_file():
            raise QuarantineError(f"Not a file: {path}")
        digest = sha256_file(str(src))
        dest = self.root / f"{int(time.time())}_{digest[:16]}.quarantined"
        try:
            shutil.move(str(src), dest)
        except OSError as exc:
            raise QuarantineError(f"Move failed: {exc}") from exc
        meta = {"original_path": str(src.resolve()), "sha256": digest, "time": time.time()}
        dest.with_suffix(".json").write_text(json.dumps(meta), encoding="utf-8")
        return dest

    def list(self) -> list[dict]:
        out = []
        for m in sorted(self.root.glob("*.json")):
            try:
                d = json.loads(m.read_text(encoding="utf-8"))
                d["vault_file"] = str(m.with_suffix(".quarantined"))
                out.append(d)
            except (OSError, ValueError):
                continue
        return out

    def restore(self, vault_file: str, confirmed_by_user: bool) -> str:
        if not confirmed_by_user:
            raise QuarantineError("User confirmation required")
        v = Path(vault_file)
        meta = json.loads(v.with_suffix(".json").read_text(encoding="utf-8"))
        target = Path(meta["original_path"])
        if target.exists():
            raise QuarantineError(f"Destination exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(v), target)
        os.remove(v.with_suffix(".json"))
        return str(target)
