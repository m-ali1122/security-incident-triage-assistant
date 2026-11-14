"""Loading and switching alternate Markdown data packs.

The registry is deliberately process-local.  A pack is immutable after it has
been built, so switching the active pack is just changing one reference.
"""
from __future__ import annotations

import hashlib
import io
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any

from triage import config
from triage.facts import FactStore, build_facts, get_facts
from triage.parsers.logs import load_profiles

_MAX_FILES = 200
_MAX_BYTES = 20 * 1024 * 1024
_lock = RLock()
_packs: dict[str, "PackInfo"] = {}
_active_hash: str | None = None


@dataclass
class PackInfo:
    facts_hash: str
    path: Path
    facts: FactStore
    files: list[str] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)
    is_default: bool = False

    @property
    def hash(self) -> str:
        return self.facts_hash

    @property
    def active(self) -> bool:
        return self.facts_hash == _active_hash

    def to_dict(self) -> dict:
        return {"facts_hash": self.facts_hash, "files": list(self.files),
                "unparsed": list(self.unparsed), "active": self.active,
                "default": self.is_default}


def _default_info() -> PackInfo:
    facts = get_facts()
    return PackInfo(facts.hash, Path(config.DATA_DIR), facts,
                    sorted(p.name for p in Path(config.DATA_DIR).glob("*.md")),
                    _unparsed(Path(config.DATA_DIR)), True)


def _ensure_default() -> PackInfo:
    global _active_hash
    with _lock:
        info = next((p for p in _packs.values() if p.is_default), None)
        if info is None:
            info = _default_info()
            _packs[info.facts_hash] = info
        if _active_hash is None:
            _active_hash = info.facts_hash
        return info


def _unparsed(root: Path) -> list[str]:
    profiles = load_profiles()
    known_table_prefixes = {f"{n:02d}_" for n in range(1, 11)} | {"17_", "18_", "20_"}
    names = []
    for path in sorted(root.glob("*.md")):
        if path.name in profiles or path.name.startswith(tuple(known_table_prefixes)):
            continue
        names.append(path.name)
    return names


def _safe_zip_bytes(raw: bytes) -> Path:
    digest = hashlib.sha256(raw).hexdigest()
    target = Path(config.CACHE_DIR) / "packs" / digest[:12]
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = [i for i in archive.infolist() if not i.is_dir()]
        if len(entries) > _MAX_FILES:
            raise ValueError("zip contains more than 200 files")
        total = 0
        for item in entries:
            name = item.filename.replace("\\", "/")
            path = Path(name)
            if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
                raise ValueError("zip contains an unsafe path")
            if path.suffix.lower() != ".md":
                raise ValueError("zip may contain only .md files")
            # Unix symlink mode, plus the Windows reparse-point bit if present.
            mode = (item.external_attr >> 16) & 0xFFFF
            if (mode and (mode & 0o170000) == 0o120000) or (item.external_attr & 0x40000000):
                raise ValueError("zip contains a symlink")
            total += item.file_size
            if total > _MAX_BYTES:
                raise ValueError("zip is larger than 20 MB uncompressed")
        if not target.exists():
            temp = Path(tempfile.mkdtemp(prefix="pack-", dir=str(target.parent)))
            try:
                for item in entries:
                    destination = temp / item.filename.replace("\\", "/")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(item) as src, destination.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                temp.replace(target)
            except Exception:
                shutil.rmtree(temp, ignore_errors=True)
                raise
    return target


def _source_dir(source: Any) -> tuple[Path, list[str]]:
    if isinstance(source, (bytes, bytearray, memoryview)):
        root = _safe_zip_bytes(bytes(source))
        return root, sorted(p.name for p in root.glob("*.md"))
    path = Path(source)
    if path.suffix.lower() == ".zip":
        try:
            return _safe_zip_bytes(path.read_bytes()), []
        except FileNotFoundError as exc:
            raise ValueError("pack zip does not exist") from exc
    if not path.is_dir():
        raise ValueError("pack source must be a directory or .zip file")
    files = sorted(p.name for p in path.iterdir() if p.is_file())
    return path, files


def load_pack(source) -> PackInfo:
    """Build and register a pack, without changing the active pack."""
    root, files = _source_dir(source)
    try:
        facts = build_facts(root)
        if not files:
            files = sorted(p.name for p in root.glob("*.md"))
        info = PackInfo(facts.hash, root, facts, files, _unparsed(root), False)
    except Exception as exc:
        raise ValueError(f"could not build data pack: {exc}") from exc
    with _lock:
        _ensure_default()
        _packs[info.facts_hash] = info
    return info


def list_packs() -> list[PackInfo]:
    _ensure_default()
    with _lock:
        return list(_packs.values())


def get_pack(facts_hash: str) -> PackInfo | None:
    _ensure_default()
    with _lock:
        return _packs.get(facts_hash)


def current_facts() -> FactStore:
    _ensure_default()
    with _lock:
        return _packs[_active_hash].facts  # type: ignore[index]


def activate(facts_hash: str) -> PackInfo:
    global _active_hash
    info = get_pack(facts_hash)
    if info is None:
        raise KeyError(facts_hash)
    with _lock:
        _active_hash = info.facts_hash
    return info


def _severity(item: dict) -> Any:
    value = item.get("severity")
    return value.get("value") if isinstance(value, dict) else value


def _engine(facts: FactStore) -> dict:
    return facts.engine.to_dict()


def diff_packs(a, b) -> dict:
    """Compare packs or FactStores by incident severity and harmless alerts."""
    left = a.facts if isinstance(a, PackInfo) else a
    right = b.facts if isinstance(b, PackInfo) else b
    ai = {x.get("incident_id"): _severity(x) for x in _engine(left).get("incidents", [])}
    bi = {x.get("incident_id"): _severity(x) for x in _engine(right).get("incidents", [])}
    changes = [{"incident_id": key, "severity_a": ai.get(key), "severity_b": bi.get(key)}
               for key in sorted(set(ai) | set(bi)) if ai.get(key) != bi.get(key)]
    ah = {x.get("alert") for x in _engine(left).get("harmless", [])}
    bh = {x.get("alert") for x in _engine(right).get("harmless", [])}
    return {"incident_severity_changes": changes,
            "harmless_alert_changes": {"added": sorted(bh - ah), "removed": sorted(ah - bh)},
            "counts": {"incidents_a": len(ai), "incidents_b": len(bi),
                       "harmless_a": len(ah), "harmless_b": len(bh)}}
