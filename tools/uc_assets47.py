#!/usr/bin/env python3
"""Phase 47 Undercover asset pipeline (Python mirror of web/src/app/uc-*.ts).

Used for CI/validation when Node is unavailable. Browser implementation remains
the TypeScript modules under web/src/app/.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

FetchFn = Callable[[str], Tuple[int, bytes]]


class ManifestError(Exception):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


@dataclass
class AssetEntry:
    id: str
    path: str
    url: str
    size: int
    sha256: str
    content_type: str
    category: str
    required: bool
    license: str


@dataclass
class AssetManifest:
    manifest_version: int
    game: str
    source_mode: str
    base_url: str
    production_authorized: bool
    note: str
    assets: List[AssetEntry]


def parse_manifest(raw: dict) -> AssetManifest:
    if not isinstance(raw, dict):
        raise ManifestError("not an object", "MANIFEST_INVALID")
    if not isinstance(raw.get("manifestVersion"), int) or raw["manifestVersion"] < 1:
        raise ManifestError("manifestVersion", "MANIFEST_INVALID")
    if raw.get("game") != "NFS_UNDERCOVER_PC":
        raise ManifestError("unexpected game", "MANIFEST_GAME")
    src = raw.get("source") or {}
    assets = []
    for a in raw.get("assets") or []:
        sha = str(a.get("sha256") or "").lower()
        if len(sha) != 64:
            raise ManifestError(f"bad hash {a.get('id')}", "MANIFEST_HASH")
        assets.append(AssetEntry(
            id=a["id"], path=a["path"].lstrip("/"), url=a["url"], size=int(a["size"]),
            sha256=sha, content_type=a.get("contentType") or "application/octet-stream",
            category=a.get("category") or "fixture", required=bool(a.get("required")),
            license=a.get("license") or "synthetic-fixture",
        ))
    return AssetManifest(
        manifest_version=raw["manifestVersion"],
        game="NFS_UNDERCOVER_PC",
        source_mode=src.get("mode") or "unavailable",
        base_url=(src.get("baseUrl") or "/").rstrip("/") + "/",
        production_authorized=bool(src.get("productionAssetsAuthorized")),
        note=src.get("note") or "",
        assets=assets,
    )


def assert_download_allowed(m: AssetManifest, e: AssetEntry) -> None:
    if e.license == "copyrighted-unavailable":
        raise ManifestError(f"{e.id} unavailable", "SOURCE_UNAUTHORIZED")
    if e.license == "copyrighted-authorized" and not (
        m.source_mode == "authorized" and m.production_authorized
    ):
        raise ManifestError(f"{e.id} not authorized", "SOURCE_UNAUTHORIZED")


def resolve_url(m: AssetManifest, e: AssetEntry) -> str:
    if e.url.startswith("http://") or e.url.startswith("https://") or e.url.startswith("/"):
        return e.url
    return m.base_url + e.url.lstrip("./")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class MemoryStore:
    data: Dict[str, bytes] = field(default_factory=dict)

    def get(self, key: str) -> Optional[bytes]:
        return self.data.get(key)

    def put(self, key: str, value: bytes) -> None:
        self.data[key] = bytes(value)

    def delete(self, key: str) -> None:
        self.data.pop(key, None)

    def list_keys(self) -> List[str]:
        return list(self.data.keys())

    def usage(self) -> int:
        return sum(len(v) for v in self.data.values())


META_KEY = "uc-asset-meta-v1"


def data_key(aid: str, sha: str) -> str:
    return f"uc-asset:{aid}:{sha.lower()}"


@dataclass
class Progress:
    phase: str = "idle"
    have_bytes: int = 0
    total_bytes: int = 0
    required_ready: int = 0
    required_total: int = 0
    error: Optional[str] = None
    current_id: Optional[str] = None


class DownloadManager:
    def __init__(
        self,
        store: MemoryStore,
        fetch: FetchFn,
        quota: Optional[int] = None,
        max_retries: int = 2,
    ):
        self.store = store
        self.fetch = fetch
        self.quota = quota
        self.max_retries = max_retries
        self.meta: Dict[str, dict] = {}
        self.progress = Progress()
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def _load_meta(self) -> None:
        raw = self.store.get(META_KEY)
        self.meta = {}
        if not raw:
            return
        try:
            for m in json.loads(raw.decode("utf-8")):
                self.meta[m["id"]] = m
        except Exception:
            self.meta = {}

    def _save_meta(self) -> None:
        self.store.put(META_KEY, json.dumps(list(self.meta.values())).encode("utf-8"))

    def has_valid(self, e: AssetEntry) -> bool:
        m = self.meta.get(e.id)
        if not m or m.get("sha256") != e.sha256 or m.get("size") != e.size:
            return False
        b = self.store.get(data_key(e.id, e.sha256))
        return b is not None and len(b) == e.size

    def write(self, e: AssetEntry, data: bytes, manifest_version: int) -> None:
        if len(data) != e.size:
            raise ValueError("size mismatch")
        self.store.put(data_key(e.id, e.sha256), data)
        self.meta[e.id] = {
            "id": e.id, "path": e.path, "sha256": e.sha256,
            "size": e.size, "manifestVersion": manifest_version,
        }
        self._save_meta()

    def read(self, e: AssetEntry) -> Optional[bytes]:
        return self.store.get(data_key(e.id, e.sha256))

    def prune(self, keep: List[AssetEntry]) -> None:
        keep_map = {a.id: a.sha256 for a in keep}
        for aid, m in list(self.meta.items()):
            want = keep_map.get(aid)
            if not want or want != m["sha256"]:
                self.store.delete(data_key(aid, m["sha256"]))
                del self.meta[aid]
        self._save_meta()

    def ensure_required(self, manifest: AssetManifest) -> Progress:
        self._cancelled = False
        self._load_meta()
        if manifest.source_mode == "unavailable":
            self.progress = Progress(
                phase="source_unavailable", error=manifest.note or "unavailable")
            return self.progress
        req = [a for a in manifest.assets if a.required]
        self.progress = Progress(phase="checking", required_total=len(req))
        self.prune(manifest.assets)
        need = [a for a in req if not self.has_valid(a)]
        have = sum(a.size for a in req if self.has_valid(a))
        total = sum(a.size for a in req)
        self.progress.have_bytes = have
        self.progress.total_bytes = total
        self.progress.required_ready = len(req) - len(need)
        if not need:
            self.progress.phase = "ready_to_initialize"
            self.progress.required_ready = len(req)
            return self.progress
        if self.quota is not None and self.store.usage() + sum(a.size for a in need) > self.quota:
            self.progress.phase = "insufficient_storage"
            self.progress.error = "quota"
            return self.progress
        self.progress.phase = "downloading"
        try:
            for a in need:
                if self._cancelled:
                    raise RuntimeError("cancelled")
                assert_download_allowed(manifest, a)
                self.progress.current_id = a.id
                self._download_one(manifest, a)
                self.progress.have_bytes += a.size
                self.progress.required_ready += 1
            ready = sum(1 for a in req if self.has_valid(a))
            self.progress.required_ready = ready
            self.progress.phase = (
                "ready_to_initialize" if ready == len(req) else "download_failed"
            )
            if self.progress.phase == "download_failed":
                self.progress.error = "required assets incomplete"
        except ManifestError as e:
            self.progress.phase = "source_unavailable" if e.code == "SOURCE_UNAUTHORIZED" else "download_failed"
            self.progress.error = str(e)
        except Exception as e:
            self.progress.phase = "download_failed"
            self.progress.error = str(e)
        return self.progress

    def _download_one(self, manifest: AssetManifest, entry: AssetEntry) -> None:
        url = resolve_url(manifest, entry)
        last = None
        for _ in range(self.max_retries + 1):
            if self._cancelled:
                raise RuntimeError("cancelled")
            try:
                status, body = self.fetch(url)
                if status != 200:
                    raise RuntimeError(f"HTTP {status}")
                if len(body) != entry.size:
                    raise RuntimeError(f"partial download {len(body)}/{entry.size}")
                self.progress.phase = "verifying"
                digest = sha256_hex(body)
                if digest != entry.sha256:
                    raise RuntimeError(f"hash mismatch for {entry.id}: got {digest}")
                self.write(entry, body, manifest.manifest_version)
                return
            except Exception as e:
                last = e
                if "hash mismatch" in str(e):
                    raise
        raise last  # type: ignore


def clear_only_commands() -> List[str]:
    return [
        "BeginScene",
        "Clear(flags=7,color=0,z=1,stencil=0)",
        "EndScene",
        "Present",
    ]


def open_virtual(manifest: AssetManifest, mgr: DownloadManager, virtual: str) -> dict:
    rel = virtual.replace("\\", "/")
    if rel.startswith("/uc/"):
        rel = rel[4:]
    elif rel.startswith("/"):
        rel = rel[1:]
    entry = next((a for a in manifest.assets if a.path.lower() == rel.lower()), None)
    if not entry:
        return {"ok": False, "code": "NOT_FOUND"}
    if entry.license == "copyrighted-unavailable":
        return {"ok": False, "code": "UNSUPPORTED"}
    data = mgr.read(entry)
    if data is None:
        return {"ok": False, "code": "NOT_CACHED"}
    return {"ok": True, "bytes": data, "contentType": entry.content_type}


def load_shipped_manifest(root: str) -> AssetManifest:
    path = os.path.join(root, "web", "src", "static", "uc-asset-manifest.json")
    with open(path, encoding="utf-8") as fh:
        return parse_manifest(json.load(fh))


def fixture_bytes(root: str, rel: str) -> bytes:
    path = os.path.join(root, "web", "src", "static", "uc-fixtures", *rel.split("/"))
    with open(path, "rb") as fh:
        return fh.read()
