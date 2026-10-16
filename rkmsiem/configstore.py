"""설정 저장소: 스키마 검증 · 버전 관리 · 롤백 · 변경 알림.

- 원천: config/ 아래 YAML 파일. 시작 시 처음 보는 내용(sha)이면 새 버전으로 가져온다.
- 운영 중 변경(API)은 DB 의 새 버전으로 저장되고 즉시 활성화된다. 롤백은 이전 내용을 새 버전으로 다시 활성화.
- 검증에 실패한 설정은 저장되지 않으며, 기존 활성 버전이 그대로 쓰인다.
"""
import copy
import glob
import hashlib
import logging
import os
import threading
import time

from . import schemas, yamlio
from .db import dumps, loads

log = logging.getLogger("rkmsiem.config")

SINGLETONS = ["lists", "detection", "sources", "workflow", "rbac", "approval", "assets", "intel", "mail", "reports", "reputation", "topology", "embeds"]
COLLECTIONS = {"rule": "rules", "playbook": "playbooks"}   # kind → 디렉터리


def _sha(content):
    return hashlib.sha256(dumps(content).encode()).hexdigest()


class ConfigStore:
    def __init__(self, db, config_dir, audit=None):
        self.db, self.config_dir, self.audit = db, config_dir, audit
        self._cache = {}
        self._lock = threading.RLock()
        self._listeners = []
        self._validators = {}          # kind → [fn(content, store)] 의미 검증(참조 무결성 등)

    # ---------- 확장 지점 ----------
    def on_change(self, fn):
        self._listeners.append(fn)

    def add_validator(self, kind, fn):
        self._validators.setdefault(kind, []).append(fn)

    def validate(self, kind, content):
        schemas.validate(kind, content)
        for fn in self._validators.get(kind, []):
            fn(content, self)
        return content

    # ---------- 시작 시 파일 가져오기 ----------
    def bootstrap(self, actor="system"):
        report = {"imported": [], "unchanged": [], "rejected": []}
        files = [(k, "default", os.path.join(self.config_dir, f"{k}.yaml")) for k in SINGLETONS]
        for kind, sub in COLLECTIONS.items():
            for f in sorted(glob.glob(os.path.join(self.config_dir, sub, "*.yaml"))):
                files.append((kind, None, f))
        # 단일 설정 먼저 (규칙·플레이북의 참조 검증이 목록/승인 정책을 필요로 함)
        for kind, name, path in files:
            if not os.path.exists(path):
                continue
            try:
                content = yamlio.load_file(path)
                name = name or content.get("id")
                if not name:
                    raise schemas.SchemaError(["id 가 없습니다"])
                self.validate(kind, content)
                if self.db.scalar("SELECT 1 FROM config_versions WHERE kind=? AND name=? AND sha=?",
                                  (kind, name, _sha(content))):
                    report["unchanged"].append(f"{kind}:{name}")
                    continue
                # 웹 콘솔·API 로 직접 바꾼 설정은 파일(업데이트로 바뀐 기본값)로 덮어쓰지 않음
                cur = self.db.one("SELECT created_by, comment FROM config_versions WHERE kind=? AND name=? AND active=1", (kind, name))
                if cur and not (cur["created_by"] == actor and (cur["comment"] or "").startswith(("file import", "settings.yaml", "기본값", "IDS 수신"))):
                    report.setdefault("kept_user_edit", []).append(f"{kind}:{name}")
                    continue
                self._save(kind, name, content, actor, f"file import: {os.path.relpath(path, self.config_dir)}", notify=False)
                report["imported"].append(f"{kind}:{name}")
            except Exception as e:                     # 잘못된 파일 하나가 전체 기동을 막지 않게
                log.error("config rejected %s: %s", path, e)
                report["rejected"].append({"file": os.path.relpath(path, self.config_dir), "error": str(e)})
        self._cache.clear()
        return report

    # ---------- 조회 ----------
    def get(self, kind, name="default", default=None):
        key = (kind, name)
        with self._lock:
            if key not in self._cache:
                r = self.db.one("SELECT content, version FROM config_versions WHERE kind=? AND name=? AND active=1", key)
                self._cache[key] = (loads(r["content"]), r["version"]) if r else None
            v = self._cache[key]
        return copy.deepcopy(v[0]) if v else default

    def version(self, kind, name="default"):
        self.get(kind, name)
        v = self._cache.get((kind, name))
        return v[1] if v else None

    def all(self, kind):
        rows = self.db.all("SELECT name, content, version FROM config_versions WHERE kind=? AND active=1 ORDER BY name", (kind,))
        return {r["name"]: dict(loads(r["content"]), _version=r["version"]) for r in rows}

    def versions(self, kind, name):
        return self.db.all("SELECT version, sha, active, created_at, created_by, comment FROM config_versions "
                           "WHERE kind=? AND name=? ORDER BY version DESC", (kind, name))

    def content_at(self, kind, name, version):
        r = self.db.one("SELECT content FROM config_versions WHERE kind=? AND name=? AND version=?", (kind, name, version))
        return loads(r["content"]) if r else None

    # ---------- 변경 ----------
    def put(self, kind, name, content, actor, comment=None):
        if kind in COLLECTIONS and content.get("id") != name:
            raise schemas.SchemaError([f"id({content.get('id')}) 와 경로 이름({name})이 다릅니다"])
        self.validate(kind, content)
        return self._save(kind, name, content, actor, comment)

    def set_enabled(self, kind, name, enabled, actor, reason=None):
        cur = self.get(kind, name)
        if cur is None:
            raise KeyError(f"{kind}:{name}")
        cur["enabled"] = bool(enabled)
        return self.put(kind, name, cur, actor, reason or ("enable" if enabled else "disable"))

    def rollback(self, kind, name, version, actor, reason=None):
        old = self.content_at(kind, name, version)
        if old is None:
            raise KeyError(f"{kind}:{name} v{version}")
        self.validate(kind, old)                    # 그 사이 바뀐 참조(목록 등)와도 맞는지 재검증
        return self._save(kind, name, old, actor, reason or f"rollback to v{version}")

    def _save(self, kind, name, content, actor, comment, notify=True):
        with self.db.tx() as c:
            v = (c.execute("SELECT MAX(version) FROM config_versions WHERE kind=? AND name=?", (kind, name)).fetchone()[0] or 0) + 1
            c.execute("UPDATE config_versions SET active=0 WHERE kind=? AND name=?", (kind, name))
            c.execute("INSERT INTO config_versions (kind, name, version, content, sha, active, created_at, created_by, comment) "
                      "VALUES (?,?,?,?,?,1,?,?,?)", (kind, name, v, dumps(content), _sha(content), time.time(), actor, comment))
            if self.audit:
                self.audit.record(actor, "config.change", kind, name, comment, {"version": v, "sha": _sha(content)}, conn=c)
        with self._lock:
            self._cache.pop((kind, name), None)
        if notify:
            for fn in self._listeners:
                try:
                    fn(kind, name)
                except Exception:
                    log.exception("config listener failed")
        return v
