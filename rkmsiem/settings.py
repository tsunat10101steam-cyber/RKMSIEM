"""런타임 설정: config/settings.yaml + 환경 변수 덮어쓰기.

환경 변수 규칙: RKMSIEM_<섹션>__<키>=값  (예: RKMSIEM_API__PORT=9000, RKMSIEM_SOAR__MODE=live)
비밀 정보(관리자 초기 비밀번호, 수집 API 키 등)는 설정 파일이 아니라 환경 변수로만 받는다.
"""
import copy
import json
import os

from . import schemas, yamlio

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _coerce(v):
    try:
        return json.loads(v)          # 숫자·불리언·리스트도 받기
    except ValueError:
        return v


class Settings:
    def __init__(self, data, config_dir):
        self.data = data
        self.config_dir = config_dir

    def get(self, dotted, default=None):
        cur = self.data
        for p in dotted.split("."):
            if not isinstance(cur, dict) or p not in cur:
                return default
            cur = cur[p]
        return cur

    def path(self, dotted):
        """설정에 적힌 상대 경로를 프로젝트 기준 절대 경로로."""
        p = self.get(dotted)
        return p if os.path.isabs(p) else os.path.join(BASE_DIR, p)

    @staticmethod
    def secret(name, default=None):
        return os.environ.get(name, default)


def load_dotenv(path=None):
    """개발 편의: 프로젝트 루트의 .env 를 읽어 '아직 없는' 환경 변수만 채운다 (.env 는 버전 관리 제외)."""
    path = path or os.path.join(BASE_DIR, ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def load(config_dir=None, overrides=None, environ=None):
    if environ is None:
        load_dotenv()
    environ = os.environ if environ is None else environ
    config_dir = config_dir or environ.get("RKMSIEM_CONFIG_DIR") or os.path.join(BASE_DIR, "config")
    data = yamlio.load_file(os.path.join(config_dir, "settings.yaml")) or {}
    data = copy.deepcopy(data)
    for k, v in environ.items():
        if not k.startswith("RKMSIEM_") or "__" not in k:
            continue
        parts = k[len("RKMSIEM_"):].lower().split("__")
        cur = data
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = _coerce(v)
    for k, v in (overrides or {}).items():
        cur = data
        parts = k.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    schemas.validate(schemas.SETTINGS, data)
    return Settings(data, config_dir)
