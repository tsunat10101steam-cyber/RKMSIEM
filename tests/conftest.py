import os
import shutil
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture
def config_dir(tmp_path):
    """실제 config/ 를 임시 폴더로 복사 — 테스트가 원본 설정을 건드리지 않게."""
    d = tmp_path / "config"
    shutil.copytree(os.path.join(ROOT, "config"), d)
    return str(d)


@pytest.fixture
def db(tmp_path):
    from rkmsiem.db import Database
    d = Database(str(tmp_path / "test.db"))
    d.migrate()
    yield d
    d.close()
