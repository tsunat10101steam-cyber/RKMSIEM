"""YAML 입출력 (ruamel.yaml 순수 파이썬 safe 모드)."""
import io

from ruamel.yaml import YAML


def _yaml():
    y = YAML(typ="safe", pure=True)
    y.default_flow_style = False
    y.allow_unicode = True
    return y


def loads(text):
    return _yaml().load(text)


def load_file(path):
    with open(path, encoding="utf-8") as f:
        return loads(f.read())


def dumps(obj):
    buf = io.StringIO()
    _yaml().dump(obj, buf)
    return buf.getvalue()
