"""플러그인 레지스트리 — 수집기 · 파서 · 플레이북 액션.

새 수집기/파서/액션은 데코레이터로 등록하고 settings.yaml 의 plugins 에 모듈 경로를 적으면
핵심 파이프라인 코드를 고치지 않고 추가된다.
"""
import importlib

COLLECTORS, PARSERS, ACTIONS = {}, {}, {}


def collector(name):
    def deco(cls):
        cls.type_name = name
        COLLECTORS[name] = cls
        return cls
    return deco


def parser(name):
    def deco(fn):
        PARSERS[name] = fn
        return fn
    return deco


def action(name, destructive=False, description=""):
    def deco(fn):
        fn.action_name, fn.destructive, fn.description = name, destructive, description
        ACTIONS[name] = fn
        return fn
    return deco


def load_builtin():
    """내장 플러그인 모듈을 import 해 데코레이터 등록을 실행한다."""
    for m in ("parsers", "collectors.file_tail", "collectors.http", "collectors.syslog_udp", "collectors.journald", "collectors.http_pull", "soar.actions"):
        importlib.import_module(f"{__package__}.{m}")


def load_external(modules):
    for m in modules or []:
        importlib.import_module(m)
