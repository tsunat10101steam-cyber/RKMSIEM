"""실제 대응 어댑터 (Linux): nftables 차단 · 계정 잠금 헬퍼 · 로컬 계정 조회.

원칙
- 셸을 거치지 않고 인자 배열로 실행 (명령 주입 불가) · 입력은 IP/계정 이름 형식 검증 후에만 사용
- 방화벽은 서비스에 CAP_NET_ADMIN 만 부여해 nft 를 직접 실행 (sudo 불필요)
- 계정 잠금은 root 소유 헬퍼 스크립트 1개만 sudo 로 허용 (sudoers 에 그 경로만 등록) — 헬퍼가 다시 검증
- 차단 목록의 원본은 DB(blocklist) — 재부팅/재시작 시 DB 의 유효 항목을 nft 에 다시 적용(reconcile)
"""
import ipaddress
import json
import logging
import re
import shutil
import subprocess
import time

log = logging.getLogger("rkmsiem.response")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")


class ResponseError(Exception):
    def __init__(self, msg, transient=False):
        super().__init__(msg)
        self.transient = transient


class Runner:
    """서브프로세스 실행기 (테스트에서는 가짜로 교체)."""

    def run(self, argv, timeout=15):
        try:
            p = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        except FileNotFoundError as e:
            raise ResponseError(f"명령 없음: {argv[0]}") from e
        except subprocess.TimeoutExpired as e:
            raise ResponseError(f"시간 초과: {' '.join(argv[:3])}", transient=True) from e
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


class NftFirewall:
    def __init__(self, cfg, runner):
        self.cfg, self.runner = cfg, runner
        self.nft = cfg.get("nft") or shutil.which("nft") or "/usr/sbin/nft"
        self.table = cfg.get("table", "rkmsiem")
        self.sets = {4: cfg.get("set_v4", "blocklist4"), 6: cfg.get("set_v6", "blocklist6")}
        self.prefix = ["sudo", "-n"] if cfg.get("sudo") else []

    def _argv(self, *args):
        return self.prefix + [self.nft] + list(args)

    def block(self, ip, timeout_sec=None):
        a = ipaddress.ip_address(ip)
        elem = f"{a}" + (f" timeout {int(timeout_sec)}s" if timeout_sec else "")
        argv = self._argv("add", "element", "inet", self.table, self.sets[a.version], "{ " + elem + " }")
        rc, out, err = self.runner.run(argv)
        if rc != 0:
            raise ResponseError(f"nft 차단 실패(rc={rc}): {err.strip()[:300]}", transient="Resource busy" in err)
        return {"backend": "nftables", "argv": argv, "rc": rc}

    def unblock(self, ip):
        a = ipaddress.ip_address(ip)
        argv = self._argv("delete", "element", "inet", self.table, self.sets[a.version], "{ " + str(a) + " }")
        rc, out, err = self.runner.run(argv)
        if rc != 0 and "No such file" not in err and "does not exist" not in err:
            raise ResponseError(f"nft 해제 실패(rc={rc}): {err.strip()[:300]}")
        return {"backend": "nftables", "argv": argv, "rc": rc, "was_present": rc == 0}

    def check(self):
        """doctor 용: 테이블·세트가 있고 권한이 있는지."""
        rc, out, err = self.runner.run(self._argv("list", "set", "inet", self.table, self.sets[4]))
        return rc == 0, (err or out).strip()[:300]


class AccountHelper:
    def __init__(self, cfg, runner):
        self.cfg, self.runner = cfg, runner
        self.helper = cfg.get("helper", "/usr/local/lib/rkmsiem/rkmsiem-account")
        self.prefix = ["sudo", "-n"] if cfg.get("sudo", True) else []

    def _run(self, op, user):
        if not USER_RE.match(user or ""):
            raise ResponseError(f"잘못된 계정 이름: {user!r}")
        argv = self.prefix + [self.helper, op, user] + (["--kill-sessions"] if op == "lock" and self.cfg.get("kill_sessions") else [])
        rc, out, err = self.runner.run(argv, timeout=20)
        try:
            res = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
        except ValueError:
            res = {"raw": out[-300:]}
        if rc != 0:
            raise ResponseError(f"계정 {op} 실패(rc={rc}): {(res.get('error') or err or out).strip()[:300]}")
        return dict(res, backend="helper", argv=argv, rc=rc)

    def lock(self, user):
        return self._run("lock", user)

    def unlock(self, user):
        return self._run("unlock", user)

    def check(self):
        rc, out, err = self.runner.run(self.prefix + [self.helper, "check"], timeout=10)
        return rc == 0, (out or err).strip()[:300]


def local_account(name, privileged_groups):
    """/etc/passwd · /etc/group 에서 계정 조회 (Linux). 다른 OS 에서는 None."""
    try:
        import grp
        import pwd
    except ImportError:
        return None
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        return {"exists": False}
    groups = sorted({g.gr_name for g in grp.getgrall() if name in g.gr_mem} | {grp.getgrgid(pw.pw_gid).gr_name})
    nologin = pw.pw_shell.endswith(("nologin", "false"))
    return {"exists": True, "uid": pw.pw_uid, "groups": groups, "shell": pw.pw_shell, "home": pw.pw_dir, "login_disabled_shell": nologin,
            "privileged": pw.pw_uid == 0 or bool(set(groups) & set(privileged_groups))}


class Response:
    """설정(settings.response)에 따라 어댑터를 구성. backend: none 이면 플랫폼 내부 기록만."""

    def __init__(self, settings, runner=None):
        cfg = settings.get("response") or {}
        self.runner = runner or Runner()
        fw = cfg.get("firewall") or {}
        ac = cfg.get("accounts") or {}
        self.firewall = NftFirewall(fw, self.runner) if fw.get("backend") == "nftables" else None
        self.accounts = AccountHelper(ac, self.runner) if ac.get("backend") == "helper" else None
        self.assets_cfg = cfg.get("assets") or {}
        self.intel = None                      # Platform 이 IntelIndex 를 채움
        from .abuseipdb import AbuseIPDB
        self.abuseipdb = AbuseIPDB.from_settings(settings)   # 키(RKMSIEM_ABUSEIPDB_KEY)가 없으면 비활성
        self.mailer = None                     # Platform 이 Mailer 를 넣어 줌
        self.report_incident = None            # Platform 이 사건 보고서(PDF) 생성 함수를 넣어 줌

    def reconcile(self, db):
        """DB 차단 목록의 유효 항목을 방화벽에 다시 적용 (재부팅 후 nft 세트가 비어 있을 때)."""
        if not self.firewall:
            return {"skipped": "firewall backend none"}
        now, ok, fail = time.time(), 0, 0
        db.execute("DELETE FROM blocklist WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        for r in db.all("SELECT ip, expires_at FROM blocklist"):
            try:
                self.firewall.block(r["ip"], int(r["expires_at"] - now) if r["expires_at"] else None)
                ok += 1
            except ResponseError as e:
                fail += 1
                log.error("reconcile %s failed: %s", r["ip"], e)
        return {"reapplied": ok, "failed": fail}
