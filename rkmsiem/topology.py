"""네트워크 토폴로지: 기기 감지 + 배치(설정 'topology') + 실시간 상태.

감지는 이 서버가 실제로 아는 것만 쓴다 (스캔하지 않음 — 네트워크에 흔적·부하를 남기지 않게):
  - 서버 자신의 IP (ip -j addr), 기본 게이트웨이 (ip -j route), 같은 망에서 통신한 이웃 (ip -j neigh, ARP 표)
  - 수집한 로그에 나온 출발 IP, IDS 경보의 목적지 IP (최근 N일)
"""
import ipaddress
import json
import shutil
import socket
import subprocess
import time


def node_ips(n):
    """기기의 모든 IP — 대표 IP(ip) + 인터페이스 IP (중복 제거, 순서 유지)."""
    out = [n["ip"]] if n.get("ip") else []
    for i in n.get("interfaces") or []:
        if i.get("ip") and i["ip"] not in out:
            out.append(i["ip"])
    return out


TYPES = ["siem", "server", "router", "switch", "firewall", "ids", "pc", "attacker", "cloud", "other"]


def _ip_json(*args):
    exe = shutil.which("ip")
    if not exe:
        return []
    try:
        out = subprocess.run([exe, "-j", *args], capture_output=True, timeout=3, check=False).stdout
        return json.loads(out or b"[]")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


def _valid(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)


def local_view():
    """서버 자신 · 게이트웨이 · 이웃 (리눅스 ip 명령, 없으면 호스트 이름 해석만)."""
    selfs, gws, neigh = {}, set(), {}
    for link in _ip_json("addr"):
        for a in link.get("addr_info", []):
            if a.get("family") == "inet" and _valid(a.get("local", "")):
                selfs[a["local"]] = {"iface": link.get("ifname"), "prefix": a.get("prefixlen")}
    if not selfs:
        try:
            for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
                if _valid(ip):
                    selfs[ip] = {"iface": None, "prefix": None}
        except OSError:
            pass
    for r in _ip_json("route"):
        if r.get("dst") == "default" and r.get("gateway") and _valid(r["gateway"]):
            gws.add(r["gateway"])
    for n in _ip_json("neigh"):
        ip = n.get("dst", "")
        if ":" not in ip and _valid(ip) and n.get("state") and "FAILED" not in n["state"] and "INCOMPLETE" not in n["state"]:
            neigh[ip] = {"mac": n.get("lladdr"), "iface": n.get("dev"), "state": ",".join(n["state"])}
    return selfs, gws, neigh


def status(p, ips=None):
    """IP 별 실시간 상태: 열린 경보의 최고 심각도·개수, 차단 여부, 최근 이벤트."""
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    out = {}
    rows = p.db.all("SELECT json_extract(a.group_fields, '$.\"source.ip\"') ip, a.severity, a.title, a.incident_id FROM alerts a "
                    "LEFT JOIN incidents i ON i.id = a.incident_id WHERE a.status <> 'closed' AND COALESCE(i.state, '') <> 'false_positive'")
    for r in rows:
        if not r["ip"] or (ips is not None and r["ip"] not in ips):
            continue
        s = out.setdefault(r["ip"], {"open_alerts": 0, "severity": None, "titles": [], "incident_id": None})
        s["open_alerts"] += 1
        if s["severity"] is None or rank[r["severity"]] > rank[s["severity"]]:
            s["severity"], s["incident_id"] = r["severity"], r["incident_id"]
        if r["title"] not in s["titles"] and len(s["titles"]) < 3:
            s["titles"].append(r["title"])
    for r in p.db.all("SELECT ip FROM blocklist"):
        if ips is None or r["ip"] in ips:
            out.setdefault(r["ip"], {"open_alerts": 0, "severity": None, "titles": [], "incident_id": None})["blocked"] = True
    since = time.time() - 86400
    q = "SELECT source_ip ip, COUNT(*) n, MAX(ts) last FROM events WHERE ingested_at >= ? AND source_ip IS NOT NULL GROUP BY source_ip"
    for r in p.db.all(q, (since,)):
        if ips is None or r["ip"] in ips:
            s = out.setdefault(r["ip"], {"open_alerts": 0, "severity": None, "titles": [], "incident_id": None})
            s["events_24h"], s["last_seen"] = r["n"], r["last"]
    return out


def discover(p, days=7):
    """배치할 수 있는 기기 후보 — 이미 아는 사실만 모음 (출처 표시)."""
    selfs, gws, neigh = local_view()
    cands = {}

    def add(ip, kind, **kw):
        c = cands.setdefault(ip, {"ip": ip, "seen_by": [], "suggest": None})
        if kind not in c["seen_by"]:
            c["seen_by"].append(kind)
        c.update({k: v for k, v in kw.items() if v is not None})

    host = socket.gethostname()
    if selfs:                                    # 이 서버의 랜카드가 여러 개여도 기기는 하나 (인터페이스로)
        first = next(iter(selfs))
        add(first, "self", label=f"{host} (RKMSIEM)", iface=selfs[first]["iface"], suggest="siem",
            interfaces=[{"name": v["iface"] or "", "ip": ip, **({"prefix": v["prefix"]} if v.get("prefix") is not None else {})}
                        for ip, v in selfs.items()])
    for ip in gws:
        add(ip, "gateway", label="게이트웨이", suggest="router")
    for ip, info in neigh.items():
        add(ip, "neighbor", mac=info["mac"], iface=info["iface"])
    since = time.time() - days * 86400
    for r in p.db.all("SELECT source_ip ip, COUNT(*) n, SUM(outcome='failure') fails, MAX(ts) last FROM events "
                      "WHERE ingested_at >= ? AND source_ip IS NOT NULL GROUP BY source_ip ORDER BY n DESC LIMIT 200", (since,)):
        if _valid(r["ip"]):
            add(r["ip"], "logs", events=r["n"], failures=r["fails"] or 0, last_seen=r["last"])
    for r in p.db.all("SELECT DISTINCT json_extract(doc, '$.destination.ip') ip FROM events WHERE ingested_at >= ? AND dataset = 'suricata.eve' "
                      "LIMIT 200", (since,)):
        if r["ip"] and _valid(r["ip"]):
            add(r["ip"], "ids")
    self_ips = {i["ip"] for c in cands.values() for i in c.get("interfaces", [])}
    for ip in self_ips - {c["ip"] for c in cands.values() if "self" in c["seen_by"]}:
        cands.pop(ip, None)                      # 서버 자신의 다른 IP 는 따로 후보로 내지 않음
    st = status(p, set(cands))
    for ip, c in cands.items():
        c["status"] = st.get(ip, {})
        if not c["suggest"]:
            sev = c["status"].get("severity")
            c["suggest"] = "attacker" if sev in ("critical", "high") or c["status"].get("blocked") else \
                "server" if "ids" in c["seen_by"] else "pc"
    order = {"self": 0, "gateway": 1, "neighbor": 2, "ids": 3, "logs": 4}
    return sorted(cands.values(), key=lambda c: (min(order[k] for k in c["seen_by"]), -(c.get("events") or 0), c["ip"]))


def validate(content, store):
    from .schemas import SchemaError
    errs, ids, owner, ifnames = [], set(), {}, {}
    for n in content.get("nodes", []):
        name = n.get("label") or n["id"]
        if n["id"] in ids:
            errs.append(f"기기 id 중복: {n['id']}")
        ids.add(n["id"])
        ifnames[n["id"]] = set()
        for i in n.get("interfaces") or []:
            nm = (i.get("name") or "").strip()
            if nm:
                if nm in ifnames[n["id"]]:
                    errs.append(f"{name}: 인터페이스 이름 중복 '{nm}'")
                ifnames[n["id"]].add(nm)
        for ip in node_ips(n):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                errs.append(f"{name}: IP 형식 오류 '{ip}'")
                continue
            if ip in owner and owner[ip] != n["id"]:
                errs.append(f"IP {ip} 가 두 기기에 있음 ({owner[ip]} · {n['id']}) — 같은 기기라면 인터페이스로 합치세요")
            owner.setdefault(ip, n["id"])
    seen = set()
    for l in content.get("links", []):
        if l["from"] not in ids or l["to"] not in ids:
            errs.append(f"연결 {l['id']}: 없는 기기를 가리킴")
            continue
        if l["from"] == l["to"]:
            errs.append(f"연결 {l['id']}: 자기 자신과 연결")
        for end, nid in (("from_if", l["from"]), ("to_if", l["to"])):
            if l.get(end) and l[end] not in ifnames.get(nid, set()):
                errs.append(f"연결 {l['id']}: {nid} 에 '{l[end]}' 인터페이스가 없음")
        key = tuple(sorted((l["from"], l["to"])))
        if key in seen and not (l.get("from_if") or l.get("to_if")):
            errs.append(f"같은 두 기기 사이에 연결이 두 번 있음 ({l['from']} ↔ {l['to']}) — 두 번째부터는 양쪽 인터페이스를 지정하세요")
        seen.add(key)
    if errs:
        raise SchemaError(errs)


def layout_ips(layout):
    return {ip for n in (layout or {}).get("nodes", []) for ip in node_ips(n)}

