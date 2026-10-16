"""운영 지표: 카운터 · 게이지 · 히스토그램 (Prometheus 텍스트 형식 출력)."""
import threading
import time

_BUCKETS = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, float("inf"))   # ms


def _key(labels):
    return tuple(sorted((labels or {}).items()))


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.counters, self.gauges, self.hists, self.help = {}, {}, {}, {}
        self.started = time.time()

    def inc(self, name, value=1, **labels):
        with self._lock:
            d = self.counters.setdefault(name, {})
            d[_key(labels)] = d.get(_key(labels), 0) + value

    def set(self, name, value, **labels):
        with self._lock:
            self.gauges.setdefault(name, {})[_key(labels)] = value

    def observe(self, name, ms, **labels):
        with self._lock:
            h = self.hists.setdefault(name, {}).setdefault(_key(labels), {"b": [0] * len(_BUCKETS), "sum": 0.0, "n": 0})
            for i, b in enumerate(_BUCKETS):
                if ms <= b:
                    h["b"][i] += 1
            h["sum"] += ms
            h["n"] += 1

    def get(self, name, **labels):
        with self._lock:
            for store in (self.counters, self.gauges):
                if name in store:
                    return store[name].get(_key(labels), 0)
        return 0

    def total(self, name):
        with self._lock:
            return sum(self.counters.get(name, {}).values())

    def hist_summary(self, name):
        with self._lock:
            out = {}
            for k, h in self.hists.get(name, {}).items():
                p95 = None
                if h["n"]:
                    target = h["n"] * .95
                    for i, c in enumerate(h["b"]):
                        if c >= target:
                            p95 = _BUCKETS[i]
                            break
                out[",".join(f"{a}={b}" for a, b in k) or "all"] = {"count": h["n"], "avg_ms": round(h["sum"] / h["n"], 2) if h["n"] else None,
                                                                   "p95_le_ms": p95}
            return out

    def snapshot(self):
        with self._lock:
            fmt = lambda store: {n: {",".join(f"{a}={b}" for a, b in k) or "all": v for k, v in d.items()} for n, d in store.items()}
            return {"uptime_sec": round(time.time() - self.started, 1), "counters": fmt(self.counters), "gauges": fmt(self.gauges)}

    def prometheus(self):
        lines = []
        q = lambda v: str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        lab = lambda k, extra=None: "{" + ",".join(f'{a}="{q(b)}"' for a, b in (list(k) + (extra or []))) + "}" if (k or extra) else ""
        with self._lock:
            for n, d in self.counters.items():
                lines.append(f"# TYPE rkmsiem_{n} counter")
                lines += [f"rkmsiem_{n}{lab(k)} {v}" for k, v in d.items()]
            for n, d in self.gauges.items():
                lines.append(f"# TYPE rkmsiem_{n} gauge")
                lines += [f"rkmsiem_{n}{lab(k)} {v}" for k, v in d.items()]
            for n, d in self.hists.items():
                lines.append(f"# TYPE rkmsiem_{n} histogram")
                for k, h in d.items():
                    for i, b in enumerate(_BUCKETS):
                        lines.append(f"rkmsiem_{n}_bucket{lab(k, [('le', '+Inf' if b == float('inf') else b)])} {h['b'][i]}")
                    lines.append(f"rkmsiem_{n}_sum{lab(k)} {h['sum']}")
                    lines.append(f"rkmsiem_{n}_count{lab(k)} {h['n']}")
        return "\n".join(lines) + "\n"
