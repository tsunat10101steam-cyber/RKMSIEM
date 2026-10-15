"""Syslog UDP 수집기 (RFC3164/5424). 큐가 가득 차면 드롭하고 계수한다(UDP 는 역압 불가)."""
import socket

from ..pipeline import make_record
from ..plugins import collector
from . import Collector


@collector("syslog_udp")
class SyslogUdpCollector(Collector):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.sock = None
        self.bound = None

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.opt.get("host", "127.0.0.1"), int(self.opt.get("port", 5514))))
        self.sock.settimeout(.5)
        self.bound = self.sock.getsockname()
        try:
            while not self._stop.is_set():
                try:
                    data, addr = self.sock.recvfrom(65535)
                except socket.timeout:
                    continue
                text = data.decode("utf-8", "replace")
                rec = make_record(self.id, text)
                if not self.pipeline.submit(rec, block=False):
                    self.metrics.inc("syslog_dropped_total", source=self.id)
                    continue
                self.mark()
        finally:
            self.sock.close()

    def status(self):
        s = super().status()
        s["listen"] = f"{self.bound[0]}:{self.bound[1]}" if self.bound else None
        return s
