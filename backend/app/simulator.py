"""
Synthetic traffic generator.

Since this project is meant to run entirely locally with no real production
traffic to point it at, this module generates realistic-looking Apache
combined log lines — mostly benign, with periodic attack bursts — so the
dashboard has something real to detect and show. It's not a mock of the
detection pipeline: generated lines are fed through the exact same
parser + AttackDetector used everywhere else.
"""
from __future__ import annotations

import asyncio
import random
import time
from datetime import datetime, timezone
from typing import Callable, Optional

BENIGN_PATHS = ["/", "/index.html", "/about", "/products", "/contact", "/api/health", "/blog/post-1"]
ATTACK_PAYLOADS = {
    "sqli": ["/login?user=admin' OR 1=1--", "/search?q=' UNION SELECT * FROM users--"],
    "xss": ["/comment?msg=<script>alert(1)</script>", "/profile?name=<img src=x onerror=alert(1)>"],
    "traversal": ["/download?file=../../../../etc/passwd", "/view?page=..%2f..%2f..%2fboot.ini"],
}
USER_AGENTS = ["Mozilla/5.0", "curl/8.4.0", "python-requests/2.31", "sqlmap/1.7"]


def _random_ip(pool: list[str]) -> str:
    return random.choice(pool)


def make_line(ip: str, path: str, status: int, method: str = "GET") -> str:
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    ua = random.choice(USER_AGENTS)
    size = random.randint(200, 5000)
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def generate_batch(normal_ips: list[str], attacker_ips: list[str], burst: Optional[str] = None) -> list[str]:
    """One 'tick' of traffic: a handful of benign requests, plus an optional attack burst."""
    lines = []
    for _ in range(random.randint(3, 8)):
        ip = _random_ip(normal_ips)
        lines.append(make_line(ip, random.choice(BENIGN_PATHS), 200))

    if burst == "bruteforce":
        ip = _random_ip(attacker_ips)
        for _ in range(random.randint(6, 12)):
            lines.append(make_line(ip, "/login", 401, method="POST"))
    elif burst == "sqli":
        ip = _random_ip(attacker_ips)
        lines.append(make_line(ip, random.choice(ATTACK_PAYLOADS["sqli"]), 200))
    elif burst == "xss":
        ip = _random_ip(attacker_ips)
        lines.append(make_line(ip, random.choice(ATTACK_PAYLOADS["xss"]), 200))
    elif burst == "traversal":
        ip = _random_ip(attacker_ips)
        lines.append(make_line(ip, random.choice(ATTACK_PAYLOADS["traversal"]), 403))
    elif burst == "volume":
        ip = _random_ip(attacker_ips)
        for _ in range(random.randint(25, 40)):
            lines.append(make_line(ip, random.choice(BENIGN_PATHS), 200))

    return lines


class Simulator:
    """Runs as an asyncio background task, ticking once per interval."""

    def __init__(self, on_batch: Callable[[list[str]], "asyncio.Future | None"], interval: float = 3.0):
        self.on_batch = on_batch
        self.interval = interval
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self.normal_ips = [f"198.51.100.{i}" for i in range(1, 12)]
        self.attacker_ips = [f"203.0.113.{i}" for i in range(1, 6)]

    @property
    def running(self) -> bool:
        return self._running

    async def _loop(self):
        bursts = [None, None, None, "bruteforce", "sqli", "xss", "traversal", "volume"]
        try:
            while self._running:
                burst = random.choice(bursts)
                lines = generate_batch(self.normal_ips, self.attacker_ips, burst=burst)
                result = self.on_batch(lines)
                if asyncio.iscoroutine(result):
                    await result
                await asyncio.sleep(self.interval)
        finally:
            self._running = False

    def start(self):
        if self._task is None or self._task.done():
            self._running = True
            self._task = asyncio.create_task(self._loop())

    def stop(self):
        self._running = False
