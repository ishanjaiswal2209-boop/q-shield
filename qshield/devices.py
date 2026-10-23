"""Simulated IoT devices for the three smart-city domains."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

import numpy as np

from .crypto import plain_pack, seal
from .gateway import Gateway
from .keymanager import QuantumChannel

# messages per key before the device asks for a fresh key; emergency rotates fastest
REKEY_EVERY = {"traffic": 100, "energy": 50, "emergency": 20}
DOMAINS = tuple(REKEY_EVERY)


def make_reading(domain: str, rng: np.random.Generator) -> dict:
    if domain == "traffic":
        return {"junction": int(rng.integers(1, 40)), "vehicles": int(rng.poisson(30)),
                "avg_speed_kmh": round(float(rng.normal(35, 8)), 1),
                "signal": str(rng.choice(["red", "green", "amber"]))}
    if domain == "energy":
        return {"feeder": int(rng.integers(1, 12)), "load_kw": round(float(rng.normal(420, 60)), 1),
                "voltage_v": round(float(rng.normal(230, 3)), 1),
                "frequency_hz": round(float(rng.normal(50.0, 0.05)), 3)}
    if domain == "emergency":
        return {"alert": str(rng.choice(["fire", "medical", "accident", "flood"])),
                "severity": int(rng.integers(1, 6)), "zone": int(rng.integers(1, 20))}
    raise ValueError(domain)


@dataclass
class Device:
    device_id: str
    domain: str
    gateway: Gateway
    channel: QuantumChannel
    rng: np.random.Generator = field(default_factory=np.random.default_rng)
    seq: int = 0
    msgs_since_key: int = 0
    sent: int = 0
    skipped: int = 0   # messages not sent because no key could be established

    def __post_init__(self) -> None:
        self.topic = f"city/{self.domain}/{self.device_id}/data"

    def ensure_key(self) -> bool:
        if self.gateway.secure is False:
            return True
        need = (self.device_id not in self.gateway.sessions
                or self.msgs_since_key >= REKEY_EVERY[self.domain])
        if need:
            res = self.gateway.establish(self.device_id, self.channel)
            self.msgs_since_key = 0
            return res.ok
        return True

    def send_reading(self, reading: dict | None = None) -> bool:
        if not self.ensure_key():
            self.skipped += 1
            return False
        reading = reading or make_reading(self.domain, self.rng)
        body = json.dumps(reading, separators=(",", ":")).encode()
        self.seq += 1
        header = {"device": self.device_id, "domain": self.domain, "seq": self.seq,
                  "ts": round(time.time(), 3)}
        if self.gateway.secure:
            sess = self.gateway.sessions[self.device_id]
            header["key_id"] = sess.key_id
            header["method"] = sess.method
            wire = seal(sess.key, header, body)
        else:
            wire = plain_pack(header, body)
        self.gateway.broker.publish(self.topic, wire)
        self.msgs_since_key += 1
        self.sent += 1
        return True
