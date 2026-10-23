"""Smart-city gateway: establishes keys, receives and authenticates device traffic."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from .crypto import DecryptError, open_sealed, split_header
from .keymanager import EstablishResult, KeyManager, QuantumChannel

TOPIC_FILTER = "city/+/+/data"
WARN_QBER = 0.05  # soft warning tier below the 11% abort threshold


@dataclass
class Session:
    key: bytes
    key_id: int
    method: str
    last_seq: int = -1
    msgs: int = 0


@dataclass
class Gateway:
    broker: object
    km: KeyManager
    mode: str = "hybrid"
    secure: bool = True                  # False = plaintext control (attack demos only)
    sessions: dict[str, Session] = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    accepted: list[dict] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=lambda: {
        "accepted": 0, "rejected_auth": 0, "rejected_replay": 0,
        "rejected_malformed": 0, "rejected_nosession": 0, "key_ok": 0, "key_fail": 0,
    })
    _key_counter: int = 0

    def __post_init__(self) -> None:
        self.broker.subscribe(TOPIC_FILTER, self.on_message)

    # -- events -------------------------------------------------------------
    def log(self, kind: str, **data) -> dict:
        ev = {"t": time.time(), "kind": kind, **data}
        self.events.append(ev)
        return ev

    # -- key establishment ----------------------------------------------------
    def establish(self, device_id: str, channel: QuantumChannel) -> EstablishResult:
        res = self.km.establish(self.mode, channel, device_id)
        if res.ok:
            self._key_counter += 1
            self.sessions[device_id] = Session(res.key_gateway, self._key_counter, res.method)
            self.counters["key_ok"] += 1
        else:
            self.sessions.pop(device_id, None)
            self.counters["key_fail"] += 1
        self.log(
            "key_established" if res.ok else "key_failed",
            device=device_id, method=res.method, requested=self.mode,
            qber=res.qber, secure_key_bits=res.secure_key_bits,
            reason=res.fallback_reason, attack_suspected=res.attack_suspected,
            wire_bytes=res.wire_bytes, latency_ms=round(res.latency_ms, 2),
        )
        if res.attack_suspected:
            self.log("alert", device=device_id,
                     message=f"QBER {res.qber:.1%} above threshold: possible eavesdropper or degraded channel")
        elif res.method == "QKD" and res.qber is not None and res.qber > WARN_QBER:
            # partial eavesdropping stays under the abort threshold but shrinks the key
            self.log("warning", device=device_id,
                     message=f"QBER elevated at {res.qber:.1%} (key shortened to {res.secure_key_bits} bits)")
        return res

    # -- data plane -------------------------------------------------------------
    def on_message(self, topic: str, wire: bytes) -> None:
        try:
            header, hb, rest = split_header(wire)
            device, seq = header["device"], int(header["seq"])
        except (DecryptError, KeyError, TypeError, ValueError):
            self.counters["rejected_malformed"] += 1
            self.log("rejected", reason="malformed")
            return

        if not self.secure:  # plaintext control: no authentication, no replay check
            try:
                reading = json.loads(rest)
            except ValueError:
                self.counters["rejected_malformed"] += 1
                return
            self._accept(device, header, reading)
            return

        sess = self.sessions.get(device)
        if sess is None or header.get("key_id") != sess.key_id:
            self.counters["rejected_nosession"] += 1
            self.log("rejected", device=device, reason="no_session_or_stale_key")
            return
        try:
            body = open_sealed(sess.key, hb, rest)
        except DecryptError:
            self.counters["rejected_auth"] += 1
            self.log("rejected", device=device, reason="authentication_failed", seq=seq)
            return
        if seq <= sess.last_seq:
            self.counters["rejected_replay"] += 1
            self.log("rejected", device=device, reason="replay", seq=seq)
            return
        sess.last_seq = seq
        sess.msgs += 1
        self._accept(device, header, json.loads(body))

    def _accept(self, device: str, header: dict, reading: dict) -> None:
        self.counters["accepted"] += 1
        self.accepted.append({"device": device, "domain": header.get("domain"),
                              "seq": header.get("seq"), "reading": reading})
