"""Attack scenarios against the data plane (replay, modification, sniffing) and
helpers for the quantum-plane attacks (intercept-resend, channel degradation),
which are parameters of QuantumChannel / run_bb84."""

from __future__ import annotations

import json

import numpy as np

from .devices import Device
from .gateway import Gateway
from .keymanager import KeyManager, QuantumChannel
from .transport import InProcessBroker


def _frame_body_is_readable(wire: bytes) -> bool:
    """Would a sniffer find a parseable sensor reading in this frame?

    A reading is a JSON object with at least two fields. (Requiring that matters:
    one random pair of final tag bytes in 65,536 is b"{}", which parses as an empty
    object and would otherwise be miscounted as a leak.)
    """
    for start in range(len(wire)):
        if wire[start:start + 1] == b"{":
            try:
                obj = json.loads(wire[start:])
            except ValueError:
                continue
            if isinstance(obj, dict) and len(obj) >= 2:
                return True
    return False


def data_plane_attacks(domain: str, secure: bool, mode: str = "hybrid", n_msgs: int = 40,
                       n_attacks: int = 10, seed: int = 0) -> dict:
    """Send n_msgs, then replay n_attacks captured frames and inject n_attacks
    frames whose body was altered in transit. Return how many each attack got through."""
    rng = np.random.default_rng(seed)
    broker = InProcessBroker()
    gw = Gateway(broker, KeyManager(rng=rng), mode=mode, secure=secure)
    dev = Device(f"{domain}-01", domain, gw, QuantumChannel(), rng=rng)

    for _ in range(n_msgs):
        dev.send_reading()
    captured = list(broker.sniffed)
    leaked = sum(_frame_body_is_readable(w) for _, w in captured)
    base_accepted = gw.counters["accepted"]

    # replay: re-inject old captured frames verbatim
    for topic, wire in captured[:n_attacks]:
        broker.inject(topic, wire)
    replay_accepted = gw.counters["accepted"] - base_accepted

    # modification: flip one bit near the end of each captured frame. On a plaintext
    # frame prefer a bit inside a value (keeps the JSON valid, so the tampering is
    # silent); on an encrypted frame any bit in the ciphertext/tag will do.
    before = gw.counters["accepted"]
    for topic, wire in captured[-n_attacks:]:
        tampered = bytearray(wire)
        pos = len(tampered) - 2
        for i in range(len(tampered) - 2, len(tampered) - 12, -1):
            b = tampered[i]
            if chr(b).isalnum() and chr(b ^ 1).isalnum():
                pos = i
                break
        tampered[pos] ^= 0x01
        broker.inject(topic, bytes(tampered))
    modified_accepted = gw.counters["accepted"] - before

    return {
        "domain": domain, "protection": "AES-256-GCM" if secure else "none (control)",
        "frames_sniffed": len(captured), "readable_by_sniffer": leaked,
        "replays_attempted": n_attacks, "replays_accepted": replay_accepted,
        "modifications_attempted": n_attacks, "modifications_accepted": modified_accepted,
    }
