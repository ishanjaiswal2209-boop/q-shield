"""Adaptive key establishment: QKD (BB84), ML-KEM fallback, classical ECDH baseline.

Modes
  classical : X25519 ECDH -> HKDF                       (baseline, not quantum-safe)
  qkd       : BB84 only; fails if the channel is noisy/attacked/down
  hybrid    : BB84 first; if QBER is high, the quantum link is down, or too
              little secure key results, fall back to ML-KEM-768 (Q-SHIELD policy)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import numpy as np

from .bb84 import QBER_THRESHOLD, BB84Result, run_bb84
from .crypto import hkdf
from .pqc import (
    MLKEM768_CT_BYTES,
    MLKEM768_PK_BYTES,
    MLKEMResponder,
    mlkem_encapsulate,
    x25519_exchange,
)

MODES = ("classical", "qkd", "hybrid")


@dataclass
class QuantumChannel:
    """Conditions on the (simulated) quantum link between a device and the gateway."""
    error: float = 0.01          # bit-flip probability
    loss: float = 0.10           # photon loss
    eve_fraction: float = 0.0    # fraction of qubits an eavesdropper intercepts
    link_up: bool = True         # False = no quantum link available


@dataclass
class EstablishResult:
    ok: bool
    mode_requested: str
    method: str                       # "QKD", "ML-KEM", "X25519" or "none"
    key_device: bytes | None = None
    key_gateway: bytes | None = None
    qber: float | None = None
    secure_key_bits: int = 0
    fallback_reason: str | None = None   # why QKD was not used (hybrid) / why it failed (qkd)
    attack_suspected: bool = False
    wire_bytes: int = 0                  # classical-channel bytes for the handshake
    qubits_sent: int = 0
    latency_ms: float = 0.0              # compute time in the simulation
    info: dict = field(default_factory=dict)


class KeyManager:
    def __init__(self, qber_threshold: float = QBER_THRESHOLD, n_qubits: int = 8192,
                 rng: np.random.Generator | None = None):
        self.qber_threshold = qber_threshold
        self.n_qubits = n_qubits
        self.rng = rng or np.random.default_rng()

    # -- individual methods -------------------------------------------------
    def _qkd(self, channel: QuantumChannel, context: bytes) -> BB84Result | None:
        if not channel.link_up:
            return None
        return run_bb84(
            n_qubits=self.n_qubits,
            channel_error=channel.error,
            photon_loss=channel.loss,
            eve_fraction=channel.eve_fraction,
            qber_threshold=self.qber_threshold,
            context=context,
            rng=self.rng,
        )

    @staticmethod
    def _mlkem(context: bytes) -> tuple[bytes, bytes, int]:
        gw = MLKEMResponder()
        ss_dev, ct = mlkem_encapsulate(gw.public_bytes)
        ss_gw = gw.decapsulate(ct)
        k_dev = hkdf(ss_dev, b"qshield-mlkem|" + context)
        k_gw = hkdf(ss_gw, b"qshield-mlkem|" + context)
        return k_dev, k_gw, MLKEM768_PK_BYTES + MLKEM768_CT_BYTES

    # -- policy ---------------------------------------------------------------
    def establish(self, mode: str, channel: QuantumChannel, device_id: str) -> EstablishResult:
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        ctx = device_id.encode()
        t0 = time.perf_counter()

        if mode == "classical":
            s_dev, s_gw, wire = x25519_exchange()
            res = EstablishResult(
                ok=True, mode_requested=mode, method="X25519",
                key_device=hkdf(s_dev, b"qshield-x25519|" + ctx),
                key_gateway=hkdf(s_gw, b"qshield-x25519|" + ctx),
                wire_bytes=wire,
            )
        else:
            q = self._qkd(channel, ctx)
            if q is not None and not q.aborted:
                res = EstablishResult(
                    ok=True, mode_requested=mode, method="QKD",
                    key_device=q.key, key_gateway=q.key,
                    qber=q.qber, secure_key_bits=q.secure_key_bits,
                    wire_bytes=q.classical_bytes, qubits_sent=q.n_sent,
                )
            else:
                reason = "qkd_unavailable" if q is None else q.reason
                suspected = q is not None and q.reason == "qber_exceeded"
                if mode == "qkd":
                    res = EstablishResult(
                        ok=False, mode_requested=mode, method="none",
                        qber=None if q is None else q.qber,
                        fallback_reason=reason, attack_suspected=suspected,
                        wire_bytes=0 if q is None else q.classical_bytes,
                        qubits_sent=0 if q is None else q.n_sent,
                    )
                else:  # hybrid -> ML-KEM fallback
                    k_dev, k_gw, wire = self._mlkem(ctx)
                    res = EstablishResult(
                        ok=True, mode_requested=mode, method="ML-KEM",
                        key_device=k_dev, key_gateway=k_gw,
                        qber=None if q is None else q.qber,
                        fallback_reason=reason, attack_suspected=suspected,
                        wire_bytes=wire + (0 if q is None else q.classical_bytes),
                        qubits_sent=0 if q is None else q.n_sent,
                    )
        res.latency_ms = (time.perf_counter() - t0) * 1000
        return res
