"""Simulated BB84 quantum key distribution with QBER monitoring.

The simulator models the protocol statistically rather than with a quantum
circuit: qubits are (bit, basis) pairs, a measurement in the wrong basis gives
a uniformly random result, and an intercept-resend eavesdropper measures and
re-prepares in her own random basis. This reproduces the textbook behaviour
(QBER ~ 25% under full intercept-resend) and runs fast enough for large sweeps.

Simplifications (documented for the report):
  * Error reconciliation is idealised: Bob adopts Alice's bits and the leaked
    information is charged as f * n * h(QBER) bits (f = 1.1).
  * Privacy amplification uses SHAKE-256; the output length is bounded by the
    asymptotic Shor-Preskill style rate  n * (1 - h(Q) - f*h(Q)) - margin.
  * The classical channel is assumed authenticated.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
import hashlib

import numpy as np

QBER_THRESHOLD = 0.11  # commonly cited BB84 abort threshold
RECONCILIATION_EFFICIENCY = 1.1
SECURITY_MARGIN_BITS = 64


def h2(p: float) -> float:
    """Binary entropy."""
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


@dataclass
class BB84Result:
    n_sent: int
    n_detected: int
    n_sifted: int
    n_sampled: int
    qber: float
    secure_key_bits: int
    key: bytes | None
    aborted: bool
    reason: str  # "ok", "qber_exceeded", "insufficient_sample", "insufficient_key"
    eve_present: bool = False
    classical_bytes: int = 0  # approximate classical-channel traffic (bases + sample)
    info: dict = field(default_factory=dict)


def run_bb84(
    n_qubits: int = 8192,
    channel_error: float = 0.0,
    photon_loss: float = 0.0,
    eve_fraction: float = 0.0,
    sample_fraction: float = 0.15,
    qber_threshold: float = QBER_THRESHOLD,
    key_bytes: int = 32,
    context: bytes = b"",
    rng: np.random.Generator | None = None,
) -> BB84Result:
    """Run one BB84 session and return the result.

    channel_error: probability that the channel flips a transmitted bit.
    photon_loss:   probability a qubit never reaches Bob.
    eve_fraction:  fraction of qubits an intercept-resend attacker measures.
    """
    rng = rng or np.random.default_rng()
    eve_present = eve_fraction > 0

    a_bits = rng.integers(0, 2, n_qubits, dtype=np.uint8)
    a_bases = rng.integers(0, 2, n_qubits, dtype=np.uint8)

    # photon loss: Bob only sees the surviving qubits
    detected = rng.random(n_qubits) >= photon_loss
    a_bits, a_bases = a_bits[detected], a_bases[detected]
    m = len(a_bits)

    state_bits, state_basis = a_bits.copy(), a_bases.copy()

    if eve_present:
        hit = rng.random(m) < eve_fraction
        e_bases = rng.integers(0, 2, m, dtype=np.uint8)
        e_rand = rng.integers(0, 2, m, dtype=np.uint8)
        e_meas = np.where(e_bases == state_basis, state_bits, e_rand)
        state_bits = np.where(hit, e_meas, state_bits).astype(np.uint8)
        state_basis = np.where(hit, e_bases, state_basis).astype(np.uint8)

    if channel_error > 0:
        flips = (rng.random(m) < channel_error).astype(np.uint8)
        state_bits = state_bits ^ flips

    b_bases = rng.integers(0, 2, m, dtype=np.uint8)
    b_rand = rng.integers(0, 2, m, dtype=np.uint8)
    b_bits = np.where(b_bases == state_basis, state_bits, b_rand).astype(np.uint8)

    # sifting: keep positions where Alice's and Bob's bases agree
    keep = a_bases == b_bases
    sa, sb = a_bits[keep], b_bits[keep]
    n_sifted = len(sa)

    k = int(sample_fraction * n_sifted)
    result_kwargs = dict(
        n_sent=n_qubits,
        n_detected=m,
        n_sifted=n_sifted,
        n_sampled=k,
        eve_present=eve_present,
        classical_bytes=(m // 8) * 2 + (k // 8) * 2,
    )
    if k < 20:
        return BB84Result(qber=1.0, secure_key_bits=0, key=None, aborted=True,
                          reason="insufficient_sample", **result_kwargs)

    perm = rng.permutation(n_sifted)
    sample_idx, key_idx = perm[:k], perm[k:]
    qber = float(np.mean(sa[sample_idx] != sb[sample_idx]))

    if qber > qber_threshold:
        return BB84Result(qber=qber, secure_key_bits=0, key=None, aborted=True,
                          reason="qber_exceeded", **result_kwargs)

    key_bits = sa[key_idx]  # after idealised reconciliation Bob holds Alice's bits
    n_key = len(key_bits)
    h = h2(qber)
    secure_bits = int(n_key * (1 - h - RECONCILIATION_EFFICIENCY * h)) - SECURITY_MARGIN_BITS
    if secure_bits < key_bytes * 8:
        return BB84Result(qber=qber, secure_key_bits=max(secure_bits, 0), key=None,
                          aborted=True, reason="insufficient_key", **result_kwargs)

    # privacy amplification: hash the reconciled key down to key_bytes
    packed = np.packbits(key_bits).tobytes()
    key = hashlib.shake_256(packed + context).digest(key_bytes)
    return BB84Result(qber=qber, secure_key_bits=secure_bits, key=key, aborted=False,
                      reason="ok", **result_kwargs)
