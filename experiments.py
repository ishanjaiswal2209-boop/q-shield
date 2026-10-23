"""Run all Q-SHIELD experiments and write CSVs, plots and a summary to ./results.

    python experiments.py            # full run (about a minute)
    python experiments.py --quick    # fewer trials
"""

from __future__ import annotations

import argparse
import os
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from qshield.attacks import data_plane_attacks
from qshield.bb84 import QBER_THRESHOLD
from qshield.crypto import open_sealed, seal, split_header
from qshield.devices import DOMAINS, Device
from qshield.gateway import Gateway
from qshield.keymanager import KeyManager, QuantumChannel
from qshield.transport import InProcessBroker

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
SEED = 2026


def exp_key_establishment(trials: int) -> pd.DataFrame:
    """E1: clean channel, compare the three modes."""
    rows = []
    for mode in ("classical", "qkd", "hybrid"):
        km = KeyManager(rng=np.random.default_rng(SEED))
        res = [km.establish(mode, QuantumChannel(error=0.01, loss=0.10), f"dev{i}") for i in range(trials)]
        ok = [r for r in res if r.ok]
        rows.append({
            "mode": mode,
            "success_rate": len(ok) / trials,
            "method_used": ",".join(sorted({r.method for r in ok})),
            "latency_ms_mean": np.mean([r.latency_ms for r in ok]),
            "latency_ms_p95": np.percentile([r.latency_ms for r in ok], 95),
            "classical_wire_bytes": int(np.mean([r.wire_bytes for r in ok])),
            "qubits_sent": int(np.mean([r.qubits_sent for r in ok])),
            "mean_qber": np.nanmean([r.qber if r.qber is not None else np.nan for r in ok]) if mode != "classical" else np.nan,
            "mean_secure_key_bits": np.mean([r.secure_key_bits for r in ok]) if mode != "classical" else np.nan,
        })
    return pd.DataFrame(rows)


def exp_channel_degradation(trials: int) -> pd.DataFrame:
    """E2: sweep channel bit-error rate; compare QKD-only vs hybrid availability."""
    rows = []
    for err in np.round(np.arange(0.0, 0.151, 0.01), 3):
        for mode in ("qkd", "hybrid"):
            km = KeyManager(rng=np.random.default_rng(SEED))
            res = [km.establish(mode, QuantumChannel(error=float(err), loss=0.10), "dev") for _ in range(trials)]
            qbers = [r.qber for r in res if r.qber is not None]
            rows.append({
                "channel_error": err, "mode": mode,
                "key_success_rate": np.mean([r.ok for r in res]),
                "qkd_used_rate": np.mean([r.method == "QKD" for r in res]),
                "mlkem_fallback_rate": np.mean([r.method == "ML-KEM" for r in res]),
                "mean_qber": np.mean(qbers) if qbers else np.nan,
                "mean_secure_key_bits": np.mean([r.secure_key_bits for r in res if r.method == "QKD"] or [0]),
            })
    return pd.DataFrame(rows)


def exp_intercept_resend(trials: int) -> pd.DataFrame:
    """E3: intercept-resend eavesdropper intercepting a fraction of the qubits."""
    rows = []
    for frac in np.round(np.arange(0.0, 1.01, 0.1), 2):
        km = KeyManager(rng=np.random.default_rng(SEED))
        res = [km.establish("hybrid", QuantumChannel(error=0.01, loss=0.10, eve_fraction=float(frac)), "dev")
               for _ in range(trials)]
        qkd = [r for r in res if r.method == "QKD"]
        rows.append({
            "eve_fraction": frac,
            "mean_qber": np.mean([r.qber for r in res if r.qber is not None]),
            "detected_rate": np.mean([r.attack_suspected for r in res]),
            "qkd_used_rate": np.mean([r.method == "QKD" for r in res]),
            "mlkem_fallback_rate": np.mean([r.method == "ML-KEM" for r in res]),
            "mean_secure_key_bits_when_accepted": np.mean([r.secure_key_bits for r in qkd]) if qkd else 0,
        })
    return pd.DataFrame(rows)


def exp_data_plane() -> pd.DataFrame:
    """E4: replay / modification / sniffing, with and without protection."""
    rows = []
    for secure in (True, False):
        for d in DOMAINS:
            rows.append(data_plane_attacks(d, secure=secure, seed=SEED))
    return pd.DataFrame(rows)


def exp_overhead(n: int = 2000) -> pd.DataFrame:
    """E5: per-message size overhead and crypto cost of AES-256-GCM sealing."""
    key = os.urandom(32)
    body = b'{"junction":12,"vehicles":31,"avg_speed_kmh":36.4,"signal":"green"}'
    header = {"device": "traffic-01", "domain": "traffic", "seq": 1, "ts": 0.0, "key_id": 1, "method": "QKD"}
    t0 = time.perf_counter()
    for _ in range(n):
        wire = seal(key, header, body)
    seal_us = (time.perf_counter() - t0) / n * 1e6
    h, hb, rest = split_header(wire)
    t0 = time.perf_counter()
    for _ in range(n):
        open_sealed(key, hb, rest)
    open_us = (time.perf_counter() - t0) / n * 1e6
    return pd.DataFrame([{
        "plaintext_bytes": len(body), "wire_bytes": len(wire), "overhead_bytes": len(wire) - len(body),
        "seal_us": round(seal_us, 1), "open_us": round(open_us, 1),
    }])


def scenario(mode: str, rounds: int = 300):
    """E6: three domains, one message per device per round. Eve attacks rounds
    60-140 on all links; the traffic device's quantum link is down in rounds 200-240."""
    rng = np.random.default_rng(SEED)
    broker = InProcessBroker()
    gw = Gateway(broker, KeyManager(rng=rng), mode=mode)
    chans = {d: QuantumChannel(error=0.01, loss=0.10) for d in DOMAINS}
    devs = {d: Device(f"{d}-01", d, gw, chans[d], rng=rng) for d in DOMAINS}
    timeline = []
    for r in range(rounds):
        eve = 60 <= r < 140
        for d in DOMAINS:
            chans[d].eve_fraction = 1.0 if eve else 0.0
        chans["traffic"].link_up = not (200 <= r < 240)
        before = len(gw.events)
        for d in DOMAINS:
            devs[d].send_reading()
        for ev in gw.events[before:]:
            if ev["kind"] in ("key_established", "key_failed"):
                timeline.append({"round": r, "device": ev["device"], "kind": ev["kind"],
                                 "method": ev["method"], "qber": ev["qber"], "reason": ev["reason"]})
    sent = sum(d.sent for d in devs.values())
    skipped = sum(d.skipped for d in devs.values())
    return pd.DataFrame(timeline), {
        "mode": mode, "messages_attempted": sent + skipped, "delivered": gw.counters["accepted"],
        "delivery_rate": gw.counters["accepted"] / (sent + skipped),
        "key_failures": gw.counters["key_fail"],
    }


def plot_all(e2, e3, tl_hybrid, rounds=300):
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})

    # E2: availability and key length under channel degradation
    fig, ax = plt.subplots(1, 2, figsize=(11, 4))
    for mode, style in (("qkd", "o-"), ("hybrid", "s--")):
        d = e2[e2["mode"] == mode]
        ax[0].plot(d["channel_error"] * 100, d["key_success_rate"] * 100, style,
                   label={"qkd": "QKD only", "hybrid": "Hybrid (QKD + ML-KEM)"}[mode])
    d = e2[e2["mode"] == "hybrid"]
    ax[0].axvline(QBER_THRESHOLD * 100, color="red", lw=0.8, ls=":")
    ax[0].set(xlabel="Channel bit-error rate (%)", ylabel="Key establishment success (%)", ylim=(-3, 105),
              title="Availability under channel degradation")
    ax[0].legend(loc="lower left", fontsize=8)
    ax[1].plot(d["channel_error"] * 100, d["mean_secure_key_bits"], "o-", color="tab:green")
    ax[1].set(xlabel="Channel bit-error rate (%)", ylabel="Secure key bits (runs that yielded a key)",
              title="Secure key yield per BB84 run (8192 qubits)")
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "e2_channel_degradation.png"), dpi=150); plt.close(fig)

    # E3: intercept-resend
    fig, ax = plt.subplots(1, 2, figsize=(11, 4))
    ax[0].plot(e3["eve_fraction"] * 100, e3["mean_qber"] * 100, "o-", label="Mean QBER")
    ax[0].plot(e3["eve_fraction"] * 100, e3["eve_fraction"] * 25 + 1, "k:", lw=1, label="Approx. theory: 1% noise + 25% x fraction")
    ax[0].axhline(QBER_THRESHOLD * 100, color="red", lw=0.8, ls=":", label="Abort threshold (11%)")
    ax[0].set(xlabel="Qubits intercepted by Eve (%)", ylabel="QBER (%)", title="QBER vs intercept-resend fraction")
    ax[0].legend(fontsize=8)
    l1, = ax[1].plot(e3["eve_fraction"] * 100, e3["detected_rate"] * 100, "s-", color="tab:red",
                     label="Attack detected -> ML-KEM fallback (left)")
    ax[1].set(xlabel="Qubits intercepted by Eve (%)", ylabel="% of sessions", ylim=(-3, 105),
              title="Detection vs key shrinkage")
    ax2 = ax[1].twinx()
    ax2.spines["top"].set_visible(False)
    l2, = ax2.plot(e3["eve_fraction"] * 100, e3["mean_secure_key_bits_when_accepted"], "^--", color="tab:green",
                   label="Secure key bits when QKD accepted (right)")
    ax2.set_ylabel("Secure key bits")
    ax[1].legend(handles=[l1, l2], fontsize=8, loc="center left")
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "e3_intercept_resend.png"), dpi=150); plt.close(fig)

    # E6: timeline
    fig, ax = plt.subplots(figsize=(11, 3.8))
    colors = {"QKD": "tab:green", "ML-KEM": "tab:orange", "none": "tab:red"}
    for m, c in colors.items():
        d = tl_hybrid[tl_hybrid["method"] == m]
        if d.empty:
            continue
        q = (d["qber"] * 100).fillna(-3)   # -3 lane = no QKD attempted (quantum link down)
        ax.scatter(d["round"], q, s=16, color=c, label=f"key via {m}")
    ax.axhline(QBER_THRESHOLD * 100, color="red", lw=0.8, ls=":")
    ax.axhline(-1.5, color="gray", lw=0.5)
    ax.text(292, -3, "no QKD attempt", fontsize=8, va="center", ha="right", color="gray")
    ax.axvspan(60, 140, color="red", alpha=0.07, label="Eavesdropper active")
    ax.axvspan(200, 240, color="gray", alpha=0.12, label="Traffic quantum link down")
    ax.set(xlabel="Round (1 message per device per round)", ylabel="QBER at rekey (%)",
           ylim=(-5, 35), title="Hybrid mode adapting to attack and link outage")
    ax.legend(fontsize=8, ncol=3, loc="upper right")
    fig.tight_layout(); fig.savefig(os.path.join(OUT, "e6_timeline.png"), dpi=150); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    trials = 30 if args.quick else 200
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()

    e1 = exp_key_establishment(trials); e1.to_csv(f"{OUT}/e1_key_establishment.csv", index=False)
    e2 = exp_channel_degradation(trials); e2.to_csv(f"{OUT}/e2_channel_degradation.csv", index=False)
    e3 = exp_intercept_resend(trials); e3.to_csv(f"{OUT}/e3_intercept_resend.csv", index=False)
    e4 = exp_data_plane(); e4.to_csv(f"{OUT}/e4_data_plane_attacks.csv", index=False)
    e5 = exp_overhead(); e5.to_csv(f"{OUT}/e5_overhead.csv", index=False)
    tls, sums = {}, []
    for mode in ("classical", "qkd", "hybrid"):
        tls[mode], s = scenario(mode)
        sums.append(s)
    tls["hybrid"].to_csv(f"{OUT}/e6_timeline_hybrid.csv", index=False)
    e6 = pd.DataFrame(sums); e6.to_csv(f"{OUT}/e6_scenario_summary.csv", index=False)
    plot_all(e2, e3, tls["hybrid"])

    with open(f"{OUT}/summary.md", "w") as f:
        f.write(f"# Q-SHIELD experiment results\n\nTrials per point: {trials}; seed {SEED}; "
                f"BB84 = 8192 qubits, 10% photon loss, 15% of sifted bits sampled for QBER, abort above {QBER_THRESHOLD:.0%}.\n\n")
        for title, df in (("E1 Key establishment (clean channel)", e1),
                          ("E2 Channel degradation", e2),
                          ("E3 Intercept-resend eavesdropper", e3),
                          ("E4 Data-plane attacks", e4),
                          ("E5 Message overhead", e5),
                          ("E6 Scenario: attack rounds 60-140, traffic quantum link down 200-240", e6)):
            f.write(f"## {title}\n\n{df.round(3).to_markdown(index=False)}\n\n")
    print(f"done in {time.time() - t0:.1f}s -> {OUT}")


if __name__ == "__main__":
    main()
