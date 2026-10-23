# Q-SHIELD prototype

Adaptive hybrid QKD-PQC framework for secure communication across smart-city IoT networks
(Design Project-1). Software-only: BB84 is simulated, everything else is real cryptography.

```
 Device (traffic / energy / emergency)                     Gateway
   |   key establishment  ------------------------------>   |
   |   1. try BB84 QKD, monitor QBER                        |
   |   2. QBER high / quantum link down / too little key    |
   |        -> fall back to ML-KEM-768                      |
   |   data: AES-256-GCM, header bound as AAD, seq numbers  |
   |   ---- MQTT-style topic  city/<domain>/<device>/data -->|
```

## Run it

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v      # 26 tests
python experiments.py                        # ~6 s, writes results/ (CSV, PNG, summary.md)
python dashboard/app.py                      # http://127.0.0.1:5000
```

## Layout

| File | Role |
|---|---|
| `qshield/bb84.py` | BB84 simulation: bases, sifting, QBER estimate, intercept-resend Eve, channel noise, photon loss, privacy amplification |
| `qshield/pqc.py` | ML-KEM-768 (FIPS 203) and X25519 via `cryptography` |
| `qshield/crypto.py` | HKDF, AES-256-GCM envelope (header authenticated as AAD) |
| `qshield/keymanager.py` | The adaptive policy: `classical` / `qkd` / `hybrid` modes |
| `qshield/transport.py` | In-process MQTT-style broker with sniffer + man-in-the-middle taps; optional paho adapter |
| `qshield/gateway.py` | Session keys, authentication, replay protection, alerts/warnings, counters |
| `qshield/devices.py` | Traffic, Smart Grid/Energy and Emergency device simulators (rekey every 100 / 50 / 20 msgs) |
| `qshield/attacks.py` | Replay, modification and sniffing attacks (with a plaintext control) |
| `experiments.py` | The experiments below |
| `dashboard/app.py` | Flask live dashboard |

## Results (200 trials per point, seed fixed; full tables in `results/summary.md`)

- **Hybrid keeps working when QKD cannot.** QKD-only key establishment succeeds 99.5% / 73.5% / 35% / 12.5% / 0% at 6 / 8 / 9 / 10 / 13% channel error; hybrid is 100% throughout by falling back to ML-KEM (`e2_channel_degradation.png`).
- **Intercept-resend is detected once it is large enough.** QBER follows about 1% + 25% x (fraction intercepted). At 50% interception 94% of sessions are flagged, at 60%+ all are. Mean QBER at full interception: 25.6% (`e3_intercept_resend.png`).
- **Partial eavesdropping is not flagged, it shrinks the key.** At 10-30% interception detection is 0-2%, but secure key length falls from ~2,540 bits to ~500. This is why the gateway also raises a soft warning above 5% QBER.
- **Data-plane attacks.** Over 3 domains x (10 replays + 10 modified frames): 0 accepted under AES-256-GCM + sequence numbers, nothing readable by a sniffer. The plaintext control accepts all of them and leaks every frame (`e4_data_plane_attacks.csv`).
- **Scenario** (Eve active rounds 60-140, traffic quantum link down 200-240, 900 messages): QKD-only delivers 82.2% (160 key failures), classical and hybrid 100% (`e6_timeline.png`).
- **Overhead:** 115 bytes per message on a 67-byte reading (JSON header + nonce + tag); sealing ~6 us, opening ~2 us.

## What is simulated, and what is not (say this in the report)

- **BB84 is a statistical simulation, not Qiskit.** Qiskit could not be installed in the build environment. The model reproduces the textbook behaviour (25% QBER under full intercept-resend; measured mean 3.99% for 4% channel error, sd 0.78%), but it is not a circuit simulation. A Qiskit/Aer backend is a natural extension.
- **Error reconciliation is idealised** (Bob adopts Alice's bits; leakage is charged as 1.1 x n x h(QBER)). Privacy amplification length uses an asymptotic bound with a 64-bit margin, not a finite-key proof. The classical channel is assumed authenticated.
- **Latencies in `e1` are compute time of the simulation**, not physical QKD latency. Do not compare them to real hardware.
- **Detection latency equals the rekey interval.** An attack starting mid-session is only noticed at the next rekey (emergency: 20 messages, energy: 50, traffic: 100). Visible in the dashboard.
- **The transport is in-process.** `MqttBroker` (paho) is written but was **not run** against Mosquitto here, and taps/attacks only work on the in-process broker. Use Wireshark for the real-broker capture demo.
- **The dashboard was exercised through its API and its JavaScript was syntax-checked, but it has not been looked at in a browser.**
- "Classical" means X25519, which a quantum adversary can break (harvest-now-decrypt-later). That is a property of the algorithm, not something the experiments measure.

## Next steps

1. Add a Qiskit/Aer BB84 backend (and optionally run a small circuit on the quantum hardware you have access to) and compare its QBER against this simulator.
2. Run `MqttBroker` against Mosquitto, capture traffic in Wireshark, and add the Docker compose file.
3. Optional: ESP32 / Raspberry Pi nodes as the demo hardware.
