"""Run with:  python -m unittest discover -s tests -v     (or: pytest)"""

import os
import sys
import unittest

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from qshield.attacks import _frame_body_is_readable, data_plane_attacks  # noqa: E402
from qshield.bb84 import run_bb84  # noqa: E402
from qshield.crypto import DecryptError, hkdf, open_sealed, seal, split_header  # noqa: E402
from qshield.devices import Device  # noqa: E402
from qshield.gateway import Gateway  # noqa: E402
from qshield.keymanager import KeyManager, QuantumChannel  # noqa: E402
from qshield.pqc import MLKEMResponder, mlkem_encapsulate, x25519_exchange  # noqa: E402
from qshield.transport import InProcessBroker, topic_matches  # noqa: E402


def rng(seed=1):
    return np.random.default_rng(seed)


class TestBB84(unittest.TestCase):
    def test_clean_channel_yields_key(self):
        r = run_bb84(channel_error=0.0, rng=rng())
        self.assertFalse(r.aborted)
        self.assertEqual(len(r.key), 32)
        self.assertLess(r.qber, 0.01)

    def test_qber_tracks_channel_error(self):
        # one run's QBER estimate has sd ~0.8% (614 sampled bits), so average 40 runs
        q = [run_bb84(channel_error=0.04, rng=rng(s)).qber for s in range(40)]
        self.assertAlmostEqual(float(np.mean(q)), 0.04, delta=0.004)

    def test_full_intercept_resend_gives_about_25_percent(self):
        runs = [run_bb84(eve_fraction=1.0, rng=rng(s)) for s in range(40)]
        self.assertTrue(all(r.aborted and r.reason == "qber_exceeded" for r in runs))
        self.assertAlmostEqual(float(np.mean([r.qber for r in runs])), 0.25, delta=0.01)

    def test_high_noise_aborts(self):
        self.assertTrue(run_bb84(channel_error=0.15, rng=rng()).aborted)

    def test_photon_loss_does_not_raise_qber(self):
        r = run_bb84(photon_loss=0.5, rng=rng())
        self.assertLess(r.qber, 0.02)

    def test_keys_differ_between_runs(self):
        a = run_bb84(rng=rng(1)).key
        b = run_bb84(rng=rng(2)).key
        self.assertNotEqual(a, b)


class TestPQC(unittest.TestCase):
    def test_mlkem_roundtrip(self):
        gw = MLKEMResponder()
        ss_dev, ct = mlkem_encapsulate(gw.public_bytes)
        self.assertEqual(ss_dev, gw.decapsulate(ct))
        self.assertEqual(len(ss_dev), 32)

    def test_x25519_agree(self):
        a, b, _ = x25519_exchange()
        self.assertEqual(a, b)


class TestKeyManager(unittest.TestCase):
    def setUp(self):
        self.km = KeyManager(rng=rng())

    def test_all_modes_agree_on_clean_channel(self):
        for mode in ("classical", "qkd", "hybrid"):
            r = self.km.establish(mode, QuantumChannel(), "d")
            self.assertTrue(r.ok, mode)
            self.assertEqual(r.key_device, r.key_gateway)

    def test_hybrid_falls_back_under_attack(self):
        r = self.km.establish("hybrid", QuantumChannel(eve_fraction=1.0), "d")
        self.assertTrue(r.ok)
        self.assertEqual(r.method, "ML-KEM")
        self.assertTrue(r.attack_suspected)
        self.assertEqual(r.key_device, r.key_gateway)

    def test_qkd_only_fails_under_attack_and_outage(self):
        self.assertFalse(self.km.establish("qkd", QuantumChannel(eve_fraction=1.0), "d").ok)
        self.assertFalse(self.km.establish("qkd", QuantumChannel(link_up=False), "d").ok)

    def test_hybrid_falls_back_when_link_down(self):
        r = self.km.establish("hybrid", QuantumChannel(link_up=False), "d")
        self.assertEqual((r.method, r.fallback_reason, r.attack_suspected), ("ML-KEM", "qkd_unavailable", False))

    def test_keys_are_fresh(self):
        a = self.km.establish("hybrid", QuantumChannel(link_up=False), "d").key_device
        b = self.km.establish("hybrid", QuantumChannel(link_up=False), "d").key_device
        self.assertNotEqual(a, b)

    def test_unknown_mode(self):
        with self.assertRaises(ValueError):
            self.km.establish("bogus", QuantumChannel(), "d")


class TestCrypto(unittest.TestCase):
    def test_roundtrip_and_tamper(self):
        key = hkdf(b"secret", b"ctx")
        h = {"device": "x", "seq": 1}
        wire = seal(key, h, b"hello")
        _, hb, rest = split_header(wire)
        self.assertEqual(open_sealed(key, hb, rest), b"hello")
        bad = bytearray(rest)
        bad[-1] ^= 1
        with self.assertRaises(DecryptError):
            open_sealed(key, hb, bytes(bad))
        with self.assertRaises(DecryptError):  # header is authenticated as AAD
            open_sealed(key, hb.replace(b'"seq":1', b'"seq":9'), rest)
        with self.assertRaises(DecryptError):  # wrong key
            open_sealed(hkdf(b"other", b"ctx"), hb, rest)


class TestTransport(unittest.TestCase):
    def test_topic_matching(self):
        self.assertTrue(topic_matches("city/+/+/data", "city/traffic/t-1/data"))
        self.assertTrue(topic_matches("city/#", "city/traffic/t-1/data"))
        self.assertFalse(topic_matches("city/+/data", "city/traffic/t-1/data"))
        self.assertFalse(topic_matches("city/energy/+/data", "city/traffic/t-1/data"))

    def test_tap_can_drop(self):
        b = InProcessBroker()
        got = []
        b.subscribe("a/#", lambda t, p: got.append(p))
        b.add_tap(lambda t, p: [])
        b.publish("a/b", b"x")
        self.assertEqual(got, [])


class TestGatewayEndToEnd(unittest.TestCase):
    def make(self, mode="hybrid", secure=True, channel=None):
        r = rng()
        broker = InProcessBroker()
        gw = Gateway(broker, KeyManager(rng=r), mode=mode, secure=secure)
        dev = Device("traffic-01", "traffic", gw, channel or QuantumChannel(), rng=r)
        return broker, gw, dev

    def test_delivery(self):
        _, gw, dev = self.make()
        for _ in range(10):
            self.assertTrue(dev.send_reading())
        self.assertEqual(gw.counters["accepted"], 10)

    def test_rekeys_on_schedule(self):
        _, gw, dev = self.make()
        for _ in range(250):
            dev.send_reading()
        self.assertEqual(gw.counters["key_ok"], 3)  # 100 msgs per key for traffic
        self.assertEqual(gw.counters["accepted"], 250)

    def test_qkd_only_under_attack_drops_traffic(self):
        _, gw, dev = self.make(mode="qkd", channel=QuantumChannel(eve_fraction=1.0))
        self.assertFalse(dev.send_reading())
        self.assertEqual(gw.counters["accepted"], 0)

    def test_hybrid_under_attack_still_delivers(self):
        _, gw, dev = self.make(channel=QuantumChannel(eve_fraction=1.0))
        for _ in range(5):
            dev.send_reading()
        self.assertEqual(gw.counters["accepted"], 5)
        self.assertEqual(gw.sessions["traffic-01"].method, "ML-KEM")
        self.assertTrue(any(e["kind"] == "alert" for e in gw.events))

    def test_replay_and_modification_rejected(self):
        for d in ("traffic", "energy", "emergency"):
            r = data_plane_attacks(d, secure=True)
            self.assertEqual(r["replays_accepted"], 0)
            self.assertEqual(r["modifications_accepted"], 0)
            self.assertEqual(r["readable_by_sniffer"], 0)

    def test_sniffer_check_ignores_random_brace_pair(self):
        # regression: ciphertext whose last two bytes are b"{}" is not a leaked reading
        self.assertFalse(_frame_body_is_readable(b"\x01\x02\x9f\xaa{}"))
        self.assertFalse(_frame_body_is_readable(bytes(range(40)) + b"{}"))
        self.assertTrue(_frame_body_is_readable(b'\x00\x10hdr{"a":1,"b":2}'))

    def test_plaintext_control_is_vulnerable(self):
        r = data_plane_attacks("energy", secure=False)
        self.assertEqual(r["replays_accepted"], r["replays_attempted"])
        self.assertEqual(r["modifications_accepted"], r["modifications_attempted"])
        self.assertEqual(r["readable_by_sniffer"], r["frames_sniffed"])

    def test_old_key_frames_rejected_after_rekey(self):
        broker, gw, dev = self.make()
        dev.send_reading()
        old = list(broker.sniffed)
        gw.establish(dev.device_id, dev.channel)  # new key_id
        before = gw.counters["accepted"]
        for topic, wire in old:
            broker.inject(topic, wire)
        self.assertEqual(gw.counters["accepted"], before)
        self.assertEqual(gw.counters["rejected_nosession"], 1)

    def test_garbage_frame_is_rejected_not_crashing(self):
        broker, gw, _ = self.make()
        broker.inject("city/traffic/x/data", b"\x00\x05nope")
        broker.inject("city/traffic/x/data", b"")
        self.assertEqual(gw.counters["rejected_malformed"], 2)


if __name__ == "__main__":
    unittest.main()
