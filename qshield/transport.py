"""MQTT-style transport.

InProcessBroker  : tested here; topic filters (+, #), a passive sniffer log and
                   active man-in-the-middle taps (drop / modify / duplicate).
MqttBroker       : thin paho-mqtt adapter with the same publish/subscribe API for
                   running against a real Mosquitto broker. NOT exercised in the
                   build sandbox (paho and Mosquitto were not installable there);
                   taps are not supported on it - use Wireshark for capture.
"""

from __future__ import annotations

from typing import Callable

Callback = Callable[[str, bytes], None]
Tap = Callable[[str, bytes], list[bytes]]


def topic_matches(filt: str, topic: str) -> bool:
    f, t = filt.split("/"), topic.split("/")
    for i, part in enumerate(f):
        if part == "#":
            return True
        if i >= len(t):
            return False
        if part != "+" and part != t[i]:
            return False
    return len(f) == len(t)


class InProcessBroker:
    def __init__(self) -> None:
        self._subs: list[tuple[str, Callback]] = []
        self.taps: list[Tap] = []
        self.sniffed: list[tuple[str, bytes]] = []   # what a passive observer sees on the wire

    def subscribe(self, topic_filter: str, callback: Callback) -> None:
        self._subs.append((topic_filter, callback))

    def add_tap(self, tap: Tap) -> None:
        self.taps.append(tap)

    def remove_tap(self, tap: Tap) -> None:
        if tap in self.taps:
            self.taps.remove(tap)

    def _deliver(self, topic: str, payload: bytes) -> None:
        for filt, cb in list(self._subs):
            if topic_matches(filt, topic):
                cb(topic, payload)

    def publish(self, topic: str, payload: bytes) -> None:
        self.sniffed.append((topic, payload))
        payloads = [payload]
        for tap in list(self.taps):
            nxt: list[bytes] = []
            for p in payloads:
                nxt.extend(tap(topic, p))
            payloads = nxt
        for p in payloads:
            self._deliver(topic, p)

    def inject(self, topic: str, payload: bytes) -> None:
        """Attacker injects a frame directly (bypasses taps)."""
        self.sniffed.append((topic, payload))
        self._deliver(topic, payload)


class MqttBroker:
    """paho-mqtt adapter (requires `pip install paho-mqtt` and a running Mosquitto)."""

    def __init__(self, host: str = "localhost", port: int = 1883) -> None:
        import paho.mqtt.client as mqtt  # imported lazily so the rest works without paho

        self._client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self._callbacks: list[tuple[str, Callback]] = []
        self._client.on_message = self._on_message
        self._client.connect(host, port)
        self._client.loop_start()

    def _on_message(self, _client, _userdata, msg) -> None:
        for filt, cb in self._callbacks:
            if topic_matches(filt, msg.topic):
                cb(msg.topic, bytes(msg.payload))

    def subscribe(self, topic_filter: str, callback: Callback) -> None:
        self._callbacks.append((topic_filter, callback))
        self._client.subscribe(topic_filter)

    def publish(self, topic: str, payload: bytes) -> None:
        self._client.publish(topic, payload)

    def close(self) -> None:
        self._client.loop_stop()
        self._client.disconnect()
