"""E2E must include Python encryption and match only applied command ACKs."""
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "main"))
import web_server as web


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.app = web.create_app(":memory:")
        self.d = self.app.extensions["dashboard"]
        self.client = self.app.test_client()

    def tearDown(self):
        self.d.store.close()

    def ready(self, enabled):
        d = self.d
        d.connected = True
        d.aes_enabled = d.firmware_aes = enabled
        d.firmware_mode_ts = d.last_state_ts = time.time()
        d.mode_challenge = "AB" * 16
        d.last_state = False

    def test_full_send_ack_includes_encryption_in_both_modes(self):
        real_encrypt = web.encrypt_payload
        for enabled in (True, False):
            with self.subTest(aes=enabled):
                self.ready(enabled)
                clock = [1_000_000_000]
                def encrypt(command, **kwargs):
                    payload = real_encrypt(command, **kwargs)
                    clock[0] += 10_000_000  # Model a 10ms encryption/packaging cost.
                    return payload
                def publish(topic, payload, **kwargs):
                    command_id = self.d.latest_packet["command_id"]
                    clock[0] += 20_000_000  # Model network and device processing.
                    ack = dict(command_id=command_id, command="ON", status="UNLOCKED",
                               phase="applied", execution_us=2500, decrypt_us=100)
                    self.d.ingest(web.STATUS_TOPIC, json.dumps(ack).encode())
                    return SimpleNamespace(rc=web.mqtt.MQTT_ERR_SUCCESS)
                self.d.client = SimpleNamespace(publish=publish)
                with patch.object(web.time, "perf_counter_ns", side_effect=lambda: clock[0]), patch.object(web, "encrypt_payload", side_effect=encrypt):
                    packet = self.d.send("control", "ON")
                    state = self.d.snapshot()
                self.assertEqual(state["end_to_end"]["status"], "measured")
                self.assertEqual(state["end_to_end"]["value_ms"], 30 if enabled else 20)
                self.assertEqual(state["latency"]["value_ms"], 2.5)
                row = self.d.store.db.execute("SELECT * FROM measurements WHERE command_id=?", (packet["command_id"],)).fetchone()
                self.assertEqual(row["rtt_ms"], 20)
                self.assertEqual(row["e2e_ms"], 30 if enabled else 20)
        stats = self.client.get("/api/performance").get_json()
        metric = next(r for r in stats["stats"] if r["field"] == "e2e_ms")
        self.assertEqual(metric["n"], 2)
        self.assertEqual(metric["mean"], 25)
        for mode, expected in (("on", 30), ("off", 20)):
            stats = self.client.get("/api/performance?mode=" + mode).get_json()
            self.assertEqual(next(r for r in stats["stats"] if r["field"] == "e2e_ms")["mean"], expected)
        self.assertIn("e2e_ms", self.client.get("/api/performance.csv").get_data(as_text=True))

    def pending(self):
        self.ready(False)
        self.d.client = SimpleNamespace(publish=lambda *args, **kwargs: SimpleNamespace(rc=0))
        return self.d.send("control", "ON")

    def test_unknown_wrong_duplicate_ack_and_timeout(self):
        packet = self.pending()
        ack = dict(command_id=packet["command_id"], command="ON", phase="applied", status="UNLOCKED")
        now_ns = time.perf_counter_ns()
        self.d._receive_command_ack(dict(ack, command_id="unknown"), now_ns, time.time())
        self.d._receive_command_ack(dict(ack, command="OFF"), now_ns, time.time())
        self.d._receive_command_ack(dict(ack, status="LOCKED"), now_ns, time.time())
        self.assertEqual(self.d.end_to_end["status"], "pending")
        self.d._receive_command_ack(ack, now_ns, time.time())
        self.assertEqual(self.d.end_to_end["status"], "measured")
        self.assertEqual(self.d.latency["status"], "missing")  # E2E does not require execution_us.
        measured = self.d.end_to_end["value_ms"]
        self.d._receive_command_ack(ack, now_ns + 100_000_000, time.time())
        self.assertEqual(self.d.end_to_end["value_ms"], measured)
        packet = self.pending()
        self.d._expire_commands(self.d.pending_commands[packet["command_id"]]["start_ns"] + 8_000_000_000)
        self.assertEqual(self.d.end_to_end["status"], "timeout")
        self.assertIsNone(self.d.end_to_end["value_ms"])
        row = self.d.store.db.execute("SELECT e2e_ms FROM measurements WHERE command_id=?", (packet["command_id"],)).fetchone()
        self.assertIsNone(row[0])

    def test_rejected_publish_failed_and_test_packets(self):
        packet = self.pending()
        self.d._receive_command_ack(dict(command_id=packet["command_id"], command="ON", phase="rejected", status="BUSY"), time.perf_counter_ns(), time.time())
        self.assertEqual(self.d.end_to_end["status"], "rejected")
        self.assertIsNone(self.d.end_to_end["value_ms"])
        self.d.client = SimpleNamespace(publish=lambda *a, **k: SimpleNamespace(rc=1))
        with self.assertRaises(ConnectionError):
            self.d.send("control", "ON")
        self.assertEqual(self.d.end_to_end["status"], "failed")
        self.assertIsNone(self.d.end_to_end["value_ms"])
        self.d.client = SimpleNamespace(publish=lambda *a, **k: SimpleNamespace(rc=0))
        self.d.send("tamper", "ON")
        self.assertEqual(self.d.end_to_end["status"], "test")
        self.assertIsNone(self.d.end_to_end["value_ms"])

    def test_migrate_old_rtt_without_relabeling_it_as_e2e(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.sqlite3"
            store = web.Store(path)
            store.record_measurement(dict(ts=time.time(), mode="on", source="command", outcome="applied", command_id="old", rtt_ms=200))
            store.db.execute("ALTER TABLE measurements DROP COLUMN e2e_ms")
            store.db.commit()
            store.close()
            for _ in range(2):
                store = web.Store(path)
                row = store.db.execute("SELECT rtt_ms,e2e_ms FROM measurements").fetchone()
                self.assertEqual(row[0], 200)
                self.assertIsNone(row[1])
                store.close()


if __name__ == "__main__":
    unittest.main()
