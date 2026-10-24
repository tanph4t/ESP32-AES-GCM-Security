import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "main"))
from web_server import create_app, TELEMETRY_TOPIC


class SensorTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(":memory:")
        self.d = self.app.extensions["dashboard"]
        self.client = self.app.test_client()

    def tearDown(self):
        self.d.store.close()

    def ingest(self, **fields):
        payload = dict(aes_enabled=True, relay_on=True, heap_free_bytes=170000, **fields)
        self.d.ingest(TELEMETRY_TOPIC, json.dumps(payload).encode())
        return self.client.get("/api/state").get_json()

    def test_sensor_error_clears_old_values_and_preserves_diagnostics(self):
        self.ingest(ina219_ok=True, sensor_error=0, voltage_v=4.98, current_ma=125, power_w=0.6225)
        state = self.ingest(ina219_ok=False, sensor_error=259, sensor_error_name="ESP_ERR_INVALID_STATE",
            sensor_stage="write_config", bus_raw=-1, shunt_raw=-1,
            voltage_v=None, current_ma=None, power_w=None)
        for field in ("voltage_v", "current_ma", "power_w"):
            self.assertNotIn(field, state["metrics"])
        self.assertEqual(state["device"]["sensor_diagnostics"]["sensor_stage"], "write_config")
        self.assertEqual(state["device"]["sensor_error"], 259)
        self.assertEqual(state["device"]["relay_on"], True)
        row = self.d.store.db.execute("SELECT * FROM measurements ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["outcome"], "sensor_error")
        self.assertIsNone(row["current_ma"])

    def test_recovery_updates_values_and_clears_old_diagnostics(self):
        self.ingest(ina219_ok=False, sensor_error=259, sensor_stage="math_overflow", bus_raw=10003, shunt_raw=200)
        state = self.ingest(ina219_ok=True, sensor_error=0, voltage_v=4.98, current_ma=125, power_w=0.6225)
        self.assertTrue(state["device"]["sensor_ok"])
        self.assertEqual(state["device"]["sensor_diagnostics"], {})
        self.assertEqual(state["metrics"]["current_ma"]["value"], 125)

    def test_invalid_raw_diagnostics_are_ignored(self):
        state = self.ingest(ina219_ok=False, sensor_error=259, sensor_stage=123, bus_raw=True, shunt_raw=999999)
        self.assertEqual(state["device"]["sensor_diagnostics"], {})


if __name__ == "__main__":
    unittest.main()
