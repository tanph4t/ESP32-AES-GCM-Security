"""Validate device execution timing independently of MQTT round-trip delay."""
import math
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'main'))
from web_server import Dashboard, Store, create_app


class ExecutionTimingTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(':memory:')
        self.dashboard = self.app.extensions['dashboard']
        self.client = self.app.test_client()

    def tearDown(self):
        self.dashboard.store.close()

    def pending(self, command_id='0123456789abcdef', encrypted=True):
        d = self.dashboard
        d.store.record_measurement(dict(ts=time.time(), mode='on' if encrypted else 'off',
            source='command', outcome='pending', command_id=command_id, command='ON'))
        d.pending_commands[command_id] = dict(command='ON', encrypted=encrypted, start_ns=1_000_000_000)
        d.latency = dict(status='pending', command_id=command_id, value_ms=None, ts=time.time())
        return dict(command_id=command_id, command='ON', phase='applied', status='UNLOCKED',
                    execution_us=2500, decrypt_us=100)

    def test_device_time_not_round_trip_for_both_modes(self):
        for encrypted in (True, False):
            with self.subTest(encrypted=encrypted):
                ack = self.pending('0123456789abcde' + str(int(encrypted)), encrypted)
                self.dashboard._receive_command_ack(ack, 1_200_000_000, time.time())
                self.assertEqual(self.dashboard.latency['value_ms'], 2.5)
                row = dict(self.dashboard.store.db.execute(
                    'SELECT * FROM measurements WHERE command_id=?', (ack['command_id'],)).fetchone())
                self.assertEqual(row['execution_ms'], 2.5)
                self.assertEqual(row['rtt_ms'], 200)
                self.assertEqual(row['decrypt_us'], 100 if encrypted else None)
        self.dashboard.store.record_measurement(dict(ts=time.time(), mode='on',
            source='command', outcome='applied', command_id='legacy', rtt_ms=999))
        stats = self.client.get('/api/performance').get_json()
        metric = next(row for row in stats['stats'] if row['field'] == 'execution_ms')
        self.assertEqual(metric['n'], 2)
        self.assertEqual(metric['mean'], 2.5)
        csv = self.client.get('/api/performance.csv').get_data(as_text=True)
        self.assertIn('rtt_ms,execution_ms', csv)
        self.assertIn('200.0,2.5', csv)
        self.assertEqual(self.client.get('/').status_code, 200)

    def test_mqtt_ingest_and_snapshot_use_firmware_measurement(self):
        import json
        from web_server import STATUS_TOPIC
        ack = self.pending()
        self.dashboard.pending_commands[ack['command_id']]['start_ns'] = time.perf_counter_ns()
        self.dashboard.ingest(STATUS_TOPIC, json.dumps(ack).encode())
        latency = self.client.get('/api/state').get_json()['latency']
        self.assertEqual(latency['status'], 'measured')
        self.assertEqual(latency['value_ms'], 2.5)

    def test_missing_invalid_and_zero_measurements(self):
        for i, value in enumerate((None, -1, True, '2500', math.nan, math.inf, 8_000_001, 0)):
            with self.subTest(value=value):
                ack = self.pending(f'{i:016x}')
                ack['execution_us'] = value
                self.dashboard._receive_command_ack(ack, 1_200_000_000, time.time())
                self.assertEqual(self.dashboard.latency['status'], 'measured' if value == 0 and type(value) is int else 'missing')
                self.assertEqual(self.dashboard.latency['value_ms'], 0 if value == 0 and type(value) is int else None)
                self.assertNotIn(ack['command_id'], self.dashboard.pending_commands)

    def test_unmatched_duplicate_rejected_and_timeout(self):
        ack = self.pending()
        wrong = dict(ack, command='OFF')
        self.dashboard._receive_command_ack(wrong, 1_200_000_000, time.time())
        self.assertEqual(self.dashboard.latency['status'], 'pending')
        self.dashboard._receive_command_ack(dict(ack, phase='rejected', status='BUSY'), 1_200_000_000, time.time())
        self.assertEqual(self.dashboard.latency['status'], 'rejected')
        self.dashboard._receive_command_ack(ack, 1_300_000_000, time.time())
        self.assertEqual(self.dashboard.latency['status'], 'rejected')
        self.pending('1111111111111111')
        self.dashboard._expire_commands(9_000_000_000)
        self.assertEqual(self.dashboard.latency['status'], 'timeout')
        self.assertIsNone(self.dashboard.latency['value_ms'])

    def test_legacy_schema_retains_rtt_without_filling_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'legacy.sqlite3'
            store = Store(path)
            store.record_measurement(dict(ts=time.time(), mode='on', source='command',
                outcome='applied', command_id='old', rtt_ms=200))
            store.db.execute('ALTER TABLE measurements DROP COLUMN execution_ms')
            store.db.commit()
            store.close()
            for _ in range(2):
                migrated = Store(path)
                row = migrated.db.execute('SELECT rtt_ms, execution_ms FROM measurements').fetchone()
                self.assertEqual(row['rtt_ms'], 200)
                self.assertIsNone(row['execution_ms'])
                migrated.close()


if __name__ == '__main__':
    unittest.main()
