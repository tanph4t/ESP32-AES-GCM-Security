"""Dashboard ESP32 AES-128-GCM. Chạy: python web_server.py.

Giao thức tương thích crypto_app.c: HEX(Nonce12 + Tag16 + AAD8-LE + CT).
Không kết nối MQTT khi import. --offline chỉ xem UI, không phát lệnh.
"""
from __future__ import annotations

import argparse
import atexit
import csv
import hmac
import io
import json
import math
import os
import re
import secrets
import sqlite3
import ssl
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, render_template_string, request
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = Path(__file__).resolve().parent
VN = timezone(timedelta(hours=7))
AES_KEY = bytes.fromhex(os.getenv("AES_KEY_HEX", "0102030405060708090A0B0C0D0E0F10"))
if len(AES_KEY) != 16:
    raise ValueError("AES_KEY_HEX phải biểu diễn đúng 16 byte cho AES-128-GCM.")
TOPIC = "device/esp32/control"
STATUS_TOPIC = "device/esp32/status"
TELEMETRY_TOPIC = "device/esp32/telemetry"
MODE_TOPIC = "device/esp32/config/aes"
from cycle_energy_web import CycleEnergy, RESULT as CYCLE_RESULT
from command_memory_web import parse_memory, register_memory_routes

METRICS = {"voltage_v", "current_ma", "power_w", "heap_free_bytes", "decrypt_us"}


def encrypt_payload(command_str, key=AES_KEY, aad_suffix=b"", *, timings=None):
    """Giữ đúng định dạng của ESP32; khóa 16 byte chọn AES-128."""
    nonce = os.urandom(12)
    aad = struct.pack("<Q", int(time.time()))
    plaintext = command_str.encode("utf-8")
    associated_data = aad + aad_suffix
    # Đo trên PC: tạo đối tượng AESGCM + encrypt (bao gồm Tag), không tính nonce/HEX/MQTT.
    started = time.perf_counter_ns()
    sealed = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    elapsed_us = (time.perf_counter_ns() - started) / 1000.0
    if timings is not None:
        timings["encrypt_us"] = elapsed_us
    return (nonce + sealed[-16:] + aad + sealed[:-16]).hex().upper()


def packet_info(payload, encrypted):
    if not encrypted:
        return {"format": "UTF-8 plaintext", "bytes": len(payload.encode()),
                "nonce": None, "tag": None, "aad": None, "ciphertext": None,
                "timestamp": None}
    raw = bytes.fromhex(payload)
    return {"format": "HEX · Nonce | Tag | AAD | Ciphertext", "bytes": len(raw),
            "nonce": raw[:12].hex().upper(), "tag": raw[12:28].hex().upper(),
            "aad": raw[28:36].hex().upper(), "ciphertext": raw[36:].hex().upper(),
            "timestamp": struct.unpack("<Q", raw[28:36])[0]}


def date_bounds(value):
    day = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=VN)
    return day.timestamp(), (day + timedelta(days=1)).timestamp()


class Store:
    def __init__(self, path):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.db:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL,
                title TEXT NOT NULL, detail TEXT NOT NULL, relay_state INTEGER)""")
            self.db.execute("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)")
            self.db.execute("""CREATE TABLE IF NOT EXISTS measurements (
                id INTEGER PRIMARY KEY, ts REAL NOT NULL, mode TEXT NOT NULL,
                source TEXT NOT NULL, command_id TEXT UNIQUE, command TEXT, scenario TEXT,
                outcome TEXT NOT NULL, payload_bytes INTEGER,
                voltage_v REAL, current_ma REAL, power_w REAL, heap_free_bytes REAL,
                encrypt_us REAL, decrypt_us REAL, rtt_ms REAL)""")
            columns = {row["name"] for row in self.db.execute("PRAGMA table_info(measurements)")}
            if "execution_ms" not in columns:
                self.db.execute("ALTER TABLE measurements ADD COLUMN execution_ms REAL")
            if "e2e_ms" not in columns:
                self.db.execute("ALTER TABLE measurements ADD COLUMN e2e_ms REAL")
            if "command_memory_json" not in columns:
                self.db.execute("ALTER TABLE measurements ADD COLUMN command_memory_json TEXT")
            self.db.execute("CREATE INDEX IF NOT EXISTS measurements_ts ON measurements(ts)")
            self.db.execute("UPDATE measurements SET outcome='interrupted' WHERE outcome='pending'")

    def log(self, kind, title, detail="", relay_state=None):
        with self.lock, self.db:
            self.db.execute("INSERT INTO events(ts,kind,title,detail,relay_state) VALUES(?,?,?,?,?)",
                            (time.time(), kind, title, detail, relay_state))

    def history(self, day, limit=500):
        start, end = date_bounds(day)
        with self.lock:
            rows = self.db.execute("SELECT * FROM events WHERE ts>=? AND ts<? ORDER BY id DESC LIMIT ?",
                                   (start, end, limit)).fetchall()
        return [dict(row) for row in rows]

    def record_measurement(self, row):
        columns = ("ts", "mode", "source", "command_id", "command", "scenario", "outcome",
                   "payload_bytes", "voltage_v", "current_ma", "power_w", "heap_free_bytes",
                   "encrypt_us", "decrypt_us", "rtt_ms", "execution_ms", "e2e_ms")
        with self.lock, self.db:
            self.db.execute("INSERT INTO measurements("+",".join(columns)+") VALUES("+
                            ",".join("?" for _ in columns)+")", tuple(row.get(c) for c in columns))

    def finish_measurement(self, command_id, outcome, decrypt_us=None, rtt_ms=None, execution_ms=None, e2e_ms=None, memory=None):
        with self.lock, self.db:
            self.db.execute("UPDATE measurements SET outcome=?,decrypt_us=?,rtt_ms=?,execution_ms=?,e2e_ms=?,command_memory_json=? "
                            "WHERE command_id=? AND outcome='pending'",
                            (outcome, decrypt_us, rtt_ms, execution_ms, e2e_ms,
                             json.dumps(memory) if memory is not None else None, command_id))

    def measurements(self, day, mode="all", limit=2000):
        if mode not in {"all", "on", "off"}:
            raise ValueError("mode phải là all, on hoặc off.")
        start, end = date_bounds(day)
        where = "ts>=? AND ts<?"
        args = [start, end]
        if mode != "all":
            where += " AND mode=?"
            args.append(mode)
        with self.lock:
            rows = self.db.execute("SELECT * FROM measurements WHERE "+where+
                                   " ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
        return [dict(row) for row in rows]

    def close(self):
        with self.lock:
            self.db.close()


class Dashboard:
    def __init__(self, db_path):
        self.store = Store(db_path)
        self.lock = threading.RLock()
        self.send_lock = threading.Lock()
        self.client = None
        self.connected = False
        self.offline = False
        self.error = "Chưa khởi động kết nối MQTT."
        self.aes_enabled = True
        self.firmware_aes = None
        self.firmware_mode_ts = None
        self.mode_challenge = None
        self.last_mode_query = 0.0
        self.pending_mode = None
        self.mode_event = threading.Event()
        self.mode_timeout_s = 6.0
        self.last_seen = None
        self.last_state = None
        self.last_state_ts = None
        self.last_message = None
        self.metrics = {}
        self.sensor_ok = None
        self.sensor_ts = None
        self.sensor_error = None
        self.sensor_diagnostics = {}
        self.samples = []
        self.latest_packet = None
        self.last_valid_packet = None
        self.heartbeat_s = 30
        self.pending_commands = {}
        self.command_timeout_s = 8.0
        self.latency = {"status": "idle", "command_id": None, "value_ms": None, "ts": None}
        self.end_to_end = dict(self.latency)
        self.mqtt_connection_epoch = 0
        self.cycle_energy = CycleEnergy(self,AES_KEY)
        self.store.log("SYSTEM", "Bắt đầu phiên dashboard", "Chờ phản hồi mới từ ESP32.")

    def start_mqtt(self):
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                             client_id="an-dashboard-" + secrets.token_hex(4),
                             protocol=mqtt.MQTTv311)
        client.username_pw_set(os.getenv("MQTT_USER", "esp32"), os.getenv("MQTT_PASS", "1234"))
        ca = Path(os.getenv("MQTT_CA_FILE", str(BASE / "emqxsl-ca.crt")))
        try:
            ctx = ssl.create_default_context(cafile=str(ca))
            # Tùy chọn lab: xuất secret phiên TLS của chính Python để phân tích Wireshark.
            # Mặc định KHÔNG bật. Không liên quan đến khóa AES của payload.
            if os.getenv("MQTT_TLS_KEYLOG"):
                ctx.keylog_filename = str(Path(os.environ["MQTT_TLS_KEYLOG"]).resolve())
            client.tls_set_context(ctx)
            client.on_connect = self.on_connect
            client.on_disconnect = self.on_disconnect
            client.on_connect_fail = self.on_connect_fail
            client.on_message = self.on_message
            client.reconnect_delay_set(min_delay=1, max_delay=30)
            self.client = client
            self.error = "Đang kết nối MQTT/TLS…"
            client.connect_async(os.getenv("MQTT_BROKER", "i9509b90.ala.asia-southeast1.emqxsl.com"),
                                 int(os.getenv("MQTT_PORT", "8883")), 60)
            client.loop_start()
        except (OSError, ValueError, ssl.SSLError) as exc:
            self.error = "Không khởi tạo được MQTT/TLS. Kiểm tra CA và cấu hình kết nối."
            self.store.log("ERROR", "Không khởi tạo được MQTT", type(exc).__name__)

    def stop(self):
        self.cycle_energy.cancel.set()
        if self.client:
            self.client.disconnect()
            self.client.loop_stop()

    def on_connect(self, client, userdata, flags, reason_code, properties):
        with self.lock:
            self.mqtt_connection_epoch += 1
            self.connected = reason_code == 0
            self.cycle_energy.supported = False
            self.firmware_mode_ts = None
            self.mode_challenge = None
            self.last_mode_query = 0.0
            self.error = None if self.connected else "Broker từ chối kết nối: " + str(reason_code)
            if self.connected:
                rc, _ = client.subscribe([(STATUS_TOPIC, 1), (TELEMETRY_TOPIC, 0), (CYCLE_RESULT, 1)])
                if rc != mqtt.MQTT_ERR_SUCCESS:
                    self.error = "Đã kết nối nhưng chưa gửi được yêu cầu subscribe."
                self.store.log("SYSTEM", "Đã kết nối MQTT/TLS", "Đang chờ dữ liệu từ ESP32.")

    def on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        with self.lock:
            self.mqtt_connection_epoch += 1
            self.connected = False
            self.cycle_energy.disconnected()
            self.firmware_mode_ts = None
            self.mode_challenge = None
            self.error = "Mất kết nối broker; đang thử kết nối lại."
            self.store.log("SYSTEM", "Mất kết nối MQTT", str(reason_code))

    def on_connect_fail(self, client, userdata):
        with self.lock:
            self.connected = False
            self.error = "Chưa kết nối được broker. Kiểm tra mạng, CA và tài khoản MQTT."

    def on_message(self, client, userdata, message):
        try:
            if message.topic == CYCLE_RESULT:
                self.cycle_energy.ingest(message.payload,retained=bool(message.retain))
            else:
                self.ingest(message.topic, message.payload, retained=bool(message.retain))
        except (ValueError, UnicodeError, TypeError):
            self.store.log("ERROR", "Bỏ qua dữ liệu MQTT không hợp lệ", "Kiểm tra JSON và schema telemetry.")

    def ingest(self, topic, payload, retained=False):
        received_ns = time.perf_counter_ns()
        if topic not in (STATUS_TOPIC, TELEMETRY_TOPIC) or len(payload) > 8192:
            raise ValueError("Unexpected topic or oversized telemetry")
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        if retained:
            # Một gói retained cũ không chứng minh thiết bị còn online.
            self.store.log("RETAINED", "Nhận bản tin retained", "Không dùng bản tin cũ để xác nhận trạng thái hiện tại.")
            return
        now = time.time()
        with self.lock:
            self._expire_commands(received_ns)
            self._receive_command_ack(data, received_ns, now)
            if type(data.get("cycle_energy_supported")) is bool:
                self.cycle_energy.supported=data["cycle_energy_supported"] and data.get("cycle_energy_protocol")==1
                self.cycle_energy.firmware_busy=data.get("cycle_energy_busy") is True
                self.cycle_energy.firmware_id=str(data.get("cycle_energy_id",""))
            state = str(data.get("status", "")).upper()[:40]
            relay = data.get("relay_on")
            if type(relay) is not bool:
                relay = True if state == "UNLOCKED" else False if state == "LOCKED" else None
            recognized = relay is not None or state in {"ALARM", "AUTH_FAIL", "REPLAY_REJECT", "REJECTED", "ONLINE", "BUSY"}
            if relay is not None:
                self.last_state, self.last_state_ts = relay, now
            for field in METRICS:
                if field in data and data[field] is None:
                    self.metrics.pop(field, None)
                    recognized = True
                value = data.get(field)
                if type(value) in (int, float) and abs(value) <= 1e12 and math.isfinite(value):
                    if field in {"voltage_v", "heap_free_bytes", "decrypt_us"} and value < 0:
                        continue
                    self.metrics[field] = {"value": value, "ts": now}
                    recognized = True
            if type(data.get("ina219_ok")) is bool:
                self.sensor_ok, self.sensor_ts = data["ina219_ok"], now
                self.sensor_error = data.get("sensor_error")
                self.sensor_diagnostics = {}
                for key in ("sensor_stage", "sensor_error_name"):
                    if isinstance(data.get(key), str):
                        self.sensor_diagnostics[key] = data[key][:64]
                for key in ("bus_raw", "shunt_raw"):
                    if type(data.get(key)) is int and -1 <= data[key] <= 65535:
                        self.sensor_diagnostics[key] = data[key]
                recognized = True
            if type(data.get("aes_enabled")) is bool:
                self.firmware_aes, self.firmware_mode_ts = data["aes_enabled"], now
                challenge = data.get("mode_challenge")
                if state in {"MODE_STATE", "MODE_CHANGED"} and isinstance(challenge, str) and re.fullmatch(r"[0-9A-Fa-f]{32}", challenge):
                    self.mode_challenge = challenge.upper()
                if self.pending_mode:
                    if (state == "MODE_CHANGED" and data.get("request_id") == self.pending_mode["id"]
                            and self.firmware_aes == self.pending_mode["enabled"]):
                        self.pending_mode["confirmed"] = True
                        self.aes_enabled = self.firmware_aes
                        self.mode_event.set()
                else:
                    self.aes_enabled = self.firmware_aes
                if not self.firmware_aes:
                    self.metrics.pop("decrypt_us", None)
                recognized = True
            if not recognized:
                raise ValueError("No supported state or metric fields")
            self.last_seen = now
            if (topic == STATUS_TOPIC or state) and state != "MODE_STATE":
                self.last_message = str(data.get("message", "ESP32 gửi trạng thái mới."))[:400]
                title = {"UNLOCKED": "Mở khóa · Relay bật", "LOCKED": "Khóa lại · Relay tắt",
                         "ALARM": "ESP32 báo cảnh báo", "AUTH_FAIL": "ESP32 báo sai Tag",
                         "REPLAY_REJECT": "ESP32 báo từ chối replay",
                         "MODE_CHANGED": "ESP32 xác nhận đổi AES", "MODE_ERROR": "ESP32 từ chối đổi AES"}.get(state, "ESP32 gửi trạng thái")
                self.store.log("DEVICE", title, self.last_message,
                               int(relay) if relay is not None else None)
            if topic == TELEMETRY_TOPIC:
                sample = {"ts": now}
                for field in METRICS:
                    value = data.get(field)
                    if field in self.metrics and self.metrics[field]["ts"] == now:
                        sample[field] = value
                self.samples.append(sample)
                self.samples = self.samples[-120:]
                # Lưu số đo cảm biến tách biệt thời gian lệnh; lỗi cảm biến không thành số 0.
                row = {"ts": now, "mode": "on" if self.aes_enabled else "off",
                       "source": "telemetry", "outcome": "valid" if self.sensor_ok is True else "sensor_error"}
                for field in ("voltage_v", "current_ma", "power_w", "heap_free_bytes"):
                    if field == "heap_free_bytes" or data.get("ina219_ok") is True:
                        item = self.metrics.get(field)
                        if item and item["ts"] == now:
                            row[field] = item["value"]
                self.store.record_measurement(row)

    def _expire_commands(self, now_ns=None):
        now_ns = time.perf_counter_ns() if now_ns is None else now_ns
        for command_id, pending in list(self.pending_commands.items()):
            if now_ns-pending["start_ns"] >= self.command_timeout_s*1e9:
                self.pending_commands.pop(command_id, None)
                self.store.finish_measurement(command_id, "ack_timeout")
                for measurement in (self.latency, self.end_to_end):
                    if measurement["command_id"] == command_id:
                        measurement.update(status="timeout", value_ms=None, ts=time.time())

    def _receive_command_ack(self, data, received_ns, now):
        command_id = data.get("command_id")
        if not isinstance(command_id, str):
            return
        pending = self.pending_commands.get(command_id)
        if not pending or data.get("command") != pending["command"]:
            return  # Không ghép telemetry, ACK lạ hoặc ACK lặp vào mẫu hiện tại.
        if "aes_enabled" in data and (type(data["aes_enabled"]) is not bool or data["aes_enabled"] != pending["encrypted"]):
            return  # A different mode cannot complete this command or its memory sample.
        phase = data.get("phase")
        expected = "UNLOCKED" if pending["command"] == "ON" else "LOCKED"
        if phase == "applied" and data.get("status") == expected:
            rtt_ms = max(0, received_ns-pending["start_ns"]) / 1_000_000.0
            decrypt_us = data.get("decrypt_us") if pending["encrypted"] else None
            if type(decrypt_us) not in (int, float) or not math.isfinite(decrypt_us) or decrypt_us < 0:
                decrypt_us = None
            execution_us = data.get("execution_us")
            execution_ms = (execution_us / 1000.0 if type(execution_us) in (int, float)
                            and math.isfinite(execution_us) and 0 <= execution_us <= self.command_timeout_s * 1e6
                            else None)
            e2e_start_ns = pending.get("e2e_start_ns")
            e2e_ms = ((received_ns - e2e_start_ns) / 1_000_000.0
                      if e2e_start_ns is not None and received_ns >= e2e_start_ns else None)
            self.store.finish_measurement(command_id, "applied", decrypt_us, rtt_ms, execution_ms, e2e_ms,
                                          parse_memory(data, pending["encrypted"]))
            if self.end_to_end["command_id"] == command_id:
                self.end_to_end.update(status="measured" if e2e_ms is not None else "missing",
                                       value_ms=e2e_ms, ts=now)
            if self.latency["command_id"] == command_id:
                self.latency.update(status="measured" if execution_ms is not None else "missing",
                                    value_ms=execution_ms, ts=now)
        elif phase == "rejected" and data.get("status") == "BUSY":
            self.store.finish_measurement(command_id, "rejected")
            for measurement in (self.latency, self.end_to_end):
                if measurement["command_id"] == command_id:
                    measurement.update(status="rejected", value_ms=None, ts=now)
        else:
            return
        self.pending_commands.pop(command_id, None)
        self.cycle_energy.ack(data)

    def request_mode_state(self, *, batch_token=None):
        # GET chỉ hỏi chế độ/challenge, không điều khiển thiết bị. Tối đa 1 gói/5s.
        with self.lock:
            if self.cycle_energy.running() and not self.cycle_energy.authorized(batch_token):return
            if not self.connected or not self.client or self.offline:
                return
            now = time.monotonic()
            if now - self.last_mode_query < 5:
                return
            self.last_mode_query = now
            self.client.publish(MODE_TOPIC, "GET", qos=0, retain=False)

    def change_mode(self, enabled, *, batch_token=None):
        # Khóa gửi lệnh trong lúc chuyển chế độ. Không giữ self.lock khi chờ ACK.
        with self.send_lock:
            with self.lock:
                if (self.cycle_energy.running() or self.cycle_energy.firmware_busy) and not self.cycle_energy.authorized(batch_token):
                    raise ConnectionError("Đang đo năng lượng theo đợt.")
                if not self.connected or not self.client or self.offline:
                    raise ConnectionError("Chưa kết nối MQTT; chưa đổi chế độ ESP32.")
                if not self.mode_challenge or self.firmware_mode_ts is None or time.time() - self.firmware_mode_ts > self.heartbeat_s:
                    raise ConnectionError("Chưa có xác nhận chế độ từ ESP32. Chờ vài giây; kiểm tra đã nạp firmware mới và quyền topic config/aes.")
                request_id = secrets.token_hex(8)
                command = f"AES={int(enabled)}:{request_id}:{self.mode_challenge}"
                # Luôn mã hóa cấu hình, kể cả khi control đang ở plaintext.
                payload = encrypt_payload(command, aad_suffix=MODE_TOPIC.encode("ascii"))
                self.pending_mode = {"id": request_id, "enabled": enabled, "confirmed": False}
                self.mode_event.clear()
                result = self.client.publish(MODE_TOPIC, payload, qos=0, retain=False)
                if result.rc != mqtt.MQTT_ERR_SUCCESS:
                    self.pending_mode = None
                    raise ConnectionError("Không gửi được yêu cầu đổi chế độ AES.")
            self.mode_event.wait(self.mode_timeout_s)
            with self.lock:
                confirmed = self.pending_mode is not None and self.pending_mode["confirmed"]
                self.pending_mode = None
                if not confirmed:
                    if self.firmware_aes is not None:
                        self.aes_enabled = self.firmware_aes
                    self.last_mode_query = 0.0
                    self.store.log("ERROR", "Chưa xác nhận đổi AES", "Kiểm tra khóa, firmware và topic config/aes.")
                    raise TimeoutError("ESP32 chưa xác nhận đổi AES trong 6 giây. Kiểm tra Serial Monitor, khóa AES và quyền MQTT cho topic config/aes; chờ trang cập nhật rồi thử lại.")
                self.store.log("MODE", "Đã bật AES trên ESP32" if enabled else "Đã tắt AES trên ESP32", "ACK khớp request_id.")
                return enabled

    def send(self, scenario, command="OFF", *, batch_token=None):
        if scenario not in {"control", "sniff", "tamper", "replay", "oversize"}:
            raise ValueError("Kịch bản không hợp lệ.")
        if command not in {"ON", "OFF"}:
            raise ValueError("Chỉ hỗ trợ ON và OFF với firmware hiện tại.")
        with self.send_lock, self.lock:
            if (self.cycle_energy.running() or self.cycle_energy.firmware_busy) and not self.cycle_energy.authorized(batch_token):
                raise ConnectionError("Đang đo năng lượng theo đợt; điều khiển thủ công tạm khóa.")
            if not self.connected or not self.client or self.offline:
                raise ConnectionError("Chưa kết nối MQTT. Lệnh chưa được gửi.")
            if (self.firmware_aes is None or self.firmware_mode_ts is None or
                    time.time() - self.firmware_mode_ts > self.heartbeat_s or
                    self.firmware_aes != self.aes_enabled or not self.mode_challenge):
                raise ConnectionError("Chưa xác nhận chế độ ESP32. Chờ đồng bộ trước khi gửi lệnh.")
            self._expire_commands()
            if scenario == "control":
                if (type(self.last_state) is not bool or self.last_state_ts is None or
                        time.time() - self.last_state_ts > self.heartbeat_s):
                    raise ConnectionError("Chưa có trạng thái khóa mới từ ESP32. Chờ thiết bị phản hồi.")
                if self.pending_commands:
                    raise ConnectionError("Đang chờ ESP32 xác nhận lệnh trước; chưa gửi lệnh mới.")
            if len(self.pending_commands) >= 64:
                raise ConnectionError("Đang chờ quá nhiều ACK; chờ vài giây rồi thử lại.")
            encrypted = self.aes_enabled
            command_id = secrets.token_hex(8) if scenario in {"control", "sniff"} else None
            # E2E starts before preparing/encrypting the command, on the same PC clock as ACK receipt.
            e2e_start_ns = time.perf_counter_ns() if command_id else None
            timings = {}
            if scenario == "replay":
                if not self.last_valid_packet:
                    raise ValueError("Hãy gửi một lệnh thường trước khi thử replay.")
                old = self.last_valid_packet
                if old["encrypted"] != encrypted:
                    raise ValueError("Mẫu cũ khác chế độ AES. Gửi lệnh thường mới trước khi replay.")
                payload, command = old["payload"], old["command"]
                created = old["created_at"]
                encryption_us = None
            else:
                plain = "A" * 200 if scenario == "oversize" else command
                if command_id:
                    plain += ":"+command_id
                t0 = time.perf_counter_ns()
                payload = encrypt_payload(plain, timings=timings) if encrypted else plain
                encryption_us = (time.perf_counter_ns() - t0) / 1000 if encrypted else None
                created = time.time()
                if scenario == "tamper" and encrypted:
                    raw = bytearray.fromhex(payload)
                    raw[-1] ^= 0x01  # Đảo một bit ciphertext, giữ nguyên Tag: luôn tạo thay đổi.
                    payload = raw.hex().upper()
            packet = {"id": secrets.token_hex(6), "scenario": scenario, "command": command,
                      "command_id": command_id, "payload": payload, "encrypted": encrypted,
                      "created_at": created, "sent_at": time.time(), "payload_chars": len(payload),
                      "publisher_processing_us": encryption_us, "encrypt_us": timings.get("encrypt_us"),
                      **packet_info(payload, encrypted)}
            self.latest_packet = packet
            # Đăng ký trước publish: tránh mất ACK rất nhanh; không đợi ACK trong HTTP/task MQTT.
            if command_id:
                self.store.record_measurement({"ts": packet["sent_at"], "mode": "on" if encrypted else "off",
                    "source": "command", "command_id": command_id, "command": command,
                    "scenario": scenario, "outcome": "pending", "payload_bytes": packet["bytes"],
                    "encrypt_us": packet["encrypt_us"]})
                self.latency = {"status": "pending", "command_id": command_id, "value_ms": None,
                                "ts": packet["sent_at"]}
                self.end_to_end = dict(self.latency)
                self.pending_commands[command_id] = {"command": command, "encrypted": encrypted,
                                                     "start_ns": time.perf_counter_ns(),
                                                     "e2e_start_ns": e2e_start_ns}
            else:
                self.latency = {"status": "test", "command_id": None, "value_ms": None, "ts": packet["sent_at"]}
                self.end_to_end = dict(self.latency)
            try:
                result = self.client.publish(TOPIC, payload, qos=0, retain=False)
                if result.rc != mqtt.MQTT_ERR_SUCCESS:
                    raise ConnectionError("MQTT chưa nhận lệnh để gửi. Hãy kiểm tra kết nối.")
            except Exception:
                if command_id:
                    self.pending_commands.pop(command_id, None)
                    self.store.finish_measurement(command_id, "publish_failed")
                self.latency.update(status="failed", value_ms=None)
                self.end_to_end.update(status="failed", value_ms=None)
                raise ConnectionError("MQTT chưa nhận lệnh để gửi. Hãy kiểm tra kết nối.") from None
            if scenario in {"control", "sniff"}:
                self.last_valid_packet = dict(packet)
            mode = "AES-128-GCM" if encrypted else "Plaintext"
            title = {"control": "Gửi lệnh " + command, "sniff": "Gửi mẫu nghe lén · " + command,
                     "tamper": "Gửi mẫu giả mạo", "replay": "Gửi lại nguyên gói cũ",
                     "oversize": "Gửi mẫu vượt kích thước"}[scenario]
            self.store.log("COMMAND" if scenario == "control" else "TEST", title,
                           mode + " · đã chuyển cho MQTT; chưa xác nhận ESP32 thực thi.")
            return packet

    def snapshot(self):
        with self.lock:
            self._expire_commands()
            now = time.time()
            return {"cycle_energy_active": self.cycle_energy.running() or self.cycle_energy.firmware_busy, "server_time": now, "today": datetime.now(VN).strftime("%Y-%m-%d"),
                    "mqtt": {"connected": self.connected, "offline": self.offline, "error": self.error,
                             "topic": TOPIC, "status_topic": STATUS_TOPIC, "telemetry_topic": TELEMETRY_TOPIC},
                    "aes_enabled": self.aes_enabled,
                    "mode_pending": self.pending_mode is not None,
                    "control_pending": bool(self.pending_commands),
                    "mode_ready": bool(self.mode_challenge and self.firmware_mode_ts is not None
                                       and now - self.firmware_mode_ts < self.heartbeat_s),
                    "device": {"relay_on": self.last_state, "state_ts": self.last_state_ts,
                               "last_seen": self.last_seen,
                               "recent": self.connected and self.last_seen is not None and now-self.last_seen < self.heartbeat_s,
                               "message": self.last_message, "aes_enabled": self.firmware_aes,
                               "aes_ts": self.firmware_mode_ts, "sensor_ok": self.sensor_ok,
                               "sensor_ts": self.sensor_ts, "sensor_error": self.sensor_error,
                               "sensor_diagnostics": dict(self.sensor_diagnostics)},
                    "metrics": dict(self.metrics), "samples": list(self.samples),
                    "latency": dict(self.latency), "end_to_end": dict(self.end_to_end),
                    "latest_packet": self.latest_packet, "replay_packet": self.last_valid_packet}


def create_app(db_path=None, connect=False):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 4096
    dashboard = Dashboard(db_path or os.getenv("DASHBOARD_DB", str(BASE / "iot_history.sqlite3")))
    app.extensions["dashboard"] = dashboard
    register_memory_routes(app, dashboard, VN)
    token = secrets.token_urlsafe(32)

    @app.before_request
    def protect_writes():
        if request.method == "POST" and not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), token):
            return jsonify(error="Yêu cầu không hợp lệ. Tải lại trang dashboard."), 403

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/")
    def index():
        return render_template_string(HTML_TEMPLATE, csrf=token)

    @app.get("/api/state")
    def state():
        dashboard.request_mode_state()
        return jsonify(dashboard.snapshot())

    @app.get("/api/cycle-energy")
    def cycle_energy_state():
        return jsonify(dashboard.cycle_energy.snapshot(request.args.get("session")))

    @app.post("/api/cycle-energy/start")
    def cycle_energy_start():
        try:return jsonify(session_id=dashboard.cycle_energy.start(request.get_json(silent=True)))
        except ValueError as exc:return jsonify(error=str(exc)),400

    @app.post("/api/cycle-energy/stop")
    def cycle_energy_stop():
        try:
            dashboard.cycle_energy.stop()
            return jsonify(message="Sẽ dừng sau chu kỳ ON/OFF hiện tại; đợt thiếu lệnh không tính trung bình.")
        except ValueError as exc:return jsonify(error=str(exc)),400

    @app.get("/api/cycle-energy.csv")
    @app.get("/api/cycle-energy-commands.csv")
    def cycle_energy_csv():
        ident=request.args.get("session", "")
        if not re.fullmatch("[0-9a-f]{16}",ident):return jsonify(error="Mã lượt thử không hợp lệ."),400
        try:
            return Response(dashboard.cycle_energy.csv(ident,request.path.endswith("-commands.csv")),mimetype="text/csv; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="cycle_energy.csv"'})
        except ValueError as exc:return jsonify(error=str(exc)),404

    @app.get("/api/history")
    def history():
        day = request.args.get("date", datetime.now(VN).strftime("%Y-%m-%d"))
        try:
            events = dashboard.store.history(day)
        except ValueError:
            return jsonify(error="Ngày phải có định dạng YYYY-MM-DD."), 400
        return jsonify(events=events, limit=500)

    @app.get("/api/history.csv")
    def export_history():
        day = request.args.get("date", datetime.now(VN).strftime("%Y-%m-%d"))
        try:
            events = dashboard.store.history(day, 100000)
        except ValueError:
            return jsonify(error="Ngày không hợp lệ."), 400
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Thời gian UTC+7", "Loại", "Sự kiện", "Chi tiết", "Relay do ESP32 báo"])
        def cell(value):
            text = str(value)
            return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text
        for event in reversed(events):
            writer.writerow([datetime.fromtimestamp(event["ts"], VN).isoformat(), event["kind"],
                             cell(event["title"]), cell(event["detail"]),
                             "" if event["relay_state"] is None else event["relay_state"]])
        return Response("\ufeff" + buffer.getvalue(), mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="history_{day}.csv"'})

    @app.get("/api/performance")
    def performance():
        day = request.args.get("date", datetime.now(VN).strftime("%Y-%m-%d"))
        mode = request.args.get("mode", "all")
        try:
            with dashboard.lock:
                dashboard._expire_commands()
            rows = dashboard.store.measurements(day, mode, limit=2000)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        fields = [("voltage_v", "Điện áp mẫu · INA219", "V"), ("current_ma", "Dòng điện mẫu · INA219", "mA"),
                  ("power_w", "Công suất mẫu nguồn ESP32", "W"), ("encrypt_us", "Mã hóa AES-GCM · Python", "µs"),
                  ("decrypt_us", "Xác thực–giải mã AES-GCM · ESP32", "µs"), ("execution_ms", "Xử lý lệnh đến đặt GPIO · ESP32", "ms"),
                  ("e2e_ms", "Độ trễ điều khiển đầu-cuối · E2E", "ms")]
        stats = []
        for field, label, unit in fields:
            values = sorted(row[field] for row in rows if row[field] is not None and
                            (row["source"] == "telemetry" and row["outcome"] == "valid" or
                             row["source"] == "command" and row["outcome"] == "applied"))
            stats.append({"field": field, "label": label, "unit": unit, "n": len(values),
                          "last": next((row[field] for row in rows if row[field] is not None and
                                       row["outcome"] in {"valid", "applied"}), None),
                          "min": values[0] if values else None, "max": values[-1] if values else None,
                          "mean": sum(values)/len(values) if values else None,
                          "p95": values[math.ceil(len(values)*.95)-1] if values else None})
        return jsonify(stats=stats, row_count=len(rows), limit=2000,
                       applied=sum(r["source"] == "command" and r["outcome"] == "applied" for r in rows),
                       timeouts=sum(r["outcome"] == "ack_timeout" for r in rows))

    @app.get("/api/performance.csv")
    def performance_csv():
        day = request.args.get("date", datetime.now(VN).strftime("%Y-%m-%d"))
        try:
            rows = dashboard.store.measurements(day, request.args.get("mode", "all"), limit=100000)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        columns = ["ts", "mode", "source", "command_id", "command", "scenario", "outcome",
                   "payload_bytes", "voltage_v", "current_ma", "power_w", "heap_free_bytes",
                   "encrypt_us", "decrypt_us", "rtt_ms", "execution_ms", "e2e_ms"]
        buffer = io.StringIO(); writer = csv.writer(buffer)
        writer.writerow(columns)
        for row in reversed(rows):
            writer.writerow([row[col] if row[col] is not None else "" for col in columns])
        return Response("\ufeff"+buffer.getvalue(), mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="measurements_{day}.csv"'})

    @app.post("/api/mode")
    def mode():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or type(data.get("enabled")) is not bool:
            return jsonify(error="enabled phải là true hoặc false."), 400
        try:
            enabled = dashboard.change_mode(data["enabled"])
        except ConnectionError as exc:
            return jsonify(error=str(exc)), 503
        except TimeoutError as exc:
            return jsonify(error=str(exc)), 504
        return jsonify(enabled=enabled, confirmed=True)

    @app.post("/api/control")
    def control():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="Cần gửi JSON object."), 400
        scenario, command = data.get("scenario", "control"), data.get("command", "OFF")
        if not isinstance(scenario, str) or not isinstance(command, str):
            return jsonify(error="Lệnh hoặc kịch bản không hợp lệ."), 400
        try:
            packet = dashboard.send(scenario, command)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except ConnectionError as exc:
            return jsonify(error=str(exc)), 503
        return jsonify(message="Đã chuyển gói tin cho MQTT. Chờ ESP32 báo trạng thái hoặc xem Serial Monitor.", packet=packet)

    if connect:
        dashboard.start_mqtt()
        atexit.register(dashboard.stop)
    return app


# HTML_TEMPLATE được đặt ở cuối file để có thể thay đúng một web_server.py.

HTML_TEMPLATE = r'''
<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270 0 64 64%27%3E%3Crect width=%2764%27 height=%2764%27 rx=%2716%27 fill=%27%23102c67%27/%3E%3Cpath d=%27M32 10L14 17v16c0 11 18 22 18 22s18-11 18-22V17z%27 fill=%27none%27 stroke=%27%23f49324%27 stroke-width=%274%27/%3E%3C/svg%3E"><meta name="color-scheme" content="light"><title>An · IoT Security Lab</title>
<style>
:root{--navy:#102c67;--navy2:#173e83;--ink:#17243c;--muted:#728096;--line:#e7ecf3;--bg:#f5f7fb;--orange:#f49324;--orange-pale:#fff2df;--green:#258069;--radius:20px}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:"Be Vietnam Pro","Segoe UI",sans-serif;font-size:16px;line-height:1.6}button,input{font:inherit}button,a,input{ -webkit-tap-highlight-color:transparent}button{cursor:pointer}button:disabled{cursor:not-allowed;opacity:.45}button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid #6393e3;outline-offset:3px}h1,h2,h3,p{margin:0}h1{font-size:29px;letter-spacing:-.7px;line-height:1.25}h2{font-size:18px;letter-spacing:-.3px}h3{font-size:17px}a{color:var(--navy)}.icon{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}.symbols{position:absolute;width:0;height:0;overflow:hidden}.sidebar{position:fixed;inset:0 auto 0 0;width:222px;background:#fff;border-right:1px solid var(--line);padding:32px 19px;display:flex;flex-direction:column;z-index:10}.brand{display:flex;gap:11px;align-items:center;padding:0 11px;margin-bottom:40px}.brand-mark{width:43px;height:43px;display:grid;place-items:center;background:var(--navy);color:white;border-radius:14px}.brand strong{font-size:18px;letter-spacing:-.5px}.eyebrow{font-size:13px;letter-spacing:1.9px;font-weight:750;text-transform:uppercase;color:var(--muted)}.brand .eyebrow{letter-spacing:1px;font-size:12px}.nav-title{margin:0 12px 12px}.nav-btn{display:flex;gap:12px;align-items:center;width:100%;text-align:left;border:0;background:none;color:var(--muted);padding:14px;border-radius:12px;margin-bottom:6px;font-size:16px;font-weight:650}.nav-btn.active{background:var(--navy);color:white}.sidebar-bottom{margin-top:auto;border-top:1px solid var(--line);padding:22px 10px 0}.avatar{height:34px;width:34px;background:var(--orange-pale);color:#b06011;border-radius:11px;display:grid;place-items:center;font-weight:750}.user{display:flex;align-items:center;gap:10px}.user small{color:var(--muted);display:block;font-size:13px}.lab-label{margin-top:20px;font-size:13px;color:var(--muted)}.app{margin-left:222px}.topbar{height:81px;padding:0 38px;background:rgba(255,255,255,.88);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:16px}.breadcrumb{color:var(--muted);font-size:14px;display:flex;gap:12px;align-items:center}.breadcrumb b{color:var(--ink);font-weight:550}.status-group{display:flex;gap:12px;align-items:center;font-size:14px}.status-chip{border:1px solid var(--line);border-radius:100px;background:white;padding:7px 12px;display:inline-flex;align-items:center;gap:7px;color:#68758b;font-size:14px;font-weight:600}.dot{width:6px;height:6px;background:#a7b0be;border-radius:50%;display:inline-block}.status-chip.live .dot{background:#26a27a}.status-chip.live{color:var(--green);background:#f0faf6;border-color:#d8eee4}.main{max-width:1500px;padding:30px 38px 22px;margin:auto}.page-head{display:flex;align-items:center;justify-content:space-between;gap:25px;margin-bottom:23px}.page-head p{color:var(--muted);font-size:14px;margin-top:8px}.page-head .eyebrow{margin-bottom:9px;color:#9a713e}.security-control{flex-shrink:0;display:flex;align-items:center;gap:15px;padding:11px 15px;border:1px solid var(--line);background:white;border-radius:15px}.security-control .icon{color:var(--navy)}.security-control strong{font-size:14px;display:block}.security-control small{font-size:13px;color:var(--muted);display:block}.toggle{width:43px;height:25px;background:#d8dde5;border:0;border-radius:100px;position:relative;flex-shrink:0;padding:0;transition:background .2s}.toggle:after{content:"";width:19px;height:19px;position:absolute;top:3px;left:3px;border-radius:50%;background:white;box-shadow:0 1px 4px #24375725;transition:left .2s}.toggle[aria-checked="true"]{background:var(--orange)}.toggle[aria-checked="true"]:after{left:21px}.mode-note{display:flex;align-items:flex-start;gap:9px;font-size:14px;line-height:1.7;background:#edf2fa;color:#516789;border:1px solid #dfe7f4;padding:11px 15px;border-radius:12px;margin-bottom:24px}.mode-note .icon{width:16px;height:16px;margin-top:2px}.mode-note.warn{background:var(--orange-pale);border-color:#f5dbb7;color:#8c5a20}.section-heading{display:flex;justify-content:space-between;align-items:center;gap:15px;margin:25px 0 14px}.section-heading .caption{color:var(--muted);font-size:14px}.section-number{color:var(--orange);font-size:14px;margin-right:7px}.pill{background:#edf2fa;color:var(--navy);border-radius:8px;padding:5px 10px;font-size:13px;font-weight:650}.hero{display:grid;grid-template-columns:1fr 260px;border-radius:var(--radius);background:var(--navy);color:white;overflow:hidden;position:relative;margin-bottom:24px;min-height:156px}.hero-content{padding:26px 28px;z-index:1}.hero .eyebrow{color:#a9bad9;font-size:12px}.hero h2{font-size:23px;line-height:1.4;margin:7px 0}.hero p{font-size:14px;color:#bccbe4;max-width:460px}.hero-footer{margin-top:15px;display:flex;gap:15px;color:#d8e1f1;font-size:13px}.hero-footer span{display:flex;align-items:center;gap:6px}.hero .house{width:242px;height:165px;align-self:end;opacity:.9}.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.metric{background:white;border:1px solid var(--line);border-radius:16px;padding:17px 18px}.metric-label{display:flex;justify-content:space-between;gap:10px;font-size:14px;color:var(--muted)}.metric-label .icon{width:17px;height:17px;color:#8397b6}.metric-value{font-size:27px;font-weight:650;margin:8px 0 1px;letter-spacing:-.7px}.metric-value small{font-size:14px;color:var(--muted);font-weight:500;margin-left:4px}.metric-foot{font-size:13px;color:var(--muted);min-height:16px}.device-grid{display:grid;grid-template-columns:1fr;gap:16px}.device-card{background:white;border:1px solid var(--line);border-radius:var(--radius);padding:20px;display:flex;flex-direction:column;min-height:222px}.device-card.primary{border-color:#d8e1f2;box-shadow:0 5px 20px #132c6105}.card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}.device-icon{width:52px;height:52px;color:var(--navy);background:#f0f4fb;border-radius:15px;display:grid;place-items:center}.device-icon .icon{width:31px;height:31px;stroke-width:1.4}.device-icon.orange{color:#d88321;background:var(--orange-pale)}.device-status{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted);margin-top:3px}.device-status.on{color:#bd7524}.device-card h3{margin-top:18px;font-size:17px}.device-card p{font-size:13px;color:var(--muted);margin-top:3px}.device-bottom{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:auto;padding-top:15px}.state-text{font-size:14px;font-weight:600;color:var(--navy)}.mini-buttons{display:flex;gap:7px}.mini-buttons button{padding:6px 13px;border:1px solid var(--line);color:var(--navy);background:#fff;border-radius:8px;font-size:14px}.mini-buttons button:first-child{background:var(--orange-pale);border-color:#f9dab3;color:#af6414}.muted-tag{font-size:13px;background:#f3f5f8;color:#8994a6;border-radius:6px;padding:4px 8px}.hardware-note{font-size:13px;color:var(--muted);margin-top:10px}.panel{background:#fff;border:1px solid var(--line);border-radius:var(--radius);margin-top:23px;overflow:hidden}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:15px;padding:18px 22px;border-bottom:1px solid var(--line)}.segmented{display:flex;gap:4px;background:#f0f3f8;border-radius:10px;padding:4px}.segmented button{border:0;border-radius:8px;background:transparent;color:var(--muted);padding:8px 13px;font-size:14px;font-weight:650}.segmented button.active{background:var(--navy);color:white}.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border-radius:10px;padding:10px 15px;font-size:14px;font-weight:650;border:1px solid var(--line);background:white;color:var(--navy);text-decoration:none}.btn .icon{width:16px;height:16px}.btn.orange{background:var(--orange);border-color:var(--orange);color:#fff}.btn.navy{background:var(--navy);border-color:var(--navy);color:#fff}.btn.subtle{background:#f4f6fa}.btn.small{font-size:13px;padding:7px 11px}.panel-body{padding:20px 22px}.history-tools{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:20px}.date-control{display:flex;gap:7px;align-items:center}.date-control input{border:1px solid var(--line);border-radius:8px;background:#f7f9fc;padding:7px 10px;color:var(--navy);font-size:14px;max-width:160px}.date-control button{border:0;background:none;color:var(--navy);font-size:18px;padding:0 6px}.legend{display:flex;gap:12px;color:var(--muted);font-size:13px}.legend span{display:flex;gap:5px;align-items:center}.legend i{width:6px;height:6px;border-radius:2px;background:var(--navy)}.legend i.sent{background:var(--orange)}.timeline{display:grid;grid-template-columns:55px 1fr;gap:0;min-height:135px;background:#fafbfd;border:1px solid #eef1f6;border-radius:12px;overflow:hidden;margin-bottom:17px}.timeline-axis{display:flex;flex-direction:column;justify-content:space-between;padding:12px 8px;height:176px;font-size:12px;color:var(--muted);border-right:1px solid var(--line)}.timeline-area{position:relative;height:176px;background:repeating-linear-gradient(to bottom,transparent 0,transparent 43px,#e8edf4 43px,#e8edf4 44px)}.timeline-caption{position:absolute;top:8px;left:14px;font-size:13px;color:var(--muted)}.timeline-empty{position:absolute;inset:0;display:grid;place-content:center;text-align:center;color:#8c99ad;font-size:14px;padding:35px}.timeline-event{position:absolute;width:8px;height:8px;border-radius:50%;background:var(--navy);left:50%;box-shadow:0 0 0 4px #e9eff9;transform:translate(-50%,-50%)}.timeline-event.sent{left:28%;background:var(--orange);box-shadow:0 0 0 4px #fff2df}.timeline-event.state-off{background:#9aa6bc}.history-list{list-style:none;padding:0;margin:0;max-height:290px;overflow:auto}.history-row{display:grid;grid-template-columns:63px 10px 1fr auto;gap:12px;padding:12px 0;border-bottom:1px solid #f0f3f7;align-items:start}.history-row:last-child{border-bottom:0}.history-row time{font-size:13px;color:var(--muted);padding-top:2px}.history-dot{height:7px;width:7px;background:var(--navy);border-radius:50%;margin-top:7px}.history-row.sent .history-dot{background:var(--orange)}.history-row strong{font-size:14px;font-weight:600;display:block}.history-row small{font-size:13px;color:var(--muted);display:block}.history-kind{font-size:12px;color:var(--muted);background:#f5f7fa;border-radius:5px;padding:2px 5px}.empty{padding:20px;text-align:center;color:var(--muted);font-size:14px}.data-grid{display:grid;grid-template-columns:1.2fr 1fr;gap:20px}.chart-box{min-height:175px;background:#fafbfd;border:1px solid var(--line);border-radius:12px;padding:15px}.chart-box svg{display:block;width:100%;height:140px}.data-table{width:100%;border-collapse:collapse;font-size:14px}.data-table td{padding:11px 5px;border-bottom:1px solid var(--line)}.data-table td:first-child{color:var(--muted)}.data-table td:last-child{text-align:right;font-weight:600}.fineprint{font-size:13px;color:var(--muted);line-height:1.8;margin-top:13px}.footer{display:flex;justify-content:space-between;gap:20px;color:#97a1b2;font-size:13px;padding:24px 1px 0}.test-layout{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,.85fr);gap:22px}.test-cards{display:flex;flex-direction:column;gap:15px}.test-card{padding:22px;background:#fff;border:1px solid var(--line);border-radius:var(--radius)}.test-title{display:flex;gap:12px;align-items:center;margin-bottom:13px}.test-no{height:35px;width:35px;border-radius:11px;background:#eef2fa;color:var(--navy);font-size:14px;font-weight:700;display:grid;place-items:center}.test-title h3{font-size:17px}.test-title small{color:var(--muted);font-size:13px}.test-card p{font-size:14px;color:#6c7a91;line-height:1.8}.test-card .actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:16px}.test-card ol{font-size:14px;color:#6c7a91;padding-left:19px;margin:10px 0}.test-card code,.note code{background:#f0f3f8;padding:2px 5px;border-radius:4px;font-size:13px;color:var(--navy);overflow-wrap:anywhere}.note{background:#fff5e7;color:#916124;font-size:13px;padding:11px 13px;border-radius:10px;margin-top:12px;line-height:1.8}.inspector{background:white;border:1px solid var(--line);border-radius:var(--radius);align-self:start;overflow:hidden;position:sticky;top:20px}.inspector-head{padding:20px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line)}.inspector-body{padding:20px}.inspector label{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px}.inspector label:first-child{margin-top:0}.mono{font-family:"JetBrains Mono",Consolas,monospace;font-size:14px;overflow-wrap:anywhere;word-break:break-all}.payload-box{min-height:90px;background:#f4f7fc;border:1px solid #e3e9f3;border-radius:11px;padding:12px;color:var(--navy);line-height:1.8;white-space:pre-wrap}.packet-meta{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:14px 0}.packet-meta div{background:#f7f9fc;border-radius:9px;padding:9px 11px;font-size:13px;color:var(--muted)}.packet-meta strong{display:block;color:var(--ink);font-size:14px;margin-top:2px}.fields{margin-top:15px;border-top:1px solid var(--line)}.fields .mono{font-size:13px;color:#566887}.test-result{background:#eef3fb;border-radius:11px;padding:12px;font-size:14px;color:#48628a;margin-top:18px}.connection-error{margin-bottom:18px;background:#fff;border:1px dashed #d9e0ec;border-radius:11px;padding:9px 13px;color:#7a879b;font-size:14px}.hidden,[hidden]{display:none!important}.toast{position:fixed;bottom:24px;left:calc(50% + 100px);transform:translateX(-50%);max-width:min(530px,90vw);border-radius:13px;background:var(--navy);color:#fff;padding:13px 20px;font-size:14px;z-index:50;box-shadow:0 10px 40px #12265530}.toast.error{background:#a74638}.mobile-label{display:none}details{margin-top:16px}summary{color:var(--muted);font-size:14px;cursor:pointer}.metric-stale{color:#a1a8b5}
@media(min-width:1550px){.main{padding-top:38px}.hero{min-height:174px}.hero-content{padding:30px}.device-card{min-height:238px}}
@media(max-width:1100px){.sidebar{width:190px;padding:27px 13px}.app{margin-left:190px}.main{padding:25px}.topbar{padding:0 25px}.nav-btn{font-size:14px}.security-control{gap:9px;padding:10px}.security-control .icon{display:none}.device-card{padding:15px}.test-layout{gap:16px}.metric{padding:14px}.metric-label{font-size:13px}.hero{grid-template-columns:1fr 200px}.hero .house{width:195px}}
@media(max-width:800px){.sidebar{position:static;width:auto;height:auto;padding:15px 20px;border-right:0;border-bottom:1px solid var(--line);display:block}.brand{margin:0;padding:0}.brand-mark{height:35px;width:35px;border-radius:10px}.brand strong{font-size:16px}.brand .eyebrow{font-size:8px}.nav-title,.sidebar-bottom{display:none}.sidebar nav{display:flex;gap:8px;margin-top:17px}.nav-btn{width:auto;margin:0;padding:10px 15px;font-size:14px;flex:1;justify-content:center}.nav-btn .icon{width:17px;height:17px}.app{margin:0}.topbar{height:55px;padding:0 22px}.breadcrumb{font-size:13px}.status-group .clock{display:none}.main{padding:23px 20px}.page-head{align-items:flex-start;gap:15px}.page-head h1{font-size:24px}.page-head p{font-size:14px}.security-control{padding:8px 10px}.security-control small{display:none}.security-control strong{font-size:13px}.security-control .toggle{width:39px;height:23px}.security-control .toggle:after{width:17px;height:17px}.security-control .toggle[aria-checked="true"]:after{left:19px}.hero{grid-template-columns:1fr 150px}.hero .house{width:150px}.hero-content{padding:21px}.hero h2{font-size:20px}.test-layout{grid-template-columns:1fr}.inspector{position:static}.toast{left:50%}.footer{font-size:12px}.data-grid{grid-template-columns:1fr}}
@media(max-width:560px){.page-head{flex-wrap:wrap;margin-bottom:17px}.page-head h1{font-size:23px}.security-control{width:100%;justify-content:flex-start;padding:10px 13px}.security-control .icon{display:block;width:19px;height:19px}.security-control>div{flex:1}.security-control small{display:block;font-size:13px}.security-control strong{font-size:14px}.hero{grid-template-columns:1fr 92px;min-height:157px}.hero .house{width:135px;height:156px;transform:translateX(-17px);opacity:.65}.hero-content{padding:19px;min-width:0}.hero h2{font-size:18px}.hero p{font-size:13px}.hero-footer{flex-wrap:wrap;gap:6px;margin-top:10px;font-size:12px}.metrics{grid-template-columns:repeat(2,1fr);gap:10px}.metric{padding:14px 15px}.metric-value{font-size:25px}.device-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:11px}.device-card{min-height:226px;padding:15px}.device-card.primary{grid-column:1 / -1;min-height:203px}.device-card.primary .device-bottom{padding-top:13px}.device-card p{font-size:13px}.device-status{font-size:12px}.device-icon{width:42px;height:42px;border-radius:12px}.device-icon .icon{width:27px;height:27px}.panel-head{padding:14px;gap:8px;flex-wrap:wrap}.segmented{flex:1}.segmented button{flex:1;padding:8px 9px;font-size:13px}.panel-body{padding:15px}.legend{gap:8px;font-size:12px}.history-tools{flex-wrap:wrap}.history-row{grid-template-columns:51px 7px 1fr;gap:8px}.history-kind{display:none}.section-heading h2{font-size:16px}.section-heading .caption{font-size:12px}.footer{flex-direction:column;gap:4px}.topbar{padding:0 20px}.test-card,.inspector-body,.inspector-head{padding:17px}.test-card .btn{flex:1}.mode-note{font-size:13px;padding:10px 12px;margin-bottom:17px}.metrics .metric-foot{font-size:12px}}

/* Chỉ có thể dùng Söhne khi máy có font; fallback hệ thống không tải font ngoài. */
html{font-size:16px}body{font-size:1rem}button,input,select,textarea,code,pre,svg text{font-family:inherit}
.metric{min-width:0}.metric-label{line-height:1.45}.metric-foot{line-height:1.5}
.main,.panel,.panel-body,.data-grid,.chart-box{min-width:0}
.stats-block{border-top:1px solid var(--line);margin-top:22px;padding-top:20px}
.stats-toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.stats-toolbar select,.stats-toolbar input{padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--ink);font-size:14px;max-width:100%}
.stats-controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.stats-scroll{overflow-x:auto}.stats-table{width:100%;border-collapse:collapse;min-width:670px;font-size:14px}
.stats-table th,.stats-table td{padding:11px 12px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.stats-table th:first-child,.stats-table td:first-child{text-align:left}.stats-table th{background:#f4f7fb;color:var(--navy);font-weight:600}
@media(min-width:1700px){.metrics{grid-template-columns:repeat(6,minmax(0,1fr))}}
@media(max-width:1100px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:520px){.metrics{grid-template-columns:1fr}.stats-controls{width:100%}}
.metric.e2e{grid-column:1 / -1}
</style>
<link rel="stylesheet" href="/static/fonts.css"><link rel="stylesheet" href="/static/cycle_energy.css"><link rel="stylesheet" href="/static/typography.css"><link rel="stylesheet" href="/static/command_memory.css"></head>
<body>
<svg class="symbols" aria-hidden="true"><defs>
<symbol id="i-home" viewBox="0 0 24 24"><path d="m3 10 9-7 9 7v10a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1Z"/></symbol>
<symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></symbol>
<symbol id="i-bulb" viewBox="0 0 24 24"><path d="M8 15c-5-4-2-12 4-12s9 8 4 12l-1 3H9ZM9 21h6M10 18v-5m4 5v-5"/></symbol>
<symbol id="i-sensor" viewBox="0 0 24 24"><circle cx="12" cy="15" r="3"/><path d="M5 8a10 10 0 0 1 14 0M8 11a6 6 0 0 1 8 0M2 5a15 15 0 0 1 20 0M12 18v3"/></symbol>
<symbol id="i-wave" viewBox="0 0 24 24"><path d="M2 13h4l3-9 5 16 3-9h5"/></symbol>
<symbol id="i-chip" viewBox="0 0 24 24"><rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 2v3m6-3v3M9 19v3m6-3v3M2 9h3m-3 6h3m14-6h3m-3 6h3"/><rect x="9" y="9" width="6" height="6" rx="1"/></symbol>
<symbol id="i-bolt" viewBox="0 0 24 24"><path d="m13 2-8 12h6l-1 8 9-13h-6Z"/></symbol>
<symbol id="i-time" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/></symbol>
<symbol id="i-download" viewBox="0 0 24 24"><path d="M12 3v12m-4-4 4 4 4-4M4 16v5h16v-5"/></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.5"/></symbol>
</defs></svg>
<aside class="sidebar">
 <div class="brand"><span class="brand-mark"><svg class="icon"><use href="#i-shield"/></svg></span><div><strong>IoT Security</strong><div class="eyebrow">ESP32 · RESEARCH LAB</div></div></div>
 <div class="nav-title eyebrow">Không gian làm việc</div>
 <nav aria-label="Điều hướng chính"><button class="nav-btn active" data-page="control"><svg class="icon"><use href="#i-home"/></svg>Điều khiển thiết bị</button><button class="nav-btn" data-page="testing"><svg class="icon"><use href="#i-shield"/></svg>Kịch bản kiểm thử</button><button class="nav-btn" data-page="cycles"><svg class="icon"><use href="#i-bolt"/></svg>Năng lượng chu kỳ</button></nav>
 <div class="sidebar-bottom"><div class="user"><span class="avatar">A</span><div><strong style="font-size:12px">Nhóm nghiên cứu IoT</strong><small>An · Firmware & bảo mật</small></div></div><div class="lab-label">AES-128-GCM<br>Mô hình nhà thông minh</div></div>
</aside>
<div class="app">
 <header class="topbar"><div class="breadcrumb">Không gian IoT <span> / </span><b id="crumb">Điều khiển thiết bị</b></div><div class="status-group"><span class="clock" id="clock">UTC+7</span><span id="mqttBadge" class="status-chip"><i class="dot"></i><span>MQTT · Đang kiểm tra</span></span></div></header>
 <main class="main">
  <div class="page-head"><div><div class="eyebrow">SMART HOME / ESP32</div><h1 id="pageTitle">Điều khiển khóa điện tử</h1><p id="pageSubtitle">Trạng thái thiết bị, số đo và lịch sử trong một không gian.</p></div><div class="security-control"><svg class="icon"><use href="#i-shield"/></svg><div><strong id="modeTitle">AES-128-GCM</strong><small id="modeSubtitle">Mã hóa payload đang bật</small></div><button id="aesSwitch" class="toggle" role="switch" aria-checked="true" aria-label="Bật hoặc tắt mã hóa AES trên web"></button></div></div>
  <div class="mode-note" id="modeNote"><svg class="icon"><use href="#i-info"/></svg><span id="modeNoteText">Đang chờ ESP32 báo chế độ. Công tắc sẽ hoàn tất khi ESP32 xác nhận; TLS vẫn bật.</span></div>
  <div class="connection-error" id="connectionError" hidden></div>
  <section id="controlPage" aria-label="Điều khiển thiết bị">
   <div class="hero"><div class="hero-content"><div class="eyebrow">NHÀ THÔNG MINH · THIẾT BỊ 01</div><h2>Mỗi trạng thái đều có dấu vết.</h2><p>Theo dõi phản hồi từ ESP32 và lưu lại các lần điều khiển để đối chiếu khi kiểm thử.</p><div class="hero-footer"><span><i class="dot" id="deviceDot"></i><span id="deviceLiveness">Chưa có phản hồi ESP32</span></span><span>MQTT / TLS</span></div></div>
    <svg class="house" viewBox="0 0 260 180" fill="none" aria-hidden="true"><circle cx="155" cy="100" r="81" stroke="#5273a4" stroke-opacity=".35"/><circle cx="155" cy="100" r="61" stroke="#5273a4" stroke-opacity=".3"/><path d="m62 94 91-59 88 59" stroke="#7f9ac3" stroke-width="2"/><path d="M82 83v80h143V83" stroke="#5277ae" stroke-width="2"/><path d="M140 163v-60h42v60" stroke="#f4a441" stroke-width="2"/><rect x="98" y="98" width="24" height="26" rx="3" stroke="#7899c9" stroke-width="2"/><path d="M110 98v26m-12-13h24" stroke="#7899c9"/><circle cx="172" cy="135" r="2" fill="#f4a441"/><path d="m145 50 10-6 10 6v10c0 7-10 13-10 13s-10-6-10-13Z" fill="#f4a441"/><path d="m150 57 4 4 7-8" stroke="#15356e" stroke-width="2"/><path d="M57 164h185" stroke="#6e8bb8" stroke-width="2"/><circle cx="78" cy="48" r="3" fill="#f4a441"/><circle cx="225" cy="38" r="2" fill="#6e8bb8"/></svg>
   </div>
   <div class="metrics">
    <div class="metric"><div class="metric-label">Điện áp mẫu nguồn ESP32 · INA219<svg class="icon"><use href="#i-bolt"/></svg></div><div class="metric-value"><span id="voltage">—</span><small>V</small></div><div class="metric-foot" id="voltageNote">Chưa có dữ liệu cảm biến</div></div>
    <div class="metric"><div class="metric-label">Dòng điện mẫu ESP32 · INA219<svg class="icon"><use href="#i-wave"/></svg></div><div class="metric-value"><span id="current">—</span><small id="currentUnit">mA</small></div><div class="metric-foot" id="currentNote">Chưa có dữ liệu cảm biến</div></div>
    <div class="metric"><div class="metric-label">Công suất mẫu nguồn ESP32<svg class="icon"><use href="#i-bolt"/></svg></div><div class="metric-value"><span id="power">—</span><small id="powerUnit">W</small></div><div class="metric-foot" id="powerNote">Chưa có dữ liệu cảm biến</div></div>
    <div class="metric"><div class="metric-label">Xác thực–giải mã AES-GCM · ESP32<svg class="icon"><use href="#i-time"/></svg></div><div class="metric-value"><span id="decrypt">—</span><small>µs</small></div><div class="metric-foot" id="decryptNote">Chờ số đo từ firmware</div></div>
    <div class="metric"><div class="metric-label">Mã hóa AES-GCM · Python<svg class="icon"><use href="#i-shield"/></svg></div><div class="metric-value"><span id="encrypt">—</span><small>µs</small></div><div class="metric-foot" id="encryptNote">Chờ gửi lệnh có AES</div></div>
    <div class="metric"><div class="metric-label">Xử lý lệnh đến đặt GPIO · ESP32<svg class="icon"><use href="#i-time"/></svg></div><div class="metric-value"><span id="latency">—</span><small>ms</small></div><div class="metric-foot" id="latencyNote">Chờ ACK đúng mã lệnh từ ESP32</div></div>
    <div class="metric e2e"><div class="metric-label">Độ trễ điều khiển đầu-cuối · End-to-End Control Latency<svg class="icon"><use href="#i-time"/></svg></div><div class="metric-value"><span id="e2e">—</span><small>ms</small></div><div class="metric-foot" id="e2eNote">Chờ lệnh từ web và ACK xác nhận đặt GPIO</div></div>
   </div>
   <p class="hardware-note" id="sensorState">Đang chờ số đo INA219 từ ESP32</p>
   <!-- COMMAND_MEMORY_PANEL -->
   <div class="section-heading"><h2><span class="section-number">01</span>Khóa điện tử</h2><span class="pill">Điều khiển thủ công</span></div>
   <div class="device-grid">
    <article class="device-card primary"><div class="card-top"><div class="device-icon orange"><svg class="icon"><use href="#i-lock"/></svg></div><span id="doorStatus" class="device-status"><i class="dot"></i><span>Chưa xác nhận</span></span></div><h3>Khóa cửa chính</h3><p>Solenoid 12V · Mặc định khóa · Giữ trạng thái theo công tắc · Bíp khi mở / khóa</p><div class="device-bottom"><span class="state-text" id="doorAction">Đang chờ trạng thái khóa</span><button class="toggle send-btn" id="doorSwitch" role="switch" aria-label="Mở khóa hoặc khóa lại" aria-describedby="doorAction doorLast" aria-checked="false" disabled></button></div><p id="doorLast" style="margin-top:12px">Đang chờ trạng thái do ESP32 báo.</p></article>
   </div>
   <p class="hardware-note">Trạng thái khóa dựa trên relay do ESP32 báo. Chưa có cảm biến xác nhận vị trí chốt hoặc cửa thực tế.</p>
   <div class="panel"><div class="panel-head"><div class="segmented" role="tablist" aria-label="Lịch sử và số đo"><button class="active" id="historyTab" role="tab" aria-selected="true">Lịch sử hoạt động</button><button id="measureTab" role="tab" aria-selected="false">Thông số đo</button></div><a id="exportCsv" class="btn small" href="/api/history.csv"><svg class="icon"><use href="#i-download"/></svg>Xuất CSV</a></div>
    <div class="panel-body" id="historyPane"><div class="history-tools"><div class="date-control"><button id="prevDate" aria-label="Ngày trước">‹</button><input type="date" id="historyDate" aria-label="Ngày xem lịch sử"><button id="nextDate" aria-label="Ngày tiếp theo">›</button></div><div class="legend"><span><i class="sent"></i>Lệnh gửi</span><span><i></i>ESP32 phản hồi</span></div></div><div class="timeline"><div class="timeline-axis"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>24:00</span></div><div class="timeline-area" id="timeline"><span class="timeline-empty">Chưa có sự kiện trong ngày đã chọn.</span></div></div><ul class="history-list" id="historyList"><li class="empty">Chưa có sự kiện.</li></ul><p class="fineprint">Mốc thời gian là lúc web gửi lệnh hoặc nhận MQTT, hiển thị UTC+7. Lệnh đã gửi không đồng nghĩa thiết bị đã thực thi. Hiển thị tối đa 500 sự kiện/ngày; CSV xuất tối đa 100.000.</p></div>
    <div class="panel-body" id="measurePane" hidden><div class="data-grid"><div class="chart-box"><div class="metric-label">Điện áp gần đây · V<span>Telemetry thực</span></div><svg id="voltageChart" viewBox="0 0 400 145" role="img" aria-label="Đồ thị điện áp"><text x="200" y="80" text-anchor="middle" fill="#94a1b6" font-size="12">Chưa nhận dữ liệu INA219</text></svg></div><table class="data-table"><tbody><tr><td>Heap trống hệ thống · ESP32</td><td id="heapValue">—</td></tr><tr><td>Xác thực–giải mã AES-GCM · ESP32</td><td id="decryptValue">—</td></tr><tr><td>Mã hóa AES-GCM · Python</td><td id="encryptValue">—</td></tr><tr><td>Xử lý lệnh đến đặt GPIO · ESP32</td><td id="latencyValue">—</td></tr><tr><td>Độ trễ điều khiển đầu-cuối · E2E</td><td id="e2eValue">—</td></tr><tr><td>Đóng gói AES · Python</td><td id="pythonValue">—</td></tr><tr><td>Chế độ AES · ESP32 báo</td><td id="firmwareMode">Chưa có dữ liệu</td></tr></tbody></table></div>
     <div class="stats-block"><div class="stats-toolbar"><h3>Thống kê số liệu</h3><div class="stats-controls"><input type="date" id="statsDate" aria-label="Ngày thống kê"><select id="statsMode" aria-label="Lọc chế độ AES"><option value="all">Tất cả chế độ</option><option value="on">AES bật</option><option value="off">AES tắt</option></select><a class="btn small" id="exportMeasurements" href="/api/performance.csv"><svg class="icon"><use href="#i-download"/></svg>CSV số đo</a></div></div><div class="stats-scroll"><table class="stats-table"><thead><tr><th>Thông số</th><th>Đơn vị</th><th>N</th><th>Gần nhất</th><th>Min</th><th>Trung bình</th><th>P95</th><th>Max</th></tr></thead><tbody id="statsBody"><tr><td colspan="8">Chưa có số liệu thực.</td></tr></tbody></table></div><p class="fineprint" id="statsNote">Thống kê tối đa 2.000 bản ghi gần nhất trong ngày. Mỗi thông số có số mẫu N riêng.</p></div>
</div>
   </div>
  </section>
  <section id="testingPage" hidden aria-label="Kịch bản kiểm thử bảo mật">
   <div class="section-heading" style="margin-top:0"><h2>Ba kịch bản bảo mật</h2><span class="caption">Mỗi thao tác gửi một gói · retain=false</span></div>
   <div class="test-layout"><div class="test-cards">
    <article class="test-card"><div class="test-title"><span class="test-no">01</span><div><h3>Nghe lén</h3><small>Eavesdropping · Quan sát dữ liệu truyền</small></div></div><p>So sánh payload khi AES bật và tắt. MQTT.fx subscribe topic điều khiển để xem dữ liệu ở tầng ứng dụng; Wireshark quan sát kết nối MQTT/TLS.</p><ol><li>Gửi mẫu OFF theo chế độ AES đang chọn.</li><li>Xem payload trong MQTT.fx hoặc khung bên phải.</li><li>Đối chiếu với Wireshark: <code>tcp.port == 8883</code>.</li></ol><div class="actions"><button class="btn navy send-btn" data-scenario="sniff" data-cmd="OFF">Gửi mẫu OFF</button><button class="btn" id="copyTopic">Sao chép topic</button></div><div class="note">TLS vẫn mã hóa đường truyền khi AES tắt. Gói TLS khó đọc chưa chứng minh riêng tác dụng AES. Hướng dẫn kèm theo có cách giải mã phiên TLS của chính web trong lab.</div></article>
    <article class="test-card"><div class="test-title"><span class="test-no">02</span><div><h3>Giả mạo dữ liệu</h3><small>Spoofing / Tampering · Kiểm tra Authentication Tag</small></div></div><p id="tamperDescription">Đảo một bit ciphertext của lệnh ON, giữ nguyên Tag. ESP32 cần từ chối gói tin và không thực thi lệnh ON.</p><div class="actions"><button class="btn orange send-btn" data-scenario="tamper" data-cmd="ON" id="tamperButton">Gửi gói ON bị sửa</button></div><p class="fineprint">Đối chiếu với Serial Monitor hoặc phản hồi AUTH_FAIL từ firmware. Web không tự đánh dấu “đã chặn” chỉ vì đã gửi mẫu.</p></article>
    <article class="test-card"><div class="test-title"><span class="test-no">03</span><div><h3>Phát lại lệnh cũ</h3><small>Replay Attack · Kiểm tra tính mới của bản tin</small></div></div><p>Lấy nguyên payload của lần gửi thường gần nhất và publish lại bằng MQTT.fx. Nonce, timestamp và ciphertext được giữ nguyên.</p><div class="note" id="replayInfo">Chưa có mẫu. Hãy gửi ON/OFF hợp lệ hoặc mẫu OFF ở kịch bản 1.</div><div class="actions"><button class="btn" id="copyReplay" disabled><svg class="icon"><use href="#i-copy"/></svg>Copy cho MQTT.fx</button><button class="btn navy send-btn" id="replayButton" data-scenario="replay" data-cmd="ON" disabled>Phát lại từ web</button></div><p class="fineprint">Thử cả gửi lại ngay và sau hơn 10 giây. Firmware hiện tại kiểm tra timestamp ±10 giây; chưa loại bỏ nonce đã dùng, nên replay trong cửa sổ có thể vẫn được nhận.</p></article>
    <details><summary>Kiểm tra bổ sung: giới hạn kích thước</summary><div class="test-card" style="margin-top:10px"><p>Gửi một payload chứa 200 ký tự A. Với AES bật: 236 byte nhị phân / 472 ký tự HEX. Theo mqtt_app.c hiện tại, gói bị chặn ở giới hạn 256 ký tự trước khi giải mã.</p><div class="actions"><button class="btn send-btn" data-scenario="oversize" data-cmd="OFF">Gửi mẫu vượt giới hạn</button></div></div></details>
   </div><aside class="inspector"><div class="inspector-head"><h3>Gói tin gần nhất</h3><span class="pill" id="packetMode">Chưa có gói</span></div><div class="inspector-body"><label>TOPIC ĐIỀU KHIỂN</label><div class="mono">device/esp32/control</div><label>PAYLOAD PUBLISH</label><div class="payload-box mono" id="packetPayload">Gửi một mẫu để xem dữ liệu.</div><div class="actions" style="margin-top:10px;display:flex;gap:8px"><button class="btn small" id="copyPacket" disabled><svg class="icon"><use href="#i-copy"/></svg>Sao chép</button><button class="btn small" id="downloadPacket" disabled>Tải JSON</button></div><div class="packet-meta"><div>Độ dài gửi<strong id="packetLength">—</strong></div><div>Thời điểm gửi<strong id="packetTime">—</strong></div></div><div class="fields"><label>NONCE · 12 BYTE</label><div class="mono" id="packetNonce">—</div><label>AUTHENTICATION TAG · 16 BYTE</label><div class="mono" id="packetTag">—</div><label>TIMESTAMP / AAD · 8 BYTE</label><div class="mono" id="packetAad">—</div><label>CIPHERTEXT</label><div class="mono" id="packetCt">—</div></div><div class="test-result" id="testResult" role="status">Chưa thực hiện thao tác kiểm thử.</div><p class="fineprint">Gói ở đây là dữ liệu do web gửi, không phải kết quả bắt gói Wireshark. Lưu kèm log ESP32 khi đánh giá.</p></div></aside></div>
  </section>
  <!-- CYCLE_ENERGY_PANEL -->
  <footer class="footer"><span>IoT Security Lab · AES-128-GCM · ESP32</span><span>Thông tin thiết bị lấy từ MQTT · Dữ liệu thiếu hiển thị “—”</span></footer>
</main>
</div><div class="toast" id="toast" role="status" hidden></div>
<script>
const CSRF={{ csrf|tojson }};
const $=id=>document.getElementById(id);
let state=null,activePage='control',pending=false,toastTimer=null,historySignature='';
const timefmt=new Intl.DateTimeFormat('vi-VN',{timeZone:'Asia/Ho_Chi_Minh',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
const shortTime=ts=>ts?timefmt.format(new Date(ts*1000)):'—';
const num=(v,d=2)=>typeof v==='number'?new Intl.NumberFormat('vi-VN',{maximumFractionDigits:d}).format(v):'—';
const age=ts=>ts?Math.max(0,Math.floor((state?.server_time||Date.now()/1000)-ts)):null;
function toast(msg,error=false){$('toast').textContent=msg;$('toast').classList.toggle('error',error);$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,6500)}
async function api(url,data){const res=await fetch(url,{method:data===undefined?'GET':'POST',headers:data===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:data===undefined?undefined:JSON.stringify(data)});const result=await res.json();if(!res.ok)throw Error(result.error||'Yêu cầu không thành công.');return result}
function node(tag,cls,text){const el=document.createElement(tag);if(cls)el.className=cls;if(text!==undefined)el.textContent=text;return el}
function switchPage(page){activePage=page;for(const key of ['control','testing','cycles'])$(key+'Page').hidden=page!==key;document.querySelectorAll('[data-page]').forEach(b=>b.classList.toggle('active',b.dataset.page===page));const titles={cycles:['Năng lượng chu kỳ','Năng lượng bo ESP32 theo chu kỳ ON/OFF','Cùng số lệnh · AES bật/tắt · Gửi tuần tự theo ACK.'],control:['Điều khiển thiết bị','Điều khiển khóa điện tử','Trạng thái thiết bị, số đo và lịch sử trong một không gian.'],testing:['Kịch bản kiểm thử','Kiểm thử bảo mật IoT','Quan sát, thay đổi và phát lại bản tin trong hệ thống thí nghiệm.']};$('crumb').textContent=titles[page][0];$('pageTitle').textContent=titles[page][1];$('pageSubtitle').textContent=titles[page][2];if(page==='cycles'&&typeof refreshCycles==='function')refreshCycles();}
document.querySelectorAll('[data-page]').forEach(b=>b.onclick=()=>switchPage(b.dataset.page));
// Scale only the displayed current; telemetry/SQLite/CSV keep the measured mA.
function currentDisplay(value){
 const valid=typeof value==='number'&&Number.isFinite(value);
 const micro=valid&&Math.abs(value)<1;
 return {value:valid?(micro?value*1000:value):null,unit:micro?'µA':'mA',dec:micro?0:1};
}
function powerDisplay(value){
 const valid=typeof value==='number'&&Number.isFinite(value);
 const milli=valid&&Math.abs(value)<1;
 return {value:valid?(milli?value*1000:value):null,unit:milli?'mW':'W',dec:milli?1:2};
}
function sensorStatusText(d){
 if(d.sensor_ts&&age(d.sensor_ts)>5)return 'INA219: dữ liệu cũ / mất cập nhật';
 if(d.sensor_ok===true)return 'INA219 đang gửi số đo · SDA25 / SCL26';
 if(d.sensor_ok!==false)return 'Đang chờ số đo INA219 từ ESP32';
 const diag=d.sensor_diagnostics||{};
 const stages={write_config:'Không ghi được cấu hình qua I²C',read_bus:'Không đọc được thanh ghi điện áp qua I²C',read_shunt:'Không đọc được thanh ghi shunt qua I²C',conversion_timeout:'Cảm biến chưa hoàn tất chuyển đổi',math_overflow:'Cờ OVF của INA219 đang bật',shunt_out_of_range:'Điện áp shunt ngoài dải ±320 mV'};
 const code=d.sensor_error+(diag.sensor_error_name?' / '+diag.sensor_error_name:'');
 const reason=stages[diag.sensor_stage]||'Firmware chưa báo bước đọc bị lỗi';
 const raw=['bus_raw','shunt_raw'].filter(k=>typeof diag[k]==='number'&&diag[k]>=0).map(k=>k+'=0x'+diag[k].toString(16).padStart(4,'0')).join(', ');
 return 'INA219 lỗi ('+code+'): '+reason+'. '+(raw?raw+'. ':'')+'Kiểm tra VCC=3V3, GND, SDA25/SCL26 và địa chỉ 0x40.';
}
function metric(field,id,note,dec=2){const m=state.metrics[field];let value=m?.value;if(field==='current_ma'){const display=currentDisplay(value);value=display.value;dec=display.dec;$('currentUnit').textContent=display.unit;}else if(field==='power_w'){const display=powerDisplay(value);value=display.value;dec=display.dec;$('powerUnit').textContent=display.unit;}$(id).textContent=num(value,dec);$(id).classList.toggle('metric-stale',m&&age(m.ts)>30);$(note).textContent=m?'Nhận '+shortTime(m.ts)+(age(m.ts)>30?' · Dữ liệu cũ':' · Từ ESP32'):'Chưa có dữ liệu từ ESP32'}
function renderTimings(){
 const p=state.latest_packet,l=state.latency||{};
 const enc=p?.encrypted&&state.aes_enabled&&p.scenario!=='replay'?p.encrypt_us:null;
 $('encrypt').textContent=num(enc,1);$('encryptValue').textContent=enc==null?'—':num(enc,1)+' µs';
 $('encrypt').classList.toggle('metric-stale',enc!=null&&age(p.sent_at)>30);
 $('encryptNote').textContent=!state.aes_enabled?'AES tắt · Không mã hóa':!p?'Chờ gửi lệnh có AES':p.scenario==='replay'?'Replay · Dùng lại gói cũ':enc!=null?'Đo '+shortTime(p.sent_at)+' · Trên Python':'Chưa có số đo mã hóa';
 const measured=l.status==='measured';$('latency').textContent=measured?num(l.value_ms,2):'—';
 $('latencyValue').textContent=measured?num(l.value_ms,2)+' ms':'—';
 $('latency').classList.toggle('metric-stale',measured&&age(l.ts)>30);
 const notes={missing:'ESP32 đã đặt GPIO nhưng chưa gửi số đo · Cần cập nhật firmware',idle:'Chờ ACK đúng mã lệnh từ ESP32',pending:'Đang chờ ESP32 đặt GPIO và trả ACK…',timeout:'Quá 8s chưa có xác nhận thực thi',rejected:'ESP32 từ chối thực thi · Chưa có số đo',failed:'Gửi MQTT thất bại · Chưa có số đo',test:'Mẫu kiểm thử · Không tính thời gian thực thi'};
 $('latencyNote').textContent=measured?'Nhận đủ MQTT → đặt GPIO · '+shortTime(l.ts)+(age(l.ts)>30?' · Dữ liệu cũ':''):notes[l.status]||notes.idle;
 const e=state.end_to_end||{},done=e.status==='measured';
 $('e2e').textContent=done?num(e.value_ms,2):'—';
 $('e2eValue').textContent=done?num(e.value_ms,2)+' ms':'—';
 $('e2e').classList.toggle('metric-stale',done&&age(e.ts)>30);
 const e2eNotes={idle:'Chờ lệnh từ web và ACK xác nhận đặt GPIO',pending:'Đang đo từ Python chuẩn bị lệnh đến ACK xác nhận GPIO…',timeout:'Quá 8s từ lúc gửi chưa có ACK · Không có số đo E2E',rejected:'ESP32 từ chối lệnh · Không có số đo E2E',failed:'Gửi MQTT thất bại · Không có số đo E2E',test:'Mẫu kiểm thử · Không đo E2E',missing:'ACK chưa có mốc bắt đầu E2E hợp lệ'};
 $('e2eNote').textContent=done?'Python chuẩn bị lệnh → ACK đặt GPIO · '+shortTime(e.ts)+(age(e.ts)>30?' · Dữ liệu cũ':''):e2eNotes[e.status]||e2eNotes.idle;
}
let statsLastFetch=0,statsBusy=false;
async function refreshStatistics(force=false){
 if(!state||statsBusy||(!force&&Date.now()-statsLastFetch<5000))return;
 statsBusy=true;
 try{
  if(!$('statsDate').value)$('statsDate').value=state.today;
  const query=new URLSearchParams({date:$('statsDate').value,mode:$('statsMode').value});
  $('exportMeasurements').href='/api/performance.csv?'+query;
  const r=await api('/api/performance?'+query);$('statsBody').replaceChildren();
  for(const row of r.stats){const tr=document.createElement('tr');for(const value of [row.label,row.unit,String(row.n),num(row.last,2),num(row.min,2),num(row.mean,2),num(row.p95,2),num(row.max,2)]){const td=document.createElement('td');td.textContent=value;tr.appendChild(td)}$('statsBody').appendChild(tr)}
  $('statsNote').textContent=r.row_count+'/'+r.limit+' bản ghi gần nhất trong ngày · '+r.applied+' lệnh có ACK · '+r.timeouts+' lệnh hết hạn ACK. N tính riêng từng thông số; chỉ dùng số đo hợp lệ và lệnh đã thực thi. CSV tối đa 100.000 bản ghi.';
  statsLastFetch=Date.now();
 }catch(e){$('statsNote').textContent='Chưa lấy được thống kê: '+e.message}finally{statsBusy=false}
}
function render(){const s=state,d=s.device;const online=s.mqtt.connected&&!s.mqtt.offline;$('clock').textContent=shortTime(s.server_time)+' · UTC+7';$('mqttBadge').classList.toggle('live',online);$('mqttBadge').querySelector('span').textContent=s.mqtt.offline?'MQTT · Xem offline':online?'MQTT · Đã kết nối':'MQTT · Chưa kết nối';$('connectionError').hidden=!s.mqtt.error&&!s.mqtt.offline;$('connectionError').textContent=s.mqtt.offline?'Đang xem offline. Web không kết nối broker và không phát lệnh.':s.mqtt.error||'';$('aesSwitch').setAttribute('aria-checked',s.aes_enabled);$('modeTitle').textContent=s.aes_enabled?'AES-128-GCM':'Plaintext · AES tắt';$('modeSubtitle').textContent=s.aes_enabled?'Mã hóa payload đang bật':'Gửi trực tiếp chữ ON / OFF';$('modeNote').classList.toggle('warn',!s.aes_enabled);let note=s.mode_pending?'Đang chờ ESP32 xác nhận đổi chế độ AES…':!s.mode_ready?'Chưa nhận chế độ ESP32. Cần nạp firmware mới, cùng khóa AES và quyền topic config/aes.':'ESP32 đã báo AES '+(d.aes_enabled?'BẬT':'TẮT')+'. Công tắc đổi chế độ hai phía có xác nhận; TLS vẫn bật.';$('modeNoteText').textContent=note;$('deviceLiveness').textContent=d.recent?'Vừa nhận phản hồi ESP32':d.last_seen?'Chưa có phản hồi gần đây · '+shortTime(d.last_seen):'Chưa có phản hồi ESP32';$('deviceDot').style.background=d.recent?'#73d9b8':'#a6b6d1';$('doorStatus').querySelector('span').textContent=d.relay_on===null?'Chưa xác nhận':d.relay_on?'Đang mở khóa · Relay ON':'Đang khóa · Relay OFF';$('doorStatus').classList.toggle('on',d.relay_on===true);$('doorSwitch').setAttribute('aria-checked',d.relay_on===true);$('doorSwitch').setAttribute('aria-busy',s.control_pending?'true':'false');$('doorAction').textContent=s.control_pending?'Đang chờ ESP32 xác nhận…':d.relay_on===null?'Chờ ESP32 xác nhận trạng thái':d.relay_on?'Đang mở khóa · Gạt để khóa lại':'Đang khóa · Gạt để mở khóa';$('doorLast').textContent=d.state_ts?'ESP32 báo lúc '+shortTime(d.state_ts)+(age(d.state_ts)>30?' · Trạng thái gần nhất':''):'Đang chờ trạng thái do ESP32 báo.';$('sensorState').textContent=sensorStatusText(d);metric('voltage_v','voltage','voltageNote');metric('current_ma','current','currentNote',1);metric('power_w','power','powerNote');metric('decrypt_us','decrypt','decryptNote',0);if(d.aes_enabled===false)$('decryptNote').textContent='AES tắt · Không thực hiện giải mã';$('heapValue').textContent=state.metrics.heap_free_bytes?num(state.metrics.heap_free_bytes.value/1024,1)+' KiB':'—';$('decryptValue').textContent=state.metrics.decrypt_us?num(state.metrics.decrypt_us.value,0)+' µs':'—';$('pythonValue').textContent=state.latest_packet?.publisher_processing_us!=null?num(state.latest_packet.publisher_processing_us,1)+' µs':'—';$('firmwareMode').textContent=d.aes_enabled===null?'Chưa có dữ liệu':(d.aes_enabled?'AES bật':'AES tắt')+' · '+shortTime(d.aes_ts);$('tamperDescription').textContent=s.aes_enabled?'Đảo một bit ciphertext của lệnh ON, giữ nguyên Tag. ESP32 cần từ chối gói tin và không thực thi lệnh ON.':'Đối chứng AES tắt: gửi trực tiếp ON như một bên có quyền publish MQTT nhưng không có khóa AES. Firmware plaintext có thể thực thi lệnh.';$('tamperButton').textContent=s.aes_enabled?'Gửi gói ON bị sửa':'Gửi ON thuần · Đối chứng';const rp=s.replay_packet;$('replayInfo').textContent=rp?'Mẫu '+rp.command+' · '+(rp.encrypted?'AES-128-GCM':'Plaintext')+' · tạo '+shortTime(rp.created_at)+' · '+age(rp.created_at)+' giây trước.'+(rp.encrypted?'':' Plaintext không có Nonce/Timestamp.'): 'Chưa có mẫu. Hãy gửi ON/OFF hợp lệ hoặc mẫu OFF ở kịch bản 1.';const ready=online&&!s.cycle_energy_active&&s.mode_ready&&!s.mode_pending&&d.aes_enabled===s.aes_enabled;document.querySelectorAll('.send-btn').forEach(b=>b.disabled=!ready||pending);$('doorSwitch').disabled=!ready||pending||s.control_pending||typeof d.relay_on!=='boolean'||!d.state_ts||age(d.state_ts)>30||!d.recent;$('replayButton').disabled=!ready||pending||!rp;$('copyReplay').disabled=!rp;$('aesSwitch').disabled=pending||!online||!s.mode_ready||s.mode_pending||s.cycle_energy_active;renderTimings();renderPacket(s.latest_packet);renderChart(s.samples);refreshStatistics()}
function renderPacket(p){if(!p)return;$('packetMode').textContent=p.encrypted?'AES-128-GCM':'Plaintext';$('packetPayload').textContent=p.payload;$('packetLength').textContent=p.payload_chars+' ký tự';$('packetTime').textContent=shortTime(p.sent_at);$('packetNonce').textContent=p.nonce||'Không dùng';$('packetTag').textContent=p.tag||'Không dùng';$('packetAad').textContent=p.aad?(p.aad+' · epoch '+p.timestamp):'Không dùng';$('packetCt').textContent=p.ciphertext||'Không dùng';$('copyPacket').disabled=false;$('downloadPacket').disabled=false}
function renderChart(samples){const svg=$('voltageChart');svg.replaceChildren();const vals=samples.filter(s=>Number.isFinite(s.voltage_v));const ns='http://www.w3.org/2000/svg';function el(tag,attrs,txt){const e=document.createElementNS(ns,tag);Object.entries(attrs).forEach(([k,v])=>e.setAttribute(k,v));if(txt)e.textContent=txt;svg.append(e);return e}if(vals.length<2){el('text',{x:200,y:80,'text-anchor':'middle',fill:'#94a1b6','font-size':12},vals.length?'Cần thêm một số đo để vẽ đồ thị':'Chưa nhận dữ liệu INA219');return}let low=Math.min(...vals.map(s=>s.voltage_v)),high=Math.max(...vals.map(s=>s.voltage_v));if(high-low<.1){low-=.05;high+=.05}const minT=vals[0].ts,maxT=Math.max(minT+.001,vals.at(-1).ts);el('line',{x1:35,y1:115,x2:390,y2:115,stroke:'#e1e8f1'});el('text',{x:0,y:22,fill:'#8d9ab0','font-size':10},num(high));el('text',{x:0,y:114,fill:'#8d9ab0','font-size':10},num(low));el('polyline',{points:vals.map(s=>(35+(s.ts-minT)/(maxT-minT)*350)+','+(115-(s.voltage_v-low)/(high-low)*95)).join(' '),fill:'none',stroke:'#173e83','stroke-width':2,'stroke-linejoin':'round'});el('text',{x:35,y:138,fill:'#8d9ab0','font-size':9},shortTime(minT));el('text',{x:390,y:138,fill:'#8d9ab0','font-size':9,'text-anchor':'end'},shortTime(maxT))}
async function refreshHistory(){const day=$('historyDate').value;if(!day)return;const r=await api('/api/history?date='+encodeURIComponent(day));$('exportCsv').href='/api/history.csv?date='+encodeURIComponent(day);const signature=day+':'+r.events.map(e=>e.id).join(',');if(signature===historySignature)return;historySignature=signature;const list=$('historyList'),timeline=$('timeline');list.replaceChildren();timeline.replaceChildren();if(!r.events.length){list.append(node('li','empty','Chưa có sự kiện trong ngày này.'));timeline.append(node('span','timeline-empty','Chưa có sự kiện trong ngày đã chọn.'));return}timeline.append(node('span','timeline-caption','Mốc lệnh gửi / phản hồi · không suy diễn thời gian chạy'));for(const e of r.events){const sent=['COMMAND','TEST','MODE'].includes(e.kind);const li=node('li','history-row'+(sent?' sent':''));li.append(node('time','',shortTime(e.ts)),node('span','history-dot'));const content=node('div');content.append(node('strong','',e.title),node('small','',e.detail));li.append(content,node('span','history-kind',e.kind==='DEVICE'?'ESP32':sent?'WEB':'HỆ THỐNG'));list.append(li);if(['COMMAND','TEST','DEVICE'].includes(e.kind)){const marker=node('span','timeline-event'+(sent?' sent':'')+(e.relay_state===0?' state-off':''));const d=new Date(e.ts*1000+7*3600*1000);const minute=d.getUTCHours()*60+d.getUTCMinutes()+d.getUTCSeconds()/60;marker.style.top=(14+minute/1440*148)+'px';marker.title=shortTime(e.ts)+' · '+e.title;timeline.append(marker)}}}
async function refresh(){
 try{state=await api('/api/state')}catch(e){$('connectionError').hidden=false;$('connectionError').textContent='Lỗi API trạng thái: '+e.message;document.querySelectorAll('.send-btn').forEach(b=>b.disabled=true);$('aesSwitch').disabled=true;return}
 try{if(!$('historyDate').value)$('historyDate').value=state.today;render()}catch(e){console.error(e);$('connectionError').hidden=false;$('connectionError').textContent='Lỗi hiển thị: '+e.message;document.querySelectorAll('.send-btn').forEach(b=>b.disabled=true);$('aesSwitch').disabled=true;return}
 try{await refreshHistory()}catch(e){console.error(e);$('connectionError').hidden=false;$('connectionError').textContent='Lỗi tải lịch sử: '+e.message+'; trạng thái vẫn đang cập nhật.'}
}
async function send(scenario,command){if(pending)return;pending=true;render();try{const r=await api('/api/control',{scenario,command});$('testResult').textContent=r.message;toast(r.message);await refresh()}catch(e){toast(e.message,true);$('testResult').textContent=e.message}finally{pending=false;if(state)render()}}
document.querySelectorAll('[data-scenario]').forEach(b=>b.onclick=()=>send(b.dataset.scenario,b.dataset.cmd));$('doorSwitch').onclick=()=>{if(!state||$('doorSwitch').disabled||typeof state.device.relay_on!=='boolean')return;send('control',state.device.relay_on?'OFF':'ON')};$('aesSwitch').onclick=async()=>{if(!state||pending)return;pending=true;render();try{await api('/api/mode',{enabled:!state.aes_enabled});await refresh();toast('ESP32 đã xác nhận chế độ AES mới. Có thể kiểm thử MQTT.fx.')}catch(e){toast(e.message,true);await refresh()}finally{pending=false;if(state)render()}};

async function copy(text){try{await navigator.clipboard.writeText(text);toast('Đã sao chép.')}catch{toast('Trình duyệt không cho sao chép tự động; chọn và copy chuỗi trong khung payload.',true)}}$('copyTopic').onclick=()=>copy('device/esp32/control');$('copyPacket').onclick=()=>state?.latest_packet&&copy(state.latest_packet.payload);$('copyReplay').onclick=()=>state?.replay_packet&&copy(state.replay_packet.payload);$('downloadPacket').onclick=()=>{if(!state?.latest_packet)return;const blob=new Blob([JSON.stringify(state.latest_packet,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='mqtt_packet_'+state.latest_packet.id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)};
function panes(which){$('historyPane').hidden=which!=='history';$('measurePane').hidden=which!=='measure';for(const [key,id] of [['history','historyTab'],['measure','measureTab']]){$(id).classList.toggle('active',key===which);$(id).setAttribute('aria-selected',key===which)}}$('historyTab').onclick=()=>panes('history');$('measureTab').onclick=()=>{panes('measure');refreshStatistics(true)};$('statsDate').onchange=()=>refreshStatistics(true);$('statsMode').onchange=()=>refreshStatistics(true);$('historyDate').onchange=()=>refreshHistory().catch(e=>toast(e.message,true));function moveDay(delta){const d=new Date($('historyDate').value+'T12:00:00Z');d.setUTCDate(d.getUTCDate()+delta);$('historyDate').value=d.toISOString().slice(0,10);refreshHistory().catch(e=>toast(e.message,true))}$('prevDate').onclick=()=>moveDay(-1);$('nextDate').onclick=()=>moveDay(1);
document.querySelectorAll('.send-btn').forEach(b=>b.disabled=true);
(async function poll(){await refresh();setTimeout(poll,2000)})();
</script><script src="/static/cycle_energy.js"></script><script src="/static/command_memory.js"></script></body></html>

'''


HTML_TEMPLATE = HTML_TEMPLATE.replace("<!-- CYCLE_ENERGY_PANEL -->", (BASE / "cycle_energy_panel.html").read_text(encoding="utf-8"))

HTML_TEMPLATE = HTML_TEMPLATE.replace("<!-- COMMAND_MEMORY_PANEL -->", (BASE / "command_memory_panel.html").read_text(encoding="utf-8"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ESP32 AES-128-GCM Dashboard")
    parser.add_argument("--offline", action="store_true", help="Xem UI, không kết nối MQTT")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    app = create_app(connect=not args.offline)
    app.extensions["dashboard"].offline = args.offline
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False, threaded=True)
