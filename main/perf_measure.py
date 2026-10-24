#!/usr/bin/env python3
"""Đo batch lệnh AES ON/OFF và (tùy chọn) phiên năng lượng trên firmware Perf.

Mỗi batch được đánh dấu trong bảng events để phân tích đúng cửa sổ thời gian.
DB mặc định tách khỏi iot_history.sqlite3.
"""
import argparse
import json
import math
import sqlite3
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import web_server as ws

METRIC_NAMES = ("encrypt_us", "decrypt_us", "execution_ms", "rtt_ms", "e2e_ms")


def stamp():
    return time.time()


def log(message):
    print(message, flush=True)


def wait_ready(dashboard, timeout=90):
    deadline = stamp() + timeout
    last_query = 0.0
    while stamp() < deadline:
        if dashboard.connected and stamp() - last_query >= 5:
            dashboard.request_mode_state()
            last_query = stamp()
        if (dashboard.connected and dashboard.last_seen
                and stamp() - dashboard.last_seen < 10
                and dashboard.mode_challenge
                and dashboard.firmware_aes is not None
                and type(dashboard.last_state) is bool
                and dashboard.sensor_ok is True):
            return
        time.sleep(0.5)
    raise TimeoutError("Thiết bị chưa sẵn sàng (MQTT/chế độ/trạng thái/INA219).")


def read_outcome(dashboard, command_id):
    with dashboard.store.lock:
        row = dashboard.store.db.execute(
            "SELECT outcome FROM measurements WHERE command_id=?", (command_id,)).fetchone()
    return row["outcome"] if row else None


def send_wait(dashboard, command, timeout=9.5):
    packet = dashboard.send("control", command)
    command_id = packet["command_id"]
    deadline = stamp() + timeout
    while command_id in dashboard.pending_commands and stamp() < deadline:
        if not dashboard.connected:
            raise ConnectionError("Mất kết nối MQTT khi chờ ACK.")
        time.sleep(0.005)
    if command_id in dashboard.pending_commands:
        with dashboard.lock:
            dashboard._expire_commands()
        time.sleep(0.05)
    if command_id in dashboard.pending_commands:
        raise TimeoutError(f"ACK {command_id} quá hạn.")
    return read_outcome(dashboard, command_id) or "unknown"


def ensure_mode(dashboard, enabled, attempts=4):
    for attempt in range(1, attempts + 1):
        if (dashboard.firmware_aes == enabled and dashboard.aes_enabled == enabled
                and dashboard.mode_challenge):
            return
        try:
            dashboard.change_mode(enabled)
            time.sleep(0.5)
            return
        except Exception as exc:
            log(f"  Đổi AES={int(enabled)} lỗi lần {attempt}: {exc}")
            with dashboard.lock:
                dashboard.last_mode_query = 0.0
            dashboard.request_mode_state()
            time.sleep(1.5)
    raise RuntimeError(f"Không đổi được AES={int(enabled)}.")


def ensure_relay(dashboard, desired, attempts=3):
    if (dashboard.last_state is desired and dashboard.last_state_ts
            and stamp() - dashboard.last_state_ts < 5):
        return
    command = "ON" if desired else "OFF"
    for attempt in range(1, attempts + 1):
        outcome = send_wait(dashboard, command)
        if outcome == "applied":
            return
        log(f"  Đồng bộ relay {command} lỗi ({outcome}), lần {attempt}.")
        time.sleep(1.0)
    raise RuntimeError(f"Không đưa relay về {command}.")


def run_batch(dashboard, enabled, count, warmup):
    label = "AES ON" if enabled else "AES OFF"
    log(f"[{label}] chuyển chế độ và warm-up {warmup} lệnh…")
    ensure_mode(dashboard, enabled)
    ensure_relay(dashboard, False)
    for i in range(warmup):
        outcome = send_wait(dashboard, "ON" if i % 2 == 0 else "OFF")
        if outcome != "applied":
            raise RuntimeError(f"Warm-up {label}: {outcome}")
    ensure_relay(dashboard, False)

    start = stamp()
    dashboard.store.log("PERF", "batch_start", json.dumps(
        {"enabled": enabled, "count": count, "warmup": warmup, "start_ts": start}))
    outcomes = {}
    began = time.perf_counter()
    for i in range(count):
        command = "ON" if i % 2 == 0 else "OFF"
        outcome = send_wait(dashboard, command)
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        if outcome != "applied":
            time.sleep(1.0)
        if (i + 1) % 50 == 0:
            log(f"  {label}: {i + 1}/{count} lệnh, lỗi/khác: {i + 1 - outcomes.get('applied', 0)}")
    end = stamp()
    dashboard.store.log("PERF", "batch_end", json.dumps(
        {"enabled": enabled, "count": count, "warmup": warmup, "start_ts": start,
         "end_ts": end, "outcomes": outcomes, "elapsed_s": end - start}))
    log(f"[{label}] xong {count} lệnh trong {end - start:.1f}s: {outcomes}")
    ensure_relay(dashboard, False)
    return {"enabled": enabled, "start": start, "end": end, "outcomes": outcomes,
            "elapsed_s": end - start}


def run_energy(dashboard, cycles):
    reason = dashboard.cycle_energy.blocked()
    if reason:
        raise RuntimeError(reason)
    ensure_mode(dashboard, True)
    ensure_relay(dashboard, False)
    log(f"[ENERGY] bắt đầu {cycles} chu kỳ (ON/OFF), 1 cặp đợt…")
    ident = dashboard.cycle_energy.start(
        {"confirmed": True, "cycles": cycles, "pairs": 1, "first": "on"})
    log(f"  session={ident}")
    previous = ""
    while dashboard.cycle_energy.running():
        progress = dashboard.cycle_energy.progress
        if progress != previous:
            log(f"  {progress}")
            previous = progress
        time.sleep(1)
    snapshot = dashboard.cycle_energy.snapshot(ident)
    log(f"  session status={snapshot['session']['status']} message={snapshot['session']['message']}")
    return snapshot


def percentile(values, q):
    ordered = sorted(values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * q / 100.0
    low, high = math.floor(position), math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] * (high - position) + ordered[high] * (position - low)


def summarise(rows):
    result = {"n": len(rows), "payload_bytes": None, "memory_valid": 0, "memory": None}
    sizes = [r["payload_bytes"] for r in rows if isinstance(r["payload_bytes"], int)]
    if sizes:
        result["payload_bytes"] = {"min": min(sizes), "max": max(sizes),
                                   "mean": statistics.mean(sizes)}
    for metric in METRIC_NAMES:
        values = [r[metric] for r in rows
                  if isinstance(r[metric], (int, float)) and math.isfinite(r[metric])]
        if not values:
            result[metric] = None
            continue
        mean = statistics.mean(values)
        sd = statistics.stdev(values) if len(values) > 1 else 0.0
        margin = 1.96 * sd / math.sqrt(len(values)) if len(values) > 1 else 0.0
        result[metric] = {"n": len(values), "mean": mean, "median": statistics.median(values),
                          "sd": sd, "p95": percentile(values, 95),
                          "min": min(values), "max": max(values),
                          "ci95": [mean - margin, mean + margin]}
    stack, allocations, heap_peak_max, retained_max, legacy = [], 0, 0, 0, 0
    for row in rows:
        if not row["command_memory_json"]:
            continue
        try:
            memory = json.loads(row["command_memory_json"])
        except (ValueError, TypeError):
            continue
        if memory.get("status") != "valid":
            continue
        result["memory_valid"] += 1
        allocations += memory.get("allocations", 0)
        heap_peak_max = max(heap_peak_max, memory.get("heap_peak", 0))
        retained_max = max(retained_max, memory.get("heap_retained", 0))
        if memory.get("v") == 1:
            legacy += 1
        elif isinstance(memory.get("stack_peak"), int) and memory["stack_peak"] > 0:
            stack.append(memory["stack_peak"])
    result["memory"] = {
        "valid": result["memory_valid"], "v1": legacy, "stack_n": len(stack),
        "stack_peak": ({"mean": statistics.mean(stack), "median": statistics.median(stack),
                        "min": min(stack), "max": max(stack)} if stack else None),
        "allocations_total": allocations, "heap_peak_max": heap_peak_max,
        "heap_retained_max": retained_max}
    return result


def analyse(db_path, batches, energy_session):
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    report = {"batches": [], "energy": None}
    for batch in batches:
        mode = "on" if batch["enabled"] else "off"
        rows = connection.execute(
            "SELECT * FROM measurements WHERE source='command' AND scenario='control' "
            "AND mode=? AND ts>=? AND ts<=? ORDER BY ts",
            (mode, batch["start"], batch["end"])).fetchall()
        outcome_rows = connection.execute(
            "SELECT outcome, COUNT(*) AS n FROM measurements WHERE source='command' "
            "AND mode=? AND ts>=? AND ts<=? GROUP BY outcome",
            (mode, batch["start"], batch["end"])).fetchall()
        applied = [row for row in rows if row["outcome"] == "applied"]
        report["batches"].append({
            "mode": mode, "start": batch["start"], "end": batch["end"],
            "elapsed_s": batch["elapsed_s"],
            "outcomes": {row["outcome"]: row["n"] for row in outcome_rows},
            "all": summarise(rows) if rows else None,
            "applied": summarise(applied),
            "memory_by_command": {command: summarise([row for row in applied if row["command"] == command])["memory"]
                                  for command in ("ON", "OFF")
                                  if any(row["command"] == command for row in applied)}})
    if energy_session:
        session_id = energy_session["session"]["id"]
        blocks = connection.execute(
            "SELECT * FROM cycle_blocks WHERE session=? ORDER BY rowid", (session_id,)).fetchall()
        report["energy"] = {
            "session": session_id,
            "status": energy_session["session"]["status"],
            "message": energy_session["session"]["message"],
            "comparison": energy_session["comparison"],
            "blocks": []}
        for block in blocks:
            data = json.loads(block["report"]) if block["report"] else None
            raw = (data or {}).get("raw") or {}
            report["energy"]["blocks"].append({
                "mode": block["mode"], "status": block["status"],
                "valid": (data or {}).get("valid"),
                "reasons": (data or {}).get("reasons"),
                "joule_per_cycle": (data or {}).get("joule_per_cycle"),
                "energy_j": raw.get("energy_j"), "duration_us": raw.get("duration_us"),
                "mean_power_w": raw.get("mean_power_w"),
                "mean_voltage_v": raw.get("mean_voltage_v"),
                "mean_current_ma": raw.get("mean_current_ma"),
                "samples": raw.get("samples"), "max_gap_us": raw.get("max_gap_us"),
                "covered_us": raw.get("covered_us"), "cpu_mhz": raw.get("cpu_mhz"),
                "wifi_ps": raw.get("wifi_ps"), "hardware_aes": raw.get("hardware_aes")})
    connection.close()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=str(HERE / "perf_20261022.sqlite3"))
    parser.add_argument("--count", type=int, default=200, help="Số lệnh đo mỗi chế độ.")
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--energy-cycles", type=int, default=50)
    parser.add_argument("--skip-energy", action="store_true")
    parser.add_argument("--skip-batch", action="store_true")
    args = parser.parse_args()
    if not 10 <= args.count <= 1000:
        parser.error("--count phải trong 10..1000")

    app = ws.create_app(args.db, connect=True)
    dashboard = app.extensions["dashboard"]
    batches = []
    energy = None
    try:
        wait_ready(dashboard)
        log(f"Thiết bị sẵn sàng: AES={dashboard.firmware_aes} state={dashboard.last_state} "
            f"V={dashboard.metrics.get('voltage_v', {}).get('value')}")
        if not args.skip_batch:
            batches.append(run_batch(dashboard, True, args.count, args.warmup))
            batches.append(run_batch(dashboard, False, args.count, args.warmup))
            ensure_mode(dashboard, True)
            ensure_relay(dashboard, False)
        if not args.skip_energy:
            try:
                energy = run_energy(dashboard, args.energy_cycles)
            except Exception as exc:
                log(f"ENERGY_ERROR: {type(exc).__name__}: {exc}")
        try:
            if dashboard.cycle_energy.firmware_busy:
                with dashboard.lock:
                    dashboard.last_mode_query = 0.0
                dashboard.request_mode_state()
                time.sleep(1.0)
                dashboard.cycle_energy.stop()
                for _ in range(30):
                    if not dashboard.cycle_energy.firmware_busy:
                        break
                    time.sleep(0.5)
            ensure_mode(dashboard, True)
            ensure_relay(dashboard, False)
        except Exception as exc:
            log(f"RESTORE_ERROR: {type(exc).__name__}: {exc}")
        report = analyse(args.db, batches, energy)
        report["db"] = str(Path(args.db).resolve())
        log("RESULT_JSON=" + json.dumps(report, ensure_ascii=False))
    finally:
        dashboard.stop()


if __name__ == "__main__":
    main()
