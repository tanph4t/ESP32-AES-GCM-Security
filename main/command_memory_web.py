"""Versioned per-command memory samples; never infer measurements from telemetry."""
import csv
import io
import json
from datetime import datetime
from flask import Response, jsonify, request

FIELDS = ("heap_before", "heap_after", "heap_peak", "heap_retained", "allocations",
          "stack_free_min", "context_bytes")


def parse_memory(data, encrypted):
    sample = data.get("memory")
    if sample is None:
        return {"status": "missing"}
    if (not isinstance(sample, dict) or type(sample.get("v")) is not int or sample["v"] != 1
            or type(data.get("aes_enabled")) is not bool or data["aes_enabled"] != encrypted
            or sample.get("valid") is not True):
        return {"status": "invalid"}
    # A malformed/overflowed trace is unavailable, never a zero-byte sample.
    if any(type(sample.get(k)) is not int or not 0 <= sample[k] <= 16 * 1024 * 1024 for k in FIELDS):
        return {"status": "invalid"}
    if (sample["heap_retained"] > sample["heap_peak"]
            or (sample["allocations"] == 0 and sample["heap_peak"] != 0)
            or (encrypted and sample["context_bytes"] == 0)
            or (not encrypted and sample["context_bytes"] != 0)):
        return {"status": "invalid"}
    return {"status": "valid", "v": 1, **{k: sample[k] for k in FIELDS}}


def register_memory_routes(app, dashboard, timezone):
    def rows(limit):
        day = request.args.get("date", datetime.now(timezone).strftime("%Y-%m-%d"))
        records = dashboard.store.measurements(day, limit=limit)
        result = []
        for row in records:
            if row["source"] != "command" or row["outcome"] != "applied" or row["command"] not in {"ON", "OFF"}:
                continue
            sample = json.loads(row["command_memory_json"]) if row["command_memory_json"] else {"status": "missing"}
            result.append({k: row[k] for k in ("ts", "command_id", "command", "mode")} | sample)
        return day, result

    @app.get("/api/command-memory")
    def command_memory():
        try:
            day, samples = rows(2000)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        groups = []
        for command in ("ON", "OFF"):
            for mode in ("on", "off"):
                group = [s for s in samples if s["command"] == command and s["mode"] == mode and s["status"] == "valid"]
                groups.append(dict(command=command, mode=mode, n=len(group),
                    peak_mean=sum(s["heap_peak"] for s in group)/len(group) if group else None,
                    peak_max=max((s["heap_peak"] for s in group), default=None),
                    retained_mean=sum(s["heap_retained"] for s in group)/len(group) if group else None))
        return jsonify(date=day, groups=groups, latest=samples[0] if samples else None,
                       samples=samples[:30], valid=sum(s["status"] == "valid" for s in samples),
                       unavailable=sum(s["status"] != "valid" for s in samples), limit=2000)

    @app.get("/api/command-memory.csv")
    def command_memory_csv():
        try:
            day, samples = rows(100000)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=("ts", "command_id", "command", "mode", "status", "v", *FIELDS))
        writer.writeheader()
        writer.writerows(reversed(samples))
        return Response("\ufeff" + buffer.getvalue(), mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="command_memory_{day}.csv"'})
