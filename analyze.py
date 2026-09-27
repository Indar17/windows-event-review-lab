"""Review synthetic Windows sign-in CSV data for a simple failure pattern."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path


REQUIRED_COLUMNS = {"timestamp_utc", "event_id", "account", "source_ip", "computer"}


def load_events(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(reader.fieldnames):
            raise ValueError("CSV needs columns: " + ", ".join(sorted(REQUIRED_COLUMNS)))
        events = []
        for line_number, row in enumerate(reader, start=2):
            if None in row or any(row[name] is None for name in REQUIRED_COLUMNS):
                raise ValueError(f"line {line_number}: invalid CSV row")
            try:
                stamp = datetime.fromisoformat(row["timestamp_utc"].strip())
                if stamp.tzinfo is None or stamp.utcoffset() is None:
                    raise ValueError("timezone required")
                event_id = int(row["event_id"])
            except ValueError as exc:
                raise ValueError(f"line {line_number}: invalid timestamp or event ID") from exc
            account = row["account"].strip()
            source_ip = row["source_ip"].strip()
            if not account or not source_ip:
                raise ValueError(f"line {line_number}: account and source_ip are required")
            events.append({
                "timestamp": stamp.astimezone(timezone.utc),
                "event_id": event_id,
                "account": account,
                "source_ip": source_ip,
                "computer": row["computer"].strip(),
            })
    return sorted(events, key=lambda event: event["timestamp"])


def analyze_events(
    events: list[dict], threshold: int = 5, window_minutes: int = 10,
    followup_minutes: int = 15,
) -> list[dict]:
    if min(threshold, window_minutes, followup_minutes) < 1:
        raise ValueError("threshold and time windows must be positive")
    failures = defaultdict(deque)
    active_bursts = {}
    findings = []
    window = timedelta(minutes=window_minutes)
    followup = timedelta(minutes=followup_minutes)
    for event in sorted(events, key=lambda item: item["timestamp"]):
        stamp = event["timestamp"]
        key = (event["account"], event["source_ip"])
        history = failures[key]
        while history and stamp - history[0] > window:
            history.popleft()
        if event["event_id"] == 4625:
            if key in active_bursts and stamp - active_bursts[key] > followup:
                active_bursts.pop(key)
            history.append(stamp)
            if len(history) >= threshold and key not in active_bursts:
                active_bursts[key] = stamp
                findings.append({
                    "timestamp_utc": stamp.isoformat(), "kind": "FAILED_SIGNIN_BURST",
                    "account": key[0], "source_ip": key[1],
                    "detail": f"{len(history)} failures in {window_minutes} min",
                })
        elif event["event_id"] == 4624 and key in active_bursts:
            elapsed = stamp - active_bursts.pop(key)
            if timedelta(0) <= elapsed <= followup:
                findings.append({
                    "timestamp_utc": stamp.isoformat(), "kind": "SUCCESS_AFTER_BURST",
                    "account": key[0], "source_ip": key[1],
                    "detail": f"success {int(elapsed.total_seconds() // 60)} min after flagged burst",
                })
            history.clear()
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--followup-minutes", type=int, default=15)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        findings = analyze_events(load_events(args.csv_path), args.threshold,
                                  args.window_minutes, args.followup_minutes)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    else:
        for item in findings:
            print(" | ".join((item["timestamp_utc"], item["kind"],
                              item["account"], item["source_ip"], item["detail"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
