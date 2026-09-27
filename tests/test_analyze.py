import csv
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from analyze import analyze_events, load_events


def event(minute, event_id, account="alex.demo", ip="203.0.113.10"):
    return {"timestamp": datetime(2026, 8, 18, tzinfo=timezone.utc) + timedelta(minutes=minute),
            "event_id": event_id, "account": account, "source_ip": ip, "computer": "LAB-PC"}


class EventReviewTests(unittest.TestCase):
    def test_burst_and_followup_success(self):
        findings = analyze_events([event(n, 4625) for n in (1, 3, 4, 6, 8)] + [event(11, 4624)])
        self.assertEqual([f["kind"] for f in findings], ["FAILED_SIGNIN_BURST", "SUCCESS_AFTER_BURST"])

    def test_separate_accounts_and_expired_failures(self):
        events = [event(n * 15, 4625) for n in range(5)]
        events += [event(n + 1, 4625, account="other.demo") for n in range(4)]
        self.assertEqual(analyze_events(events), [])

    def test_missing_identity_rejected_with_line_number(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.csv"
            with path.open("w", newline="") as dest:
                writer = csv.writer(dest)
                writer.writerow(["timestamp_utc", "event_id", "account", "source_ip", "computer"])
                writer.writerow(["2026-08-18T09:00:00Z", "4625", "", "203.0.113.10", "LAB-PC"])
            with self.assertRaisesRegex(ValueError, "line 2"):
                load_events(path)

    def test_new_burst_after_old_one_expires(self):
        first = [event(n, 4625) for n in (1, 2, 3, 4, 5)]
        second = [event(n, 4625) for n in (31, 32, 33, 34, 35)]
        findings = analyze_events(first + second)
        self.assertEqual([f["kind"] for f in findings],
                         ["FAILED_SIGNIN_BURST", "FAILED_SIGNIN_BURST"])


if __name__ == "__main__":
    unittest.main()
