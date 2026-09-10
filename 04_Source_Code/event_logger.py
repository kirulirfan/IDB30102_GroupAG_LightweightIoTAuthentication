"""
event_logger.py

Lightweight, timestamped security-event log used by the gateway to record
accepted requests, rejections and detected attacks (Table 3.3 STRIDE
control: "Repudiation -> Timestamped security-event logging").

Events are kept in memory and can optionally be appended to a CSV file so
they can be committed as evidence in 06_Results_or_Expected_Output/.
"""

import time
import csv
import os


class EventLog:
    def __init__(self, csv_path: str = None):
        self.events = []
        self.csv_path = csv_path
        if self.csv_path and not os.path.exists(self.csv_path):
            with open(self.csv_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "device_id", "event_type", "detail"])

    def record(self, device_id: str, event_type: str, detail: str = ""):
        entry = {
            "timestamp": time.time(),
            "device_id": device_id,
            "event_type": event_type,
            "detail": detail,
        }
        self.events.append(entry)
        if self.csv_path:
            with open(self.csv_path, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([entry["timestamp"], device_id, event_type, detail])
        return entry

    def print_recent(self, n: int = 10):
        for e in self.events[-n:]:
            ts = time.strftime("%H:%M:%S", time.localtime(e["timestamp"]))
            print(f"  [{ts}] {e['device_id']:<16} {e['event_type']:<22} {e['detail']}")

    def count(self, event_type: str = None) -> int:
        if event_type is None:
            return len(self.events)
        return sum(1 for e in self.events if e["event_type"] == event_type)
