from dvwa import sanitize_event
from contextlib import closing
"""Replay/local Suricata collector. No model calls or remote actions."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3


def collect(log_path, db_path):
    source = str(Path(log_path).resolve())
    counts = dict(inserted=0, duplicates=0, ignored=0, malformed=0)
    with closing(sqlite3.connect(db_path)) as db, db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS checkpoints (
                source TEXT PRIMARY KEY, identity TEXT NOT NULL,
                offset INTEGER NOT NULL, anchor TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS ingest_errors (
                source TEXT NOT NULL, offset INTEGER NOT NULL,
                error TEXT NOT NULL, recorded_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Event writes and checkpoint advance commit together.
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT identity, offset, anchor FROM checkpoints WHERE source=?", (source,)
        ).fetchone()
        with open(source, "rb") as stream:
            import os
            stat = os.fstat(stream.fileno())
            identity = f"{stat.st_dev}:{stat.st_ino}"
            offset = 0
            if row and row[0] == identity and stat.st_size >= row[1]:
                stream.seek(max(0, row[1] - 256))
                anchor = hashlib.sha256(stream.read(min(256, row[1]))).hexdigest()
                if anchor == row[2]:
                    offset = row[1]
            stream.seek(offset)
            while True:
                start = stream.tell()
                line = stream.readline()
                if not line or not line.endswith(b"\n"):
                    # Do not checkpoint an event that is still being written.
                    stream.seek(start)
                    break
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("event must be a JSON object")
                except (ValueError, UnicodeDecodeError):
                    db.execute(
                        "INSERT INTO ingest_errors(source, offset, error) VALUES (?, ?, ?)",
                        (source, start, "Invalid JSON event"),
                    )
                    counts["malformed"] += 1
                    continue
                if event.get("event_type") != "alert":
                    counts["ignored"] += 1
                    continue
                event = sanitize_event(event)
                payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
                event_id = hashlib.sha256(payload.encode()).hexdigest()
                result = db.execute(
                    "INSERT OR IGNORE INTO events(event_id, payload) VALUES (?, ?)",
                    (event_id, payload),
                )
                counts["inserted" if result.rowcount else "duplicates"] += 1
            offset = stream.tell()
            stream.seek(max(0, offset - 256))
            anchor = hashlib.sha256(stream.read(min(256, offset))).hexdigest()
            db.execute(
                "INSERT OR REPLACE INTO checkpoints VALUES (?, ?, ?, ?)",
                (source, identity, offset, anchor),
            )
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True)
    parser.add_argument("--db", required=True)
    args = parser.parse_args()
    print(json.dumps(collect(args.log, args.db), sort_keys=True))
