from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from collector import collect


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "eve.json"
        self.db = Path(self.tmp.name) / "state.sqlite3"
        self.event = {"event_type": "alert", "timestamp": "2026-10-20T12:00:00Z"}
        self.line = json.dumps(self.event).encode() + b"\n"

    def count(self):
        with closing(sqlite3.connect(self.db)) as db, db:
            return db.execute("SELECT count(*) FROM events").fetchone()[0]

    def test_filter_deduplicate_and_restart(self):
        self.log.write_bytes(self.line * 2 + b'{"event_type":"flow"}\n')
        self.assertEqual(collect(self.log, self.db),
                         dict(inserted=1, duplicates=1, ignored=1, malformed=0))
        self.assertEqual(collect(self.log, self.db)["inserted"], 0)
        self.assertEqual(self.count(), 1)

    def test_incomplete_line_is_read_after_completion(self):
        self.log.write_bytes(self.line[:-1])
        self.assertEqual(collect(self.log, self.db)["inserted"], 0)
        with self.log.open("ab") as stream:
            stream.write(b"\n")
        self.assertEqual(collect(self.log, self.db)["inserted"], 1)

    def test_malformed_line_does_not_hide_next_alert(self):
        self.log.write_bytes(b"invalid\n" + self.line)
        result = collect(self.log, self.db)
        self.assertEqual(result["malformed"], 1)
        self.assertEqual(result["inserted"], 1)

    def test_rotation_replay_and_new_event(self):
        self.log.write_bytes(self.line)
        collect(self.log, self.db)
        self.log.rename(self.log.with_suffix(".old"))
        newer = dict(self.event, timestamp="2026-10-20T12:01:00Z")
        self.log.write_bytes(self.line + json.dumps(newer).encode() + b"\n")
        result = collect(self.log, self.db)
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(result["inserted"], 1)

    def test_copytruncate_regrowth_resets_checkpoint(self):
        self.log.write_bytes(self.line)
        collect(self.log, self.db)
        self.log.write_bytes(json.dumps(dict(self.event, timestamp="2026-10-20T12:02:00Z",
                                            detail="longer replacement")).encode() + b"\n")
        self.assertEqual(collect(self.log, self.db)["inserted"], 1)


if __name__ == "__main__":
    unittest.main()
