from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from collector import collect
from incidents import group_events


class IncidentTests(unittest.TestCase):
    def test_group_restart_bound_samples_and_late_revision(self):
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "eve.json"
            db_path = Path(root) / "state.sqlite3"
            base = dict(event_type="alert", src_ip="192.168.64.4",
                        dest_ip="192.168.64.6", dest_port=22,
                        alert=dict(signature_id=9001001))
            events = [dict(base, timestamp=f"2026-10-20T12:00:0{i}Z") for i in range(5)]
            log.write_text("".join(json.dumps(e) + "\n" for e in events))
            collect(log, db_path)
            self.assertEqual(group_events(db_path)["grouped"], 5)
            self.assertEqual(group_events(db_path)["grouped"], 0)
            with closing(sqlite3.connect(db_path)) as db, db:
                evidence, count, revision = db.execute(
                    "SELECT evidence, alert_count, revision FROM incidents").fetchone()
                self.assertEqual(count, 5)
                self.assertEqual(len(json.loads(evidence)["sample_event_ids"]), 3)
            with log.open("a") as out:
                out.write(json.dumps(dict(base, timestamp="2026-10-20T12:00:30Z")) + "\n")
                out.write(json.dumps(dict(base, timestamp="2026-10-20T12:02:00Z")) + "\n")
                out.write(json.dumps(dict(base, timestamp="bad")) + "\n")
            collect(log, db_path)
            self.assertEqual(group_events(db_path), dict(grouped=2, rejected=1))
            with closing(sqlite3.connect(db_path)) as db, db:
                self.assertEqual(db.execute("SELECT count(*) FROM incidents").fetchone()[0], 2)
                self.assertEqual(db.execute("SELECT max(revision) FROM incidents").fetchone()[0], revision+1)


if __name__ == "__main__":
    unittest.main()
