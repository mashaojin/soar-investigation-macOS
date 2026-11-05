from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from live import collect_once, RemoteGap
from remote_reader import read_batch, CollectionGap


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "eve.json"
        self.db = Path(self.tmp.name) / "state.sqlite3"
        self.path.write_bytes(Path("fixtures/eve.json").read_bytes())
        self.config = dict(ssh_target="victim@192.168.64.6", log_path=str(self.path), start_at="beginning")

    def reader(self, config, cursor):
        try:
            return read_batch(dict(path=config["log_path"], cursor=cursor, start_at=config["start_at"]))
        except CollectionGap as exc:
            raise RemoteGap(str(exc)) from exc

    def collect(self):
        return collect_once(self.config, self.db, reader=self.reader)

    def event(self, second):
        return (json.dumps(dict(event_type="alert", timestamp=f"2026-10-20T19:00:{second:02d}Z",
                               src_ip="192.168.64.4", dest_ip="192.168.64.6", dest_port=22,
                               alert=dict(signature_id=9001001))) + "\n").encode()

    def test_restart_and_rotation_drain_before_active_file(self):
        self.assertEqual(self.collect()["inserted"], 2)
        with self.path.open("ab") as out:
            out.write(self.event(10))
        self.path.rename(self.path.with_suffix(".json.1"))
        self.path.write_bytes(self.event(20))
        self.assertEqual(self.collect()["inserted"], 1)
        self.assertEqual(self.collect()["inserted"], 1)
        self.assertEqual(self.collect()["inserted"], 0)

    def test_disconnect_preserves_cursor_then_resume(self):
        self.collect()
        with self.path.open("ab") as out:
            out.write(self.event(10))
        with closing(sqlite3.connect(self.db)) as db:
            before = db.execute("SELECT cursor FROM remote_checkpoints").fetchone()[0]
        def disconnected(*args):
            raise ConnectionError("simulated disconnect")
        with self.assertRaises(ConnectionError):
            collect_once(self.config, self.db, reader=disconnected)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute("SELECT cursor FROM remote_checkpoints").fetchone()[0], before)
        self.assertEqual(self.collect()["inserted"], 1)

    def test_end_baseline_does_not_replay_historical_alerts(self):
        self.config["start_at"] = "end"
        result = self.collect()
        self.assertEqual(result["inserted"], 0)
        self.assertGreater(result["baseline_skipped_bytes"], 0)
        with self.path.open("ab") as out:
            out.write(self.event(10))
        self.assertEqual(self.collect()["inserted"], 1)

    def test_partial_line_waits_for_completion(self):
        self.collect()
        with self.path.open("ab") as out:
            out.write(self.event(10)[:-1])
        self.assertEqual(self.collect()["inserted"], 0)
        with self.path.open("ab") as out:
            out.write(b"\n")
        self.assertEqual(self.collect()["inserted"], 1)

    def test_missing_rotation_is_visible_gap(self):
        self.collect()
        self.path.rename(self.path.with_suffix(".hidden"))
        self.path.write_bytes(self.event(10))
        with self.assertRaises(RemoteGap):
            self.collect()

    def test_copytruncate_is_gap_instead_of_silent_reset(self):
        self.collect()
        self.path.write_bytes(self.event(10))
        with self.assertRaises(RemoteGap):
            self.collect()

    def test_rollback_events_and_cursor_if_batch_commit_fails(self):
        self.collect()
        with self.path.open("ab") as out:
            out.write(self.event(10))
        def broken(config, cursor):
            batch = self.reader(config, cursor)
            del batch["cursor"]
            return batch
        with self.assertRaises(KeyError):
            collect_once(self.config, self.db, reader=broken)
        self.assertEqual(self.collect()["inserted"], 1)

    def test_demo_filter_ignores_management_connections(self):
        self.config['source_ips']=['192.168.64.4','192.168.64.8']
        self.config['destination_ip']='192.168.64.6'
        self.path.write_bytes(self.event(1).replace(b'192.168.64.4',b'192.168.64.1'))
        result=self.collect()
        self.assertEqual(result['inserted'],0)
        self.assertEqual(result['filtered'],1)

    def test_unrelated_signature_is_filtered_without_model_work(self):
        self.path.write_text(json.dumps(dict(event_type="alert", alert=dict(signature_id=123))) + "\n")
        result = self.collect()
        self.assertEqual(result["filtered"], 1)
        self.assertEqual(result["inserted"], 0)
        self.assertEqual(result["grouped"], 0)

    def test_compressed_rotation_stops_instead_of_skipping_history(self):
        self.collect()
        self.path.rename(self.path.with_suffix(".json.2"))
        compressed = self.path.with_suffix(".json.1.gz")
        compressed.write_bytes(b"compressed placeholder")
        self.path.write_bytes(self.event(10))
        os.utime(self.path.with_suffix(".json.2"), (100, 100))
        os.utime(compressed, (200, 200))
        with self.assertRaises(RemoteGap):
            self.collect()

    def test_large_batch_is_bounded_and_eventually_drains(self):
        flow = json.dumps(dict(event_type="flow", data="x" * 1024)).encode() + b"\n"
        self.path.write_bytes(flow * 300 + self.event(10))
        first = self.collect()
        self.assertTrue(first["has_more"])
        second = self.collect()
        self.assertFalse(second["has_more"])
        self.assertEqual(second["inserted"], 1)


if __name__ == "__main__":
    unittest.main()
