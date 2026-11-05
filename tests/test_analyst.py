from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from analyst import analyze_next, validate_report
from collector import collect
from incidents import group_events


REPORT = {"evidence_refs": ["E1"], "verdict": "INSUFFICIENT_EVIDENCE", "reason": "Repeated SSH connections warrant review.",
          "recommendations": ["Check SSH authentication logs.", "Review the source host."]}


class AnalystTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.db = Path(self.root.name) / "state.sqlite3"
        self.log = Path(self.root.name) / "eve.json"
        self.log.write_bytes(Path("fixtures/eve.json").read_bytes())
        collect(self.log, self.db)
        group_events(self.db)
        self.now = datetime(2026, 10, 21, tzinfo=timezone.utc)

    def run_worker(self, runner):
        return analyze_next(self.db, {}, now=self.now, runner=runner)

    def test_fresh_bounded_prompt_and_no_repeat(self):
        calls = []
        def runner(prompt, settings):
            calls.append(prompt)
            self.assertLess(len(prompt.encode()), 6000)
            return {"text": json.dumps(REPORT)}
        self.assertEqual(self.run_worker(runner)["status"], "manual_review")
        self.assertEqual(self.run_worker(runner)["status"], "idle")
        self.assertEqual(len(calls), 1)

    def test_timeout_goes_to_manual_review_without_retry(self):
        def timeout(*args):
            raise subprocess.TimeoutExpired("hermes", 120)
        self.assertEqual(self.run_worker(timeout)["status"], "manual_review")
        self.assertEqual(self.run_worker(timeout)["status"], "idle")

    def test_incomplete_json_goes_to_manual_review(self):
        self.assertEqual(self.run_worker(lambda *args: {"text": '{"verdict":'})["status"], "manual_review")

    def test_open_window_is_not_analyzed(self):
        now = datetime(2026, 10, 20, 19, 1, 0, tzinfo=timezone.utc)
        def forbidden(*args):
            self.fail("Window has not passed its grace period")
        self.assertEqual(analyze_next(self.db, {}, now=now, runner=forbidden)["status"], "idle")

    def test_late_evidence_during_analysis_marks_report_stale(self):
        def runner(*args):
            with closing(sqlite3.connect(self.db)) as db, db:
                db.execute("UPDATE incidents SET revision=revision+1")
            return {"text": json.dumps(REPORT)}
        self.assertEqual(self.run_worker(runner)["status"], "stale")

    def test_invalid_verdict_rejected(self):
        with self.assertRaises(ValueError):
            validate_report(json.dumps(dict(REPORT, verdict="BLOCK_NOW")))


if __name__ == "__main__":
    unittest.main()
