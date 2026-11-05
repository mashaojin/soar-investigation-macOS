from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import live_lab
import live_lab_guard


class LiveLabTests(unittest.TestCase):
    def test_plan_is_fixed_and_scoped(self):
        plan = live_lab.live_plan("incident")
        self.assertEqual(plan["source"], "192.168.64.4")
        self.assertEqual(plan["destination"], "192.168.64.6")
        self.assertEqual(plan["port"], 22)
        self.assertEqual(plan["duration_seconds"], 60)
        self.assertNotEqual(plan["source"], plan["management_ip"])
        changed = dict(plan, port=80)
        self.assertNotEqual(live_lab.digest(plan), live_lab.digest(changed))

    def test_rollback_source_compiles(self):
        compile(live_lab_guard.ROLLBACK, "rollback.py", "exec")

    def test_pending_request_cannot_execute(self):
        with tempfile.TemporaryDirectory() as root, patch.object(live_lab, "DB", Path(root)/"state.sqlite3"):
            with closing(live_lab.connection()) as db, db:
                plan = live_lab.live_plan("incident")
                db.execute("INSERT INTO live_lab_tests VALUES(?,?,?,'pending',1,0,9999999999,'bot',100,100,'{}')",
                           ("a"*24, json.dumps(plan), live_lab.digest(plan)))
            with patch.object(live_lab, "poll"), patch.object(live_lab, "kali_probe") as probe:
                result = live_lab.execute(None, dict(bot_key="bot", chat_id=100, user_id=100))
                self.assertFalse(result["applied"])
                probe.assert_not_called()

    def test_tampered_approved_plan_cannot_execute(self):
        with tempfile.TemporaryDirectory() as root, patch.object(live_lab, "DB", Path(root)/"state.sqlite3"):
            with closing(live_lab.connection()) as db, db:
                original = live_lab.live_plan("incident")
                changed = dict(original, source="192.168.64.1")
                db.execute("INSERT INTO live_lab_tests VALUES(?,?,?,'approved',1,0,9999999999,'bot',100,100,'{}')",
                           ("a"*24, json.dumps(changed), live_lab.digest(original)))
            with patch.object(live_lab, "poll"), patch.object(live_lab, "kali_probe") as probe:
                with self.assertRaises(RuntimeError):
                    live_lab.execute(None, dict(bot_key="bot", chat_id=100, user_id=100))
                probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
