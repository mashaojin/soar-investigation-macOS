import sqlite3
import tempfile
import unittest
from pathlib import Path
from dashboard import database_snapshot

class DashboardTests(unittest.TestCase):
    def test_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'missing.db'
            self.assertFalse(database_snapshot(path)['available'])
            self.assertFalse(path.exists())
    def test_only_current_revision_is_shown(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'state.db'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE incidents (incident_id TEXT,revision INTEGER,evidence TEXT,status TEXT)')
                db.execute("INSERT INTO incidents VALUES ('i',2,'{}','pending')")
                db.execute('CREATE TABLE analyses (incident_id TEXT,revision INTEGER,status TEXT,report TEXT,metadata TEXT,error TEXT)')
                db.execute("INSERT INTO analyses VALUES ('i',1,'complete','{\"verdict\":\"BENIGN\"}','{}',NULL)")
                db.execute('CREATE TABLE telegram_offsets (bot_key TEXT)')
                db.execute("INSERT INTO telegram_offsets VALUES ('secret')")
            result=database_snapshot(path)
            self.assertIsNone(result['incidents'][0]['report'])
            self.assertNotIn('secret',str(result))
