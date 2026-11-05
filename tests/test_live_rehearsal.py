from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import live_lab


class CurrentRehearsalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.here = patch.object(live_lab, 'HERE', self.root)
        self.here.start()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.here.stop)
        self.now = datetime.now(timezone.utc)
        self.incident = 'a'*64
        self.evidence = dict(source_ip='192.168.64.4', destination_ip='192.168.64.6',
                             destination_port=22, signature_id=9001001,
                             window_start=(self.now-timedelta(minutes=3)).isoformat())
        self.report = dict(verdict='SUSPICIOUS', coverage='observed_window')
        self.metadata = dict(engine='ollama_direct', model='gemma4:e4b', investigation=dict(
            origin='live_read_only', plan_evidence={'plan':None}, authentication=dict(
                source_ip='192.168.64.4', target_ip='192.168.64.6', coverage='observed_window',
                limited=False, failed_password_count=6, successful_login_count=0,
                coverage_checks={k:True for k in ('query_not_limited','retained_entry_before_start','root_service_records','window_elapsed')})))
        self.save()

    def save(self, revision=1, assessment_revision=None, status='complete'):
        with sqlite3.connect(self.root/'ssh-live.sqlite3') as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS incidents(incident_id TEXT,evidence TEXT,revision INTEGER);
                CREATE TABLE IF NOT EXISTS analyses(incident_id TEXT,revision INTEGER,status TEXT,report TEXT,metadata TEXT);
                CREATE TABLE IF NOT EXISTS remote_audit(kind TEXT,recorded_at TEXT);
                DELETE FROM incidents; DELETE FROM analyses; DELETE FROM remote_audit;''')
            db.execute('INSERT INTO incidents VALUES(?,?,?)', (self.incident,json.dumps(self.evidence),revision))
            db.execute('INSERT INTO analyses VALUES(?,?,?,?,?)', (self.incident,revision if assessment_revision is None else assessment_revision,status,json.dumps(self.report),json.dumps(self.metadata)))
            db.execute('INSERT INTO remote_audit VALUES(?,?)', ('operator_rebaseline_20261103',(self.now-timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')))

    def check(self):
        return live_lab.current_rehearsal_incident(self.incident, now=self.now)

    def test_accepts_fresh_complete_scoped_evidence(self):
        self.assertEqual(self.check()[2]['revision'],1)

    def test_snapshot_changes_if_assessment_changes(self):
        original=self.check()[2]
        self.report['reason']='changed assessment'
        self.save()
        self.assertNotEqual(original,self.check()[2])

    def test_rejects_incomplete_successful_and_out_of_scope(self):
        auth=self.metadata['investigation']['authentication']
        for field,value in [('coverage','partial'),('failed_password_count',5),('successful_login_count',1),('source_ip','192.168.64.8'),('limited',True)]:
            with self.subTest(field=field):
                old=auth[field]; auth[field]=value; self.save()
                with self.assertRaises(ValueError): self.check()
                auth[field]=old
        auth['coverage_checks']['window_elapsed']=False; self.save()
        with self.assertRaises(ValueError): self.check()

    def test_rejects_stale_revision(self):
        self.save(revision=2,assessment_revision=1)
        with self.assertRaises(ValueError): self.check()

    def test_rejects_historical_or_expired_incident(self):
        self.evidence['window_start']=(self.now-timedelta(hours=1)).isoformat(); self.save()
        with self.assertRaises(ValueError): self.check()

    def test_rejects_benign_and_matching_plan(self):
        self.report['verdict']='BENIGN'; self.save()
        with self.assertRaises(ValueError): self.check()
        self.report['verdict']='SUSPICIOUS'
        self.metadata['investigation']['plan_evidence']['plan']={'id':'approved'}; self.save()
        with self.assertRaises(ValueError): self.check()


if __name__=='__main__': unittest.main()
