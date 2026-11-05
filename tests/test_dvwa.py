from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from analyst import analyze_next
from collector import collect
from dvwa import sanitize_event
from incidents import group_events
from response import queue_reports, message_for


class DVWATests(unittest.TestCase):
    def test_sanitization_and_transaction_grouping(self):
        event = json.loads(Path('fixtures/dvwa-eve.json').read_text())
        event['http']['url'] += '&password=SECRET&token=SECRET'
        event['http']['cookie'] = 'SECRET'
        event['payload'] = 'SECRET'
        event['http']['url'] = 'http://user:SECRET@host' + event['http']['url']
        safe = sanitize_event(event)
        self.assertNotIn('SECRET', json.dumps(safe))
        self.assertIn('id=', safe['http']['uri'])
        with tempfile.TemporaryDirectory() as root:
            log, db_path = Path(root)/'eve.json', Path(root)/'state.sqlite3'
            another = dict(event, tx_id=1)
            log.write_text(json.dumps(event)+'\n'+json.dumps(another)+'\n')
            collect(log, db_path)
            self.assertEqual(group_events(db_path)['grouped'], 2)
            with closing(sqlite3.connect(db_path)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM incidents').fetchone()[0], 2)
                self.assertNotIn('SECRET', str(db.execute('SELECT payload FROM events').fetchall()))

    def test_direct_evidence_provenance_and_telegram_report_only(self):
        with tempfile.TemporaryDirectory() as root:
            db_path = Path(root)/'state.sqlite3'
            collect('fixtures/dvwa-eve.json', db_path); group_events(db_path)
            def runner(prompt, settings):
                self.assertIn('OR', prompt)  # sanitized evidence supplied by Python
                self.assertNotIn('investigation',settings)
                return {'text': json.dumps({'verdict':'SUSPICIOUS', 'reason':'Tautology attempts to widen the query; success is unknown.',
                        'recommendations':['Review application evidence.', 'Use parameterized queries.'],'evidence_refs':['E1','E2','P1']}),
                        'tools_used':['get_incident_evidence', 'get_lab_asset_context']}
            self.assertEqual(analyze_next(db_path, {}, now=datetime(2026,10,23,tzinfo=timezone.utc), runner=runner)['status'], 'complete')
            policy = dict(mode='dry_run', approval_ttl_seconds=600)
            identity = dict(bot_key='test',chat_id='1',user_id='1')
            self.assertEqual(queue_reports(db_path,policy,identity),1)
            with closing(sqlite3.connect(db_path)) as db:
                db.row_factory=sqlite3.Row
                row=db.execute('SELECT * FROM approval_requests').fetchone()
                self.assertIsNone(row['plan'])
                msg=message_for(row)
                self.assertNotIn('reply_markup',msg)
                self.assertIn('DVWA REPORT ONLY',msg['text'])
                self.assertIn('Success undetermined',msg['text'])

    def test_missing_tool_provenance_requires_manual_review(self):
        with tempfile.TemporaryDirectory() as root:
            db_path=Path(root)/'state.sqlite3'
            collect('fixtures/dvwa-eve.json',db_path);group_events(db_path)
            def runner(*args):
                return {'text':json.dumps(dict(verdict='SUSPICIOUS', reason='Attempt.', recommendations=['Review.','Verify.']))}
            self.assertEqual(analyze_next(db_path,{},now=datetime(2026,10,23,tzinfo=timezone.utc),runner=runner)['status'],'manual_review')
