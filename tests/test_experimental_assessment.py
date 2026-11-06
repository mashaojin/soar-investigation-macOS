"""Unqualified model stays review-only; no live or simulated response approval."""
from contextlib import closing
from copy import deepcopy
from datetime import datetime,timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from experimental_assessment import qualification
from analyst import analyze_next
from response import queue_reports,deliver_one,handle_update,bound_plan
from live_response import validate_live_evidence
from test_direct_gemma import job,report
from test_windows_profile import windows
from assessment_facts import observed_claims


def settings():
    lab=windows();lab['ollama'].update(model='qwen3:4b-instruct-2507-q4_K_M',num_thread=4)
    return dict(lab_profile=lab,experimental_assessment=dict(model=lab['ollama']['model'],authorized_at='2026-11-05T00:00:00Z',mode='dry_run_human_review'))


class ExperimentalTests(unittest.TestCase):
    def test_authorization_is_model_bound_and_cannot_enable_live(self):
        value=settings();policy=dict(mode='dry_run',experimental_assessment=value['experimental_assessment'])
        self.assertTrue(qualification(value,policy)['human_review_required'])
        with self.assertRaises(ValueError):qualification(value,dict(policy,mode='live'))
        bad=deepcopy(value);bad['experimental_assessment']['model']='gemma3:1b'
        with self.assertRaises(ValueError):qualification(bad)
        self.assertEqual(qualification({}),{})

    def test_valid_suspicious_report_is_retained_but_requires_review_once(self):
        evidence,investigation=job('unapproved_activity')
        answer=dict(report('SUSPICIOUS','Sixteen failed logins warrant investigation.'),claims=observed_claims(investigation),recommended_action='REQUEST_BLOCK_APPROVAL')
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'state.sqlite3'
            with closing(sqlite3.connect(path)) as db,db:
                db.execute('CREATE TABLE incidents(incident_id TEXT PRIMARY KEY,revision INTEGER,evidence TEXT,alert_count INTEGER,status TEXT)')
                db.execute('INSERT INTO incidents VALUES(?,1,?,1,?)',('i',json.dumps(evidence),'pending'))
            value=dict(settings(),ssh_enrichment=True,approved_plans='unused.json')
            with patch('ssh_live_investigation.prepare_live_job',return_value=('',investigation)),patch('analyst.ollama_report'):
                from unittest.mock import MagicMock
                runner=MagicMock(return_value={'text':json.dumps(answer),'model_qualification':'qualified'})
                first=analyze_next(path,value,now=datetime(2030,1,1,tzinfo=timezone.utc),runner=runner)
                second=analyze_next(path,value,now=datetime(2030,1,1,tzinfo=timezone.utc),runner=runner)
            self.assertEqual(first['status'],'manual_review');self.assertEqual(second['status'],'idle');self.assertEqual(runner.call_count,1)
            with closing(sqlite3.connect(path)) as db:
                saved,metadata=db.execute('SELECT report,metadata FROM analyses').fetchone()
            self.assertEqual(json.loads(saved)['verdict'],'SUSPICIOUS')
            self.assertEqual(json.loads(metadata)['model_qualification'],'experimental_unverified')

    def test_experimental_report_gets_review_buttons_without_response_plan(self):
        import test_continuous_response as legacy
        from test_telegram_decisions import RecordingTelegram
        fixture=legacy.ContinuousResponseTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.metadata.update(model_qualification='experimental_unverified',human_review_required=True)
        with closing(sqlite3.connect(fixture.db)) as db,db:
            db.execute('UPDATE incidents SET incident_id=?',('a'*64,))
            db.execute('UPDATE analyses SET incident_id=?',('a'*64,))
            db.execute("UPDATE incidents SET status='manual_review'")
            db.execute("UPDATE analyses SET status='manual_review',metadata=?",(json.dumps(fixture.metadata),))
        client=RecordingTelegram()
        queue_reports(fixture.db,fixture.policy,legacy.IDENTITY)
        self.assertEqual(deliver_one(fixture.db,client,legacy.IDENTITY),'sent')
        payload=client.calls[0][1]
        self.assertIn('Experimental AI',payload['text'])
        buttons=payload['reply_markup']['inline_keyboard']
        self.assertEqual(len(buttons),2)
        self.assertNotIn('Do you authorize blocking',payload['text'])
        self.assertEqual([b['text'] for row in buttons for b in row],
            ['🟢 Benign','🔴 Suspicious','🟡 Need more evidence'])
        callback=buttons[0][0]['callback_data']
        self.assertTrue(callback.startswith('hr:b:'))
        with closing(sqlite3.connect(fixture.db)) as db:
            self.assertEqual(db.execute('SELECT used FROM review_choices').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM human_reviews').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM dry_run_actions').fetchone()[0],0)
        with closing(sqlite3.connect(fixture.db)) as db:
            self.assertIsNone(db.execute('SELECT plan FROM approval_requests').fetchone()[0])
        update=dict(update_id=1,callback_query=dict(id='q',data=callback,**{'from':{'id':100,'is_bot':False}},message=dict(message_id=42,chat=dict(id=100,type='private'))))
        self.assertEqual(handle_update(fixture.db,update,legacy.IDENTITY),'review_benign')
        with closing(sqlite3.connect(fixture.db)) as db:
            self.assertEqual(json.loads(db.execute('SELECT report FROM analyses').fetchone()[0])['verdict'],'SUSPICIOUS')
            self.assertIsNone(db.execute('SELECT plan FROM approval_requests').fetchone()[0])
        with self.assertRaises(ValueError):bound_plan(fixture.evidence,fixture.report,fixture.metadata,fixture.policy,fixture.now)
        with self.assertRaises(ValueError):validate_live_evidence(fixture.evidence,fixture.report,fixture.metadata,fixture.policy,fixture.now)


if __name__=='__main__':unittest.main()
