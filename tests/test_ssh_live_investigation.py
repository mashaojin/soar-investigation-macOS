import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
import sqlite3
from analyst import analyze_next
from ssh_live_investigation import prepare_live_job

class LiveInvestigationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.plans=Path(self.temp.name)/'plans.json';self.plans.write_text('[]')
        self.evidence={'signature_id':9001001,'destination_port':22,'source_ip':'192.168.64.4',
                       'destination_ip':'192.168.64.6','window_start':'2026-10-21T05:14:00+00:00','alert_count':1}
    def collector(self, request):
        return dict(request, coverage='journal_query_complete', failed_accounts={'root':3},
                    failed_password_count=3,successful_login_count=0)
    def test_live_label_and_window_preserved(self):
        _,job=prepare_live_job('incident',self.evidence,self.plans,self.collector)
        self.assertEqual(job['origin'],'live_read_only')
        self.assertEqual(job['authentication']['coverage'],'journal_query_complete')
        self.assertEqual(job['authentication']['start'],'2026-10-21T05:13:00+00:00')
        self.assertIsNone(job['plan_evidence']['plan'])
    def test_wrong_source_and_fixture_coverage_rejected(self):
        for changes in ({'source_ip':'192.168.64.99'}, {'coverage':'complete_for_fixture'}):
            with self.assertRaises(ValueError):
                prepare_live_job('incident',self.evidence,self.plans,
                                 lambda req: dict(self.collector(req),**changes))
    def test_collection_failure_is_claimed_once_and_never_calls_model(self):
        db=Path(self.temp.name)/'state.sqlite3'
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE incidents (incident_id TEXT,revision INTEGER,evidence TEXT,alert_count INTEGER,status TEXT)')
            connection.execute('INSERT INTO incidents VALUES (?,?,?,?,?)',('i',1,json.dumps(self.evidence),1,'pending'))
        settings={'ssh_enrichment':True,'approved_plans':str(self.plans)}
        with patch('ssh_live_investigation.prepare_live_job',side_effect=RuntimeError('Unavailable')) as prepare:
            def forbidden(*args): self.fail('Model called without evidence')
            first=analyze_next(db,settings,runner=forbidden)
            second=analyze_next(db,settings,runner=forbidden)
        self.assertEqual(first['status'],'manual_review')
        self.assertEqual(second['status'],'idle')
        self.assertEqual(prepare.call_count,1)

    def test_inconclusive_report_queues_without_action(self):
        from response import queue_reports
        db=Path(self.temp.name)/'response.sqlite3'
        report={'verdict':'INSUFFICIENT_EVIDENCE','reason':'Coverage unverified.',
                'recommendations':['Review coverage.','Collect evidence.']}
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE incidents (incident_id TEXT,revision INTEGER,evidence TEXT,alert_count INTEGER,status TEXT)')
            connection.execute('CREATE TABLE analyses (incident_id TEXT,revision INTEGER,report TEXT,status TEXT)')
            connection.execute('INSERT INTO incidents VALUES (?,?,?,?,?)',('i',1,json.dumps(self.evidence),1,'complete'))
            connection.execute('INSERT INTO analyses VALUES (?,?,?,?)',('i',1,json.dumps(report),'complete'))
        policy={'mode':'dry_run','approval_ttl_seconds':600}
        identity={'bot_key':'test','chat_id':1,'user_id':1}
        self.assertEqual(queue_reports(db,policy,identity),1)
        with sqlite3.connect(db) as connection:
            self.assertIsNone(connection.execute('SELECT plan FROM approval_requests').fetchone()[0])

    def test_unapproved_window_has_arrival_margin_before_inference(self):
        from ssh_live_investigation import ready_after
        self.assertEqual(ready_after(self.evidence,self.plans).isoformat(),'2026-10-21T05:16:00+00:00')
        _,job=prepare_live_job('i',self.evidence,self.plans,self.collector)
        end=datetime.fromisoformat(job['authentication']['end'])
        self.assertEqual((ready_after(self.evidence,self.plans)-end).total_seconds(),30)

    def test_unapproved_worker_waits_past_evidence_end(self):
        db=Path(self.temp.name)/'gate.sqlite3'
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE incidents (incident_id TEXT,revision INTEGER,evidence TEXT,alert_count INTEGER,status TEXT)')
            connection.execute('INSERT INTO incidents VALUES (?,?,?,?,?)',('i',1,json.dumps(self.evidence),1,'pending'))
        def forbidden(*args):self.fail('Must not infer before the full arrival allowance')
        settings={'ssh_enrichment':True,'approved_plans':str(self.plans)}
        for second in [30,31,59]:
            now=datetime(2026,10,21,5,15,second,tzinfo=timezone.utc)
            with patch('ssh_live_investigation.prepare_live_job',side_effect=forbidden):
                self.assertEqual(analyze_next(db,settings,now=now,runner=forbidden)['status'],'idle')
        with sqlite3.connect(db) as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM analyses').fetchone()[0],0)

    def test_plan_wait_and_full_window_counts(self):
        from ssh_live_investigation import ready_after
        plan={'id':'p','approval_status':'approved','owner':'operator','approved_by':'operator',
              'approved_at':'2026-10-21T05:09:00Z','source_ips':['192.168.64.4'],
              'target_ip':'192.168.64.6','target_port':22,'start':'2026-10-21T05:10:00Z',
              'end':'2026-10-21T05:20:00Z','allowed_accounts':['soc_test'],
              'maximum_failed_attempts':10,'scope':'test','stop_conditions':['stop after ten']}
        self.plans.write_text(json.dumps([plan]))
        self.assertEqual(ready_after(self.evidence,self.plans).isoformat(),'2026-10-21T05:20:30+00:00')
        _,job=prepare_live_job('i',self.evidence,self.plans,self.collector)
        self.assertEqual(job['authentication']['start'],plan['start'])
        self.assertEqual(job['authentication']['end'],plan['end'])
        self.assertEqual(job['authentication']['counting_scope'],'entire_approved_plan')
    def test_observed_label_requires_proof_fields(self):
        with self.assertRaisesRegex(ValueError,'independent checks'):
            prepare_live_job('i',self.evidence,self.plans,lambda r:dict(self.collector(r),coverage='observed_window'))
