from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from dashboard import snapshot
from dashboard_view import document_key, document_references, incident_view, plan_view


NOW=datetime(2026,10,27,18,0,tzinfo=timezone.utc)
PLAN={'id':'historical','approval_status':'approved','owner':'operator',
      'approved_by':'operator','approved_at':'2026-10-27T16:59:00Z',
      'source_ips':['192.168.64.8'],'target_ip':'192.168.64.6','target_port':22,
      'start':'2026-10-27T17:00:00Z','end':'2026-10-27T17:03:00Z',
      'allowed_accounts':['soc_test'],'maximum_failed_attempts':10,
      'scope':'Test','stop_conditions':['Stop after ten failures']}


def incident(plan=PLAN):
    return {'incident_id':'recorded-incident','revision':1,'status':'complete',
            'evidence':{'source_ip':'192.168.64.8','destination_ip':'192.168.64.6',
                        'destination_port':22,'signature_id':9001001,'window_start':'2026-10-27T17:01:00Z'},
            'analysis_status':'complete','report':{'verdict':'BENIGN'},'approval':None,
            'metadata':{'tool_trace':[{'tool':'get_ssh_auth_summary','result':{}},
                        {'tool':'get_approved_test_plan','result':{'plan':deepcopy(plan),'checks':{'source_matches':True}}}]}}


class ViewTests(unittest.TestCase):
    def test_history_matches_recorded_plan_not_latest_registry_plan(self):
        latest=dict(PLAN,id='new-plan',start='2026-10-27T18:10:00Z',end='2026-10-27T18:13:00Z')
        view=incident_view(incident(),[latest],NOW)
        self.assertEqual(view['authorization']['source'],'recorded')
        self.assertEqual(view['authorization']['plan']['id'],'historical')
        self.assertEqual(view['authorization']['plan']['timing'],'expired')

    def test_recorded_no_match_stays_no_match_when_new_plan_exists(self):
        view=incident_view(incident(None),[PLAN],NOW)
        self.assertEqual(view['authorization']['source'],'recorded')
        self.assertIsNone(view['authorization']['plan'])

    def test_missing_historical_tool_data_is_unknown_not_new_plan(self):
        row=incident();row['metadata']={}
        self.assertEqual(incident_view(row,[PLAN],NOW)['authorization']['source'],'unavailable')

    def test_pending_deadline_uses_existing_scheduler_rule(self):
        row=incident();row.update(status='pending',analysis_status='pending',report=None,metadata={})
        before=datetime(2026,10,27,17,1,10,tzinfo=timezone.utc)
        view=incident_view(row,[PLAN],before)
        self.assertEqual(view['status'],'waiting')
        self.assertEqual(view['waiting_until'],'2026-10-27T17:03:30+00:00')
        self.assertEqual(view['authorization']['source'],'scheduling')
        self.assertIsNone(view['response_approval_required'])
        self.assertEqual(view['stages'][3]['state'],'waiting')
        unmatched=incident_view(row,[],before)
        self.assertEqual(unmatched['waiting_until'],'2026-10-27T17:03:00+00:00')

    def test_report_only_skips_response_approval_and_does_not_claim_execution(self):
        row=incident();row['approval']={'status':'notified','plan':None}
        view=incident_view(row,[PLAN],NOW)
        self.assertEqual(view['label'],'Report delivered')
        self.assertFalse(view['response_approval_required'])
        self.assertEqual(view['stages'][3],{'label':'Approval not required','state':'skipped'})
        self.assertEqual(view['stages'][4]['label'],'Report delivered')

    def test_response_states_and_unknown_worker_phase_are_accurate(self):
        for status,label in [('pending','Awaiting Telegram decision'),('dry_run_complete','Simulated response complete'),
                             ('expired','Response request expired'),('denied','Report only — declined')]:
            row=incident();row['approval']={'status':status,'plan':{'mode':'dry_run'}}
            self.assertEqual(incident_view(row,[],NOW)['label'],label)
        row=incident();row.update(status='pending',report=None,analysis_status='running',metadata={})
        view=incident_view(row,[],NOW)
        self.assertEqual(view['label'],'Gathering evidence / analyzing')
        self.assertIn('not separately recorded',view['detail'])
        row['analysis_status']='manual_review'
        self.assertIsNone(incident_view(row,[],NOW)['waiting_until'])

    def test_suspicious_verdict_survives_request_for_more_evidence(self):
        row=incident(None)
        row.update(status='manual_review',analysis_status='manual_review')
        row['report']={'verdict':'SUSPICIOUS','recommended_action':'REQUEST_MORE_EVIDENCE'}
        row['approval']={'status':'notified','plan':None}
        before=deepcopy(row)
        view=incident_view(row,[],NOW)
        self.assertEqual(view['ai_verdict'],'SUSPICIOUS')
        self.assertEqual(view['label'],'More evidence requested')
        self.assertTrue(view['workflow_attention'])
        self.assertEqual(view['progress']['phase']['kind'],'paused')
        self.assertFalse(view['response_approval_required'])
        self.assertIn('No additional evidence collection or firewall response',view['detail'])
        self.assertEqual(row,before)

    def test_inconclusive_ai_verdict_is_distinct_from_workflow(self):
        row=incident(None);row.update(status='manual_review',analysis_status='manual_review')
        row['report']={'verdict':'INSUFFICIENT_EVIDENCE','recommended_action':'REQUEST_MORE_EVIDENCE'}
        view=incident_view(row,[],NOW)
        self.assertEqual(view['ai_verdict'],'INSUFFICIENT_EVIDENCE')
        self.assertEqual(view['label'],'More evidence requested')

    def test_failure_before_a_report_does_not_invent_an_ai_verdict(self):
        row=incident(None);row.update(status='manual_review',analysis_status='manual_review',report=None,error='Evidence collection failed.')
        view=incident_view(row,[],NOW)
        self.assertIsNone(view['ai_verdict'])
        self.assertEqual(view['label'],'Manual review required')
        self.assertEqual(view['detail'],'Evidence collection failed.')
        self.assertTrue(view['workflow_attention'])

    def test_benign_complete_assessment_has_no_review_warning(self):
        row=incident();row['approval']={'status':'notified','plan':None}
        view=incident_view(row,[],NOW)
        self.assertEqual(view['ai_verdict'],'BENIGN')
        self.assertFalse(view['workflow_attention'])
        self.assertEqual(view['label'],'Report delivered')

    def test_persistent_instructions_match_only_supported_scope(self):
        view=plan_view(PLAN,NOW)
        self.assertIn('--mode approved',view['run_instructions']['command'])
        self.assertEqual(view['run_instructions']['waiting_until'],'2026-10-27T17:03:30+00:00')
        for changes in [{'source_ips':['192.168.64.4']},{'allowed_accounts':['root']},
                        {'maximum_failed_attempts':5},{'target_ip':'192.168.64.99'}]:
            self.assertIsNone(plan_view(dict(PLAN,**changes),NOW)['run_instructions']['command'])

    def test_safe_document_keys_allow_recorded_word_sources_only(self):
        word=dict(PLAN,source_document='/tmp/registered-plan.docx',source_sha256='a'*64)
        row=incident(word);row['view']=incident_view(row,[],NOW)
        state={'plans':[],'history':{'incidents':[row]}}
        key=document_key(word)
        self.assertEqual(len(key),32)
        self.assertEqual(document_references(state)[key]['id'],'historical')
        self.assertIsNone(document_key(PLAN))
        self.assertNotIn('/tmp/',key)

    def test_snapshot_reads_live_only_and_never_marks_expired_plan_current(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'plans.json').write_text(json.dumps([PLAN]))
            (root/'runtime.ssh.live.local.json').write_text(json.dumps({'approved_plans':'plans.json'}))
            (root/'live.ssh.local.json').write_text(json.dumps({'source_ips':['192.168.64.8'],'destination_ip':'192.168.64.6'}))
            # Invalid evaluation artifacts must not be read by the dashboard.
            (root/'verification-ssh-release-gated.json').write_text('not JSON')
            (root/'verification-ssh-observed.sqlite3').write_bytes(b'not a database')
            state=snapshot(root)
            self.assertIn('history',state)
            self.assertNotIn('sources',state)
            self.assertNotIn('regressions',state)
            self.assertIsNone(state['next_plan'])
            self.assertFalse((root/'ssh-live.sqlite3').exists())
