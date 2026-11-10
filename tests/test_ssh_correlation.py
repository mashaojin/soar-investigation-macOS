"""Synthetic correlation/evidence/approval integration; no network or model calls."""
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from analyst import analyze_next
from collector import collect
from dashboard_view import incident_view
from incidents import group_events
from response import queue_reports, initialize as response_initialize
from ssh_correlation import scope, recorded_plan, ready_at, CorrelationError
from ssh_live_investigation import prepare_live_job, ready_after

PLAN = dict(id='plan-one', approval_status='approved', owner='operator', approved_by='operator',
    approved_at='2026-11-04T06:40:00Z', source_ips=['192.168.64.8'], target_ip='192.168.64.6',
    target_port=22, start='2026-11-04T06:41:00Z', end='2026-11-04T06:45:00Z',
    allowed_accounts=['soc_test'], maximum_failed_attempts=10, scope='SSH test', stop_conditions=['Stop on a violation'])


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.log=self.root/'eve.json'; self.db=self.root/'state.db'
        self.plans=self.root/'plans.json'; self.plans.write_text(json.dumps([PLAN])); self.log.write_text('')

    def add(self, *times, source='192.168.64.8', destination='192.168.64.6', sid=9001001, group=True):
        with self.log.open('a') as out:
            for t in times:
                out.write(json.dumps(dict(event_type='alert',timestamp='2026-11-04T'+t+'Z',src_ip=source,
                    dest_ip=destination,dest_port=22,alert=dict(signature_id=sid)))+'\n')
        collect(self.log,self.db)
        if group: return group_events(self.db,ssh_plans_path=self.plans)

    def rows(self):
        with closing(sqlite3.connect(self.db)) as db:
            return [(i,json.loads(e),n,r) for i,e,n,r in db.execute('SELECT incident_id,evidence,alert_count,revision FROM incidents ORDER BY json_extract(evidence,\'$.window_start\')')]

    def test_all_plan_minutes_one_investigation_with_restart(self):
        self.add('06:41:10','06:42:35'); first=self.rows()[0][0]
        self.add('06:43:20','06:44:59.999999')
        rows=self.rows(); self.assertEqual(len(rows),1); self.assertEqual(rows[0][0],first)
        self.assertEqual(rows[0][2],4); self.assertEqual(len(rows[0][1]['sample_event_ids']),3)
        self.assertEqual(rows[0][1]['window_start'],'2026-11-04T06:41:00+00:00')
        self.assertEqual(ready_after(rows[0][1],self.plans).isoformat(),'2026-11-04T06:45:30+00:00')
        self.assertEqual(group_events(self.db,ssh_plans_path=self.plans)['grouped'],0)

    def test_unapproved_two_minutes_end_exclusive_and_no_extension(self):
        self.add('06:43:10','06:44:00',source='192.168.64.4')
        original=self.rows()[0]
        self.add('06:45:09.999999','06:45:10',source='192.168.64.4')
        rows=self.rows(); self.assertEqual(len(rows),2); self.assertEqual(rows[0][0],original[0])
        self.assertEqual(rows[0][2],3); self.assertEqual(rows[0][1]['correlation']['end'],'2026-11-04T06:45:10+00:00')
        self.assertEqual(rows[1][1]['correlation']['evidence_start'],rows[0][1]['correlation']['end'])
        self.assertEqual(ready_after(rows[0][1],self.plans).isoformat(),'2026-11-04T06:45:40+00:00')

    def test_sources_targets_and_signatures_are_separate(self):
        self.add('06:43:10'); self.add('06:43:10',source='192.168.64.4')
        self.add('06:43:10',destination='192.168.64.7'); self.add('06:43:10',sid=9001002)
        self.assertEqual(len(self.rows()),4)

    def test_before_within_and_after_plan_are_separate_without_evidence_overlap(self):
        self.add('06:40:40','06:41:00','06:44:59.999999','06:45:00')
        rows=self.rows(); self.assertEqual(len(rows),3)
        self.assertEqual([scope(r[1])['kind'] for r in rows],['fixed_window','approved_plan','fixed_window'])
        self.assertEqual(rows[0][1]['correlation']['end'],rows[1][1]['window_start'])
        self.assertEqual(rows[1][1]['correlation']['end'],rows[2][1]['correlation']['evidence_start'])

    def test_two_plans_same_source_remain_separate(self):
        second=dict(PLAN,id='plan-two',start='2026-11-04T06:45:00Z',end='2026-11-04T06:48:00Z')
        self.plans.write_text(json.dumps([PLAN,second]))
        self.add('06:44:59','06:45:00')
        self.assertEqual([r[1]['correlation']['plan_snapshot']['id'] for r in self.rows()],['plan-one','plan-two'])

    def test_out_of_order_batch_and_late_context_do_not_create_duplicate(self):
        self.add('06:44:00','06:43:10',source='192.168.64.4')
        self.assertEqual(self.rows()[0][1]['window_start'],'2026-11-04T06:43:10+00:00')
        self.add('06:42:45',source='192.168.64.4')
        self.assertEqual(len(self.rows()),1); self.assertEqual(self.rows()[0][2],3)

    def test_late_older_window_does_not_overlap_existing_evidence(self):
        self.add('06:45:00',source='192.168.64.4')
        self.add('06:43:30',source='192.168.64.4')
        rows=self.rows(); self.assertEqual(len(rows),2)
        self.assertEqual(rows[0][1]['correlation']['end'],rows[1][1]['correlation']['evidence_start'])

    def test_plan_revoked_or_changed_requires_review(self):
        self.add('06:43:10'); evidence=self.rows()[0][1]
        for changed in [dict(PLAN,approval_status='revoked'),dict(PLAN,allowed_accounts=['root'])]:
            self.plans.write_text(json.dumps([changed]))
            with self.assertRaisesRegex(ValueError,'changed or was revoked'):
                prepare_live_job('i',evidence,self.plans,collector=lambda _:self.fail('No collection from changed scope'))

    def test_new_authorization_does_not_retroactively_bless_fixed_window(self):
        self.plans.write_text('[]'); self.add('06:43:10')
        evidence=self.rows()[0][1]
        self.plans.write_text(json.dumps([PLAN]))
        with self.assertRaisesRegex(ValueError,'Authorization changed'):
            ready_after(evidence,self.plans)

    def test_ambiguous_plans_do_not_discard_pending_alert(self):
        self.plans.write_text(json.dumps([PLAN,dict(PLAN,id='overlapping')]))
        with self.assertRaises(CorrelationError): self.add('06:43:10')
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM grouped_events').fetchone()[0],0)
        self.plans.write_text(json.dumps([PLAN])); self.assertEqual(group_events(self.db,ssh_plans_path=self.plans)['grouped'],1)

    def test_historical_incident_and_group_mapping_unchanged(self):
        self.add('06:43:10'); row=self.rows()[0]
        with closing(sqlite3.connect(self.db)) as db,db:
            db.execute('DELETE FROM ssh_correlations')
            historical=dict(row[1]); historical.pop('correlation')
            db.execute("UPDATE incidents SET incident_id='legacy-minute-id',evidence=?",(json.dumps(historical),))
            db.execute("UPDATE grouped_events SET incident_id='legacy-minute-id'")
        self.add('06:44:10')
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(json.loads(db.execute('SELECT evidence FROM incidents WHERE incident_id=?',('legacy-minute-id',)).fetchone()[0]),historical)
        self.assertEqual(len(self.rows()),2)

    def collector(self,request):
        return dict(request,coverage='observed_window',limited=False,failed_accounts={'root':1,'soc_test':17},
                    failed_password_count=18,successful_accounts={},successful_login_count=0,
                    coverage_checks={k:True for k in ('query_not_limited','retained_entry_before_start','root_service_records','window_elapsed')})

    def runner(self,prompt,settings):
        self.calls+=1
        return dict(text='Assessment: Suspicious. Root attempts are outside the approved scope [E2, P1]. Request a block.',
                    model='gemma4:e4b',request_count=1)

    def analyze(self,now='2026-11-04T06:46:00+00:00'):
        from ssh_live_investigation import prepare_live_job as prepare
        with patch('ssh_live_investigation.prepare_live_job',side_effect=lambda i,e,p:prepare(i,e,p,self.collector)):
            return analyze_next(self.db,dict(ssh_enrichment=True,approved_plans=str(self.plans),attack_retrieval=False),
                now=datetime.fromisoformat(now),runner=self.runner)

    def test_plan_three_alert_minutes_one_advisory_per_revision(self):
        self.add('06:41:10','06:42:10','06:43:10'); self.calls=0
        self.assertEqual(self.analyze('2026-11-04T06:45:29+00:00')['status'],'idle')
        self.assertEqual(self.analyze()['status'],'manual_review'); self.assertEqual(self.analyze()['status'],'idle'); self.assertEqual(self.calls,1)
        policy=dict(mode='dry_run',duration_seconds=60,approval_ttl_seconds=600,victim_ip='192.168.64.6',
            allowed_attacker_ips=['192.168.64.8'],protected_ips=['192.168.64.1','192.168.64.6'],destination_port=22)
        identity=dict(bot_key='synthetic',chat_id=1,user_id=1)
        now=int(datetime(2026,11,4,6,46,tzinfo=timezone.utc).timestamp())
        self.assertEqual(queue_reports(self.db,policy,identity,now=now),0)
        self.assertEqual(queue_reports(self.db,policy,identity,now=now),0)
        self.add('06:44:10')
        self.assertEqual(len(self.rows()),1); self.assertEqual(self.analyze()['status'],'manual_review')
        self.assertEqual(self.calls,2)
        self.assertEqual(queue_reports(self.db,policy,identity,now=now),0)

    def test_advisory_cannot_create_live_claim(self):
        from live_response import claim
        self.add('06:41:10','06:42:10','06:43:10'); self.calls=0
        self.assertEqual(self.analyze()['status'],'manual_review')
        policy=dict(mode='live',duration_seconds=60,approval_ttl_seconds=600,
            live_enabled_after='2026-11-04T06:40:00+00:00',victim_ip='192.168.64.6',
            allowed_attacker_ips=['192.168.64.8'],protected_ips=['192.168.64.1','192.168.64.6'],destination_port=22)
        identity=dict(bot_key='synthetic',chat_id=1,user_id=1)
        now=int(datetime(2026,11,4,6,46,tzinfo=timezone.utc).timestamp())
        self.assertEqual(queue_reports(self.db,policy,identity,now=now),0)
        self.assertIsNone(claim(self.db,policy,identity,now=now))
        self.assertEqual(queue_reports(self.db,policy,identity,now=now),0)

    def test_monitor_passes_runtime_plan_registry_to_collection(self):
        import monitor
        configs=[]
        def collect_once(config,db):
            configs.append(config)
            return {'has_more':False}
        with patch('monitor.collect_once',side_effect=collect_once), patch('monitor.analyze_next',return_value={'status':'idle'}):
            self.assertEqual(monitor.run({'poll_seconds':1},str(self.db),
                {'ssh_enrichment':True,'approved_plans':str(self.plans)},duration=0.1),0)
        self.assertTrue(configs); self.assertEqual(configs[0]['approved_plans'],str(self.plans))

    def test_exact_auth_interval_and_dashboard_deadline(self):
        self.add('06:43:10',source='192.168.64.4'); i,e,n,r=self.rows()[0]
        _,job=prepare_live_job(i,e,self.plans,self.collector)
        self.assertEqual(job['authentication']['start'],'2026-11-04T06:42:10+00:00')
        self.assertEqual(job['authentication']['end'],'2026-11-04T06:45:10+00:00')
        row=dict(incident_id=i,evidence=e,status='pending')
        view=incident_view(row,[PLAN],datetime(2026,11,4,6,44,tzinfo=timezone.utc))
        self.assertEqual(view['waiting_until'],'2026-11-04T06:45:40+00:00')
        self.assertEqual(view['progress']['phase']['kind'],'determinate')
        self.assertEqual(incident_view(row,[PLAN],datetime(2026,11,4,6,45,40,tzinfo=timezone.utc))['status'],'queued')

    def test_unapproved_analysis_waits_for_end_plus_thirty_seconds(self):
        self.add('06:43:10',source='192.168.64.4'); self.calls=0
        self.assertEqual(self.analyze('2026-11-04T06:45:39+00:00')['status'],'idle')
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM analyses').fetchone()[0],0)

    def test_oldest_ready_incident_is_processed_first(self):
        self.add('06:43:10',source='192.168.64.4'); older=self.rows()[0][0]
        self.add('06:44:00'); self.calls=0
        # Plan ready at :45:30; Kali ready at :45:40. Ready-time FIFO wins over hashes.
        plan_id=next(r[0] for r in self.rows() if r[1]['source_ip']=='192.168.64.8')
        self.assertEqual(self.analyze()['incident_id'],plan_id)
        self.assertEqual(self.analyze()['incident_id'],older)


if __name__=='__main__': unittest.main()
