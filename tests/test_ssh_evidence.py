import copy
from datetime import datetime
import unittest
from pathlib import Path
from approved_plans import load_plans, select_plan, validate_plan
from ssh_auth_reader import summarize, validate_request

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.plan={'id':'fixture','approval_status':'draft','owner':'operator',
                   'source_ips':['192.168.64.8'],'target_ip':'192.168.64.6','target_port':22,
                   'start':'2026-10-26T18:00:00Z','end':'2026-10-26T18:05:00Z',
                   'allowed_accounts':['soc_test'],'maximum_failed_attempts':10,
                   'scope':'test','stop_conditions':['Stop after ten failures']}
        self.request={'source_ip':'192.168.64.4','target_ip':'192.168.64.6',
                      'start':'2026-10-26T18:00:00Z','end':'2026-10-26T18:01:00Z'}
    def row(self, message, cursor, time='2026-10-26T18:00:30+00:00'):
        return {'MESSAGE':message,'__CURSOR':cursor,
                '__REALTIME_TIMESTAMP':str(int(datetime.fromisoformat(time).timestamp()*1000000))}
    def test_attribution_deduplication_and_no_double_count(self):
        failure=self.row('Failed password for invalid user soc_test from 192.168.64.4 port 123 ssh2','a')
        rows=[failure,failure,self.row('Invalid user soc_test from 192.168.64.4 port 123','b'),
              self.row('Failed password for root from 192.168.64.40 port 123 ssh2','c'),
              self.row('Accepted publickey for victim from 192.168.64.1 port 123 ssh2: key','d'),
              self.row('Accepted password for root from 192.168.64.4 port 124 ssh2','e')]
        result=summarize(self.request,rows)
        self.assertEqual(result['failed_accounts'],{'soc_test':1})
        self.assertEqual(result['successful_accounts'],{'root':1})
        self.assertEqual(result['other_source_messages'],1)
    def test_end_exclusive_and_partial(self):
        row=self.row('Failed password for root from 192.168.64.4 port 123','a','2026-10-26T18:01:00+00:00')
        self.assertEqual(summarize(self.request,[row],True)['failed_password_count'],0)
        self.assertEqual(summarize(self.request,[],True)['coverage'],'partial')
        self.assertNotEqual(summarize(self.request,[])['coverage'],'complete_for_fixture')
    def test_penalties_are_context_not_additional_failed_passwords(self):
        rows=[self.row('Failed password for root from 192.168.64.4 port 123 ssh2','a','2026-10-26T18:00:10+00:00'),
              self.row('Failed password for root from 192.168.64.4 port 124 ssh2','b','2026-10-26T18:00:20+00:00'),
              self.row('drop connection #0 from [192.168.64.4]:55706 on [192.168.64.6]:22 penalty: failed authentication','c'),
              self.row('srclimit_penalise: 192.168.64.4/32: activating ipv4 penalty of 17 seconds for penalty: failed authentication','d'),
              self.row('drop connection #0 from [192.168.64.40]:1 on [192.168.64.6]:22 penalty: failed authentication','e')]
        result=summarize(self.request,rows+rows)
        self.assertEqual(result['failed_password_count'],2)
        self.assertEqual(result['connection_drop_count'],1)
        self.assertEqual(result['penalty_event_count'],1)
        self.assertEqual(result['failed_password_span_seconds'],10)
        self.assertEqual(len(result['protection_events']),2)
    def test_invalid_window_rejected(self):
        self.request['end']='2026-10-26T19:00:00Z'
        with self.assertRaises(ValueError): validate_request(self.request)
    def test_draft_and_overlaps(self):
        plan=copy.deepcopy(self.plan)
        incident=dict(self.request,target_port=22)
        plan['source_ips']=[incident['source_ip']]
        self.assertIsNone(select_plan(incident,[plan]))
        plan['end']='2026-10-26T18:05:00Z'
        plan.update(approval_status='approved',approved_by='Test operator',approved_at='2026-10-26T17:00:00Z')
        validate_plan(plan)
        self.assertEqual(select_plan(incident,[plan]),plan)
        other=copy.deepcopy(plan);other['id']='second'
        with self.assertRaises(ValueError): select_plan(incident,[plan,other])
    def test_approval_metadata_required(self):
        plan=copy.deepcopy(self.plan)
        plan['approval_status']='approved'
        with self.assertRaises(ValueError): validate_plan(plan)
