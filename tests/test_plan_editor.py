from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from approved_plans import load_plans, select_plan
from dashboard import make_server
from plan_editor import PlanEditor
from ssh_live_investigation import prepare_live_job


class EditorFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'plans').mkdir()
        source = Path(__file__).parents[1]
        (self.root/'live.ssh.local.json').write_text(json.dumps({
            'source_ips':['192.168.64.4','192.168.64.8'],'destination_ip':'192.168.64.6'}))
        (self.root/'runtime.ssh.live.local.json').write_text(json.dumps({'approved_plans':'plans/word-plans.json'}))
        self.registry = self.root/'plans/word-plans.json'
        self.registry.write_text('[]')
        self.editor = PlanEditor(self.root)
        self.now = datetime.now(timezone.utc).replace(second=0,microsecond=0)
        self.start = self.now+timedelta(minutes=3)
        self.end = self.start+timedelta(minutes=3)
        self.fields = {'owner':'Test operator','source_ip':'192.168.64.8','target_ip':'192.168.64.6',
                       'allowed_accounts':'soc_test', 'maximum_failed_attempts':10,
                       'start':self.start.isoformat(),'end':self.end.isoformat()}


class EditorTests(EditorFixture, unittest.TestCase):
    def test_validation_is_not_approval_and_word_roundtrips(self):
        result = self.editor.validate(self.fields)
        self.assertEqual(load_plans(self.registry),[])
        self.assertEqual(result['plan']['approval_status'],'draft')
        self.assertEqual(result['plan']['source_format'],'dashboard_native')
        self.assertNotIn('document_url',result)
        self.assertNotIn('source_document',result['plan'])
        self.assertNotIn('TO BE CONFIRMED',str(result))

    def test_approval_is_idempotent_and_live_monitor_reads_document(self):
        result = self.editor.validate(self.fields)
        plan = self.editor.approve(result['draft_id'],result['validation_token'])
        self.assertEqual(self.editor.approve(result['draft_id'],result['validation_token']),plan)
        self.assertEqual(len(json.loads(self.registry.read_text())),1)
        evidence={'signature_id':9001001,'destination_port':22,'source_ip':'192.168.64.8',
                  'destination_ip':'192.168.64.6','window_start':self.start.isoformat()}
        def collector(request):
            return dict(request,coverage='observed_window',
                        coverage_checks=dict.fromkeys(('retained_entry_before_start','window_elapsed','root_service_records','query_not_limited'),True),
                        failed_accounts={'root':1,'soc_test':5},failed_password_count=6,
                        successful_login_count=0,successful_accounts={})
        _, job = prepare_live_job('test',evidence,self.registry,collector)
        self.assertEqual(job['plan_evidence']['plan']['id'],plan['id'])
        self.assertEqual(job['plan_evidence']['scope_comparison']['unexpected_accounts'],['root'])
        self.assertEqual(job['authentication']['counting_scope'],'entire_approved_plan')

    def test_bad_token_or_legacy_draft_cannot_approve(self):
        result=self.editor.validate(self.fields)
        with self.assertRaises(ValueError): self.editor.approve(result['draft_id'],'wrong')
        with self.assertRaises(ValueError): self.editor.approve('0'*32,result['validation_token'])
        self.assertEqual(load_plans(self.registry),[])

    def test_expired_preview_cannot_approve(self):
        result=self.editor.validate(self.fields)
        with self.assertRaisesRegex(ValueError,'expired'):
            self.editor.approve(result['draft_id'],result['validation_token'],self.start)
        self.assertEqual(load_plans(self.registry),[])

    def test_invalid_scope_is_rejected(self):
        cases=[{'source_ip':'192.168.64.99'},{'target_ip':'192.168.64.1'},
               {'allowed_accounts':'root; rm -rf /'}, {'maximum_failed_attempts':True},
               {'maximum_failed_attempts':0},{'owner':''},
               {'start':self.now.isoformat()}, {'end':(self.start+timedelta(minutes=11)).isoformat()},
               {'start':(self.start+timedelta(seconds=1)).isoformat()},
               {'start':'2026-10-28T18:00:00'}, {'document':'/tmp/arbitrary.docx'}]
        for changes in cases:
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                self.editor.validate(dict(self.fields,**changes))

    def test_overlapping_plan_rejected_at_both_stages(self):
        first=self.editor.validate(self.fields)
        second=self.editor.validate(self.fields)
        self.editor.approve(first['draft_id'],first['validation_token'])
        with self.assertRaisesRegex(ValueError,'[Oo]verlap'): self.editor.validate(self.fields)
        with self.assertRaisesRegex(ValueError,'Overlapping'):
            self.editor.approve(second['draft_id'],second['validation_token'])

    def test_parallel_approval_records_once(self):
        draft=self.editor.validate(self.fields)
        results=[]
        def submit(): results.append(self.editor.approve(draft['draft_id'],draft['validation_token']))
        threads=[threading.Thread(target=submit) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(len(results),2)
        self.assertEqual(results[0],results[1])
        self.assertEqual(len(load_plans(self.registry)),1)


class EditorHTTPTests(EditorFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.server=make_server(self.root,port=0)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.base='http://127.0.0.1:'+str(self.server.server_port)
        with urlopen(self.base+'/api/state') as response:
            self.token=json.load(response)['csrf_token']

    def close_server(self):
        self.server.shutdown();self.server.server_close();self.thread.join()

    def request(self,path,data,**headers):
        return Request(self.base+path,data=json.dumps(data).encode(),headers={
            'Content-Type':'application/json','Origin':self.base,'X-SOAR-CSRF':self.token,**headers})

    def test_http_validate_review_approve_and_download(self):
        with urlopen(self.request('/api/plans/validate',self.fields)) as response: draft=json.load(response)
        self.assertNotIn('document_url',draft)
        with self.assertRaises(HTTPError) as caught: urlopen(self.base+'/api/plans/'+draft['draft_id']+'/document')
        self.assertEqual(caught.exception.code,404)
        self.assertEqual(load_plans(self.registry),[])
        with urlopen(self.request('/api/plans/approve',{
                'draft_id':draft['draft_id'],'validation_token':draft['validation_token']})) as response:
            self.assertEqual(json.load(response)['plan']['approval_status'],'approved')
        with urlopen(self.base+'/api/state') as response:
            state=json.load(response)
            self.assertEqual(len(state['plans']),1)
        self.assertNotIn('document_url',state['plans'][0])
        self.assertIsNotNone(state['plans'][0]['run_instructions']['command'])

    def test_word_endpoints_are_not_exposed(self):
        for path in ['/api/plan-documents/'+'a'*32,'/api/plans/'+'a'*32+'/document']:
            with self.assertRaises(HTTPError) as caught: urlopen(self.base+path)
            self.assertEqual(caught.exception.code,404)

    def test_cross_origin_missing_token_and_arbitrary_paths_rejected(self):
        for request in [self.request('/api/plans/validate',self.fields,Origin='https://untrusted.example'),
                        self.request('/api/plans/validate',self.fields,**{'X-SOAR-CSRF':''}),
                        self.request('/api/plans/validate',self.fields,Host='untrusted.example')]:
            with self.assertRaises(HTTPError) as caught: urlopen(request)
            self.assertEqual(caught.exception.code,403)
        for path in ['/api/plans/approve/firewall','/api/plans/../../runtime.ssh.live.local.json','/runtime.ssh.live.local.json']:
            with self.assertRaises(HTTPError) as caught: urlopen(self.base+path)
            self.assertEqual(caught.exception.code,404)

    def test_unvalidated_approval_and_oversized_body_rejected(self):
        with self.assertRaises(HTTPError) as caught:
            urlopen(self.request('/api/plans/approve',{'draft_id':'0'*32,'validation_token':'x'}))
        self.assertEqual(caught.exception.code,400)
        with self.assertRaises(HTTPError) as caught:
            urlopen(self.request('/api/plans/validate',{'large':'x'*9000}))
        self.assertEqual(caught.exception.code,413)
