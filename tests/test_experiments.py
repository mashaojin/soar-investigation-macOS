from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request,urlopen

from experiment_store import ExperimentStore,active_instruction,sha,encode
from ollama_analyst import INSTRUCTION,make_prompt,assessment_payload
from advisory_report import INSTRUCTION as ADVISORY
from ssh_investigation import build_job
from ssh_scenarios import ROOT
from rule_editor import RuleEditor
import soc_rule_helper as helper


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        _,self.job=build_job(ROOT/'approved_test.json')
        self.evidence=dict(source_ip=self.job['authentication']['source_ip'],destination_ip=self.job['authentication']['target_ip'],
            destination_port=22,signature_id=9001001,window_start=self.job['authentication']['start'])
        self.payload=assessment_payload(self.evidence,self.job)
        self.meta=dict(engine='ollama_direct',assessment_data=self.payload,investigation=self.job)
        with closing(sqlite3.connect(self.root/'ssh-live.sqlite3')) as db,db:
            db.executescript('CREATE TABLE incidents(incident_id TEXT,revision INTEGER,evidence TEXT); CREATE TABLE analyses(incident_id TEXT,revision INTEGER,metadata TEXT,prompt_hash TEXT,report TEXT);')
            db.execute('INSERT INTO incidents VALUES(?,?,?)',('saved',1,encode(self.evidence)))
            db.execute('INSERT INTO analyses VALUES(?,?,?,?,?)',('saved',1,encode(self.meta),sha(make_prompt(self.payload)),None))
        self.calls=[];self.store=ExperimentStore(self.root,runner=self.runner);self.addCleanup(self.store.close)

    def runner(self,prompt,settings):
        self.calls.append((prompt,deepcopy(settings)))
        return dict(text='Observed attempts fit the approved test scope [E2, P1].',model='gemma4:e4b')

    def test_save_does_not_activate_and_activate_requires_current_version(self):
        base=active_instruction(self.root)
        candidate=self.store.save_prompt({'text':INSTRUCTION+'Consider alternatives explicitly.','label':'Alternative emphasis'})
        self.assertEqual(active_instruction(self.root)['id'],base['id'])
        self.store.activate({'id':candidate['id'],'expected_active':base['id']})
        self.assertEqual(active_instruction(self.root)['id'],candidate['id'])
        with self.assertRaises(ValueError): self.store.activate({'id':base['id'],'expected_active':base['id']})
        self.store.activate({'id':base['id'],'expected_active':candidate['id']})
        self.assertEqual(active_instruction(self.root)['text'],ADVISORY)

    def test_second_dashboard_cannot_interrupt_running_store(self):
        with self.assertRaisesRegex(RuntimeError,'Another dashboard'):
            ExperimentStore(self.root)

    def test_invalid_prompt_limits_and_unknown_fields_rejected(self):
        for value in ['x','x'*12001,INSTRUCTION+'\x00']:
            with self.assertRaises(ValueError): self.store.save_prompt({'text':value,'label':'bad'})
        with self.assertRaises(ValueError):self.store.save_prompt({'text':INSTRUCTION,'label':'bad','path':'/tmp/other'})

    def test_saved_comparison_frozen_evidence_and_no_production_writes(self):
        before=(self.root/'ssh-live.sqlite3').read_bytes()
        candidate=self.store.save_prompt({'text':INSTRUCTION+'Weigh competing explanations.','label':'Candidate'})
        result=self.store.start_comparison({'incident_id':'saved','prompt_id':candidate['id']})
        self.store.pool.shutdown(wait=True)
        with closing(sqlite3.connect(self.store.path)) as db:
            status,snapshot,report=db.execute('SELECT status,snapshot,result FROM comparisons WHERE id=?',(result['id'],)).fetchone()
        r=json.loads(report);s=json.loads(snapshot)
        self.assertEqual(status,'complete');self.assertEqual(len(self.calls),2)
        self.assertNotEqual(self.calls[0][0],self.calls[1][0])
        self.assertEqual(self.calls[0][1],self.calls[1][1]);self.assertEqual(s['evidence_hash'],sha(encode(self.payload)))
        self.assertTrue(r['responses_disabled']);self.assertEqual(before,(self.root/'ssh-live.sqlite3').read_bytes())
        self.assertEqual(len(r['arms']),2);self.assertEqual(active_instruction(self.root)['text'],ADVISORY)

    def test_live_analyst_uses_active_version_and_records_it(self):
        from analyst import analyze_next
        from datetime import datetime,timezone
        candidate=self.store.save_prompt({'text':INSTRUCTION+'Evaluate timing explicitly.','label':'Timing'})
        self.store.activate({'id':candidate['id'],'expected_active':sha(ADVISORY)})
        with closing(sqlite3.connect(self.root/'ssh-live.sqlite3')) as db,db:
            db.execute('DROP TABLE incidents');db.execute('DROP TABLE analyses')
            db.execute('CREATE TABLE incidents(incident_id TEXT PRIMARY KEY,revision INTEGER,evidence TEXT,alert_count INTEGER,status TEXT)')
            db.execute("INSERT INTO incidents VALUES('saved',1,?,1,'pending')",(encode(self.evidence),))
        with patch('ssh_live_investigation.ready_after',return_value=datetime(2020,1,1,tzinfo=timezone.utc)),patch('ssh_live_investigation.prepare_live_job',return_value=('',self.job)):
            result=analyze_next(self.root/'ssh-live.sqlite3',dict(ssh_enrichment=True,approved_plans='unused'),runner=self.runner)
        self.assertEqual(result['status'],'manual_review');self.assertIn('Evaluate timing explicitly.',self.calls[0][0])
        with closing(sqlite3.connect(self.root/'ssh-live.sqlite3')) as db:
            saved=json.loads(db.execute('SELECT metadata FROM analyses').fetchone()[0])
        self.assertEqual(saved['prompt_version']['id'],candidate['id']);self.assertIn('code_hash',saved['python_context'])

    def test_unknown_original_instruction_is_not_silently_substituted(self):
        with closing(sqlite3.connect(self.root/'ssh-live.sqlite3')) as db,db:db.execute("UPDATE analyses SET prompt_hash='unknown'")
        with self.assertRaisesRegex(ValueError,'reconstructed'):
            self.store.start_comparison({'incident_id':'saved','prompt_id':sha(INSTRUCTION)})

    def test_invalid_model_output_is_retained_for_comparison(self):
        self.store.runner=lambda *args:{'text':'Unrecognized evidence [E99]'}
        self.store.start_comparison({'incident_id':'saved','prompt_id':sha(INSTRUCTION)})
        self.store.pool.shutdown(wait=True)
        r=self.store.state()['comparisons'][0]
        self.assertEqual(r['status'],'needs_review');self.assertEqual(r['result']['arms'][0]['raw_output'],'Unrecognized evidence [E99]')


class RuleHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.rule=self.root/'ssh.rules';self.rule.write_text(helper.DEFAULT)
        self.config=self.root/'suricata.yaml';self.config.write_text('rule-files:\n  - ssh_bruteforce.rules\n  - dvwa_sqli.rules\n')
        self.state=self.root/'state';self.state.mkdir()
        for name,value in [('RULE',self.rule),('CONFIG',self.config),('STATE',self.state)]:
            p=patch.object(helper,name,value);p.start();self.addCleanup(p.stop)
        self.changed=helper.DEFAULT.replace('count 5','count 6').replace('rev:1','rev:2')

    def test_only_fixed_ssh_template_allowed(self):
        self.assertEqual(helper.parse_rule(self.changed)['count'],6)
        for bad in [self.changed.replace('any 22','any 80'),self.changed.replace('9001001','9001002'),
                    self.changed+'\n'+helper.DEFAULT,self.changed.replace('alert tcp','drop tcp'),self.changed.replace('count 6','count 0')]:
            with self.assertRaises(ValueError):helper.parse_rule(bad)

    def test_candidate_validation_does_not_change_rule_or_other_rule_references(self):
        calls=[]
        with patch.object(helper,'run',side_effect=lambda args,**kw:calls.append(args) or ''):
            result=helper.handle(dict(action='validate',text=self.changed,expected_hash=helper.sha(helper.DEFAULT)))
        self.assertTrue(result['valid']);self.assertEqual(self.rule.read_text(),helper.DEFAULT)
        self.assertEqual(calls[0][1:3],['-T','--init-errors-fatal'])

    def test_changed_revision_and_stale_hash_rejected(self):
        for text,h in [(self.changed,'wrong'),(self.changed.replace('rev:2','rev:1'),helper.sha(helper.DEFAULT))]:
            with self.assertRaises(ValueError):helper.handle(dict(action='validate',text=text,expected_hash=h))

    def test_successful_apply_has_backup_and_verified_reload(self):
        with patch.object(helper,'run',return_value='active\n'),patch.object(helper,'socket',return_value=[{'rules_failed':0}]) as socket:
            result=helper.handle(dict(action='apply',text=self.changed,expected_hash=helper.sha(helper.DEFAULT),configuration_hash=helper.sha(self.config.read_text())))
        self.assertEqual(result['status'],'active');self.assertEqual(self.rule.read_text(),self.changed)
        self.assertEqual((self.state/(result['backup_id']+'.rules')).read_text(),helper.DEFAULT)
        self.assertIn(('reload-rules',),[call.args for call in socket.call_args_list])

    def test_reload_failure_restores_previous_file(self):
        with patch.object(helper,'run',return_value='active\n'),patch.object(helper,'socket',side_effect=[RuntimeError('reload failed'),{}]):
            result=helper.handle(dict(action='apply',text=self.changed,expected_hash=helper.sha(helper.DEFAULT),configuration_hash=helper.sha(self.config.read_text())))
        self.assertEqual(result['status'],'rolled_back');self.assertEqual(self.rule.read_text(),helper.DEFAULT)

    def test_failed_rollback_is_reported_as_recovery_required(self):
        with patch.object(helper,'run',return_value='active\n'),patch.object(helper,'socket',side_effect=RuntimeError('socket failed')):
            result=helper.handle(dict(action='apply',text=self.changed,expected_hash=helper.sha(helper.DEFAULT),configuration_hash=helper.sha(self.config.read_text())))
        self.assertEqual(result['status'],'recovery_required')

    def test_restore_previous_rule_uses_fresh_revision(self):
        with patch.object(helper,'run',return_value='active\n'),patch.object(helper,'socket',return_value=[{'rules_failed':0}]):
            applied=helper.handle(dict(action='apply',text=self.changed,expected_hash=helper.sha(helper.DEFAULT),configuration_hash=helper.sha(self.config.read_text())))
            restored=helper.handle(dict(action='restore',expected_hash=helper.sha(self.changed),backup_id=applied['backup_id']))
        self.assertEqual(restored['status'],'active')
        self.assertEqual(helper.parse_rule(self.rule.read_text())['count'],5)
        self.assertEqual(helper.parse_rule(self.rule.read_text())['revision'],3)

    def test_configuration_change_rejects_apply_before_write(self):
        with patch.object(helper,'run',return_value=''):
            with self.assertRaisesRegex(ValueError,'configuration changed'):
                helper.handle(dict(action='apply',text=self.changed,expected_hash=helper.sha(helper.DEFAULT),configuration_hash='stale'))
        self.assertEqual(self.rule.read_text(),helper.DEFAULT)


class RuleHostTests(unittest.TestCase):
    def test_exact_validated_draft_and_single_use_activation(self):
        with tempfile.TemporaryDirectory() as root:
            store=ExperimentStore(root);self.addCleanup(store.close)
            text=helper.DEFAULT;changed=text.replace('count 5','count 6').replace('rev:1','rev:2')
            calls=[]
            def remote(req):
                nonlocal text
                calls.append(req['action'])
                if req['action']=='read':return dict(text=text,hash=helper.sha(text),activation_verified=True,fields=helper.parse_rule(text),last_activation={'activated_at':1.0})
                if req['action']=='validate':return dict(valid=True,configuration_hash='c')
                text=req['text'];return dict(status='active',hash=helper.sha(text))
            editor=RuleEditor(root,remote)
            draft=editor.validate(dict(text=changed,expected_hash=helper.sha(text)))
            self.assertEqual(calls,['read','validate']);self.assertEqual(text,helper.DEFAULT)
            with self.assertRaises(ValueError):editor.apply(dict(id=draft['id'],validation_token='wrong'))
            self.assertEqual(editor.apply(dict(id=draft['id'],validation_token=draft['validation_token']))['status'],'active')
            with self.assertRaises(ValueError):editor.apply(dict(id=draft['id'],validation_token=draft['validation_token']))
            self.assertEqual(calls.count('apply'),1)


class ExperimentHTTPTests(unittest.TestCase):
    def test_new_endpoints_keep_origin_csrf_and_size_guards(self):
        from dashboard import make_server
        with tempfile.TemporaryDirectory() as root:
            server=make_server(root,port=0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                base='http://127.0.0.1:'+str(server.server_port)
                with urlopen(base+'/api/experiments') as response: state=json.load(response)
                self.assertEqual(state['active']['text'],ADVISORY)
                for headers in [{},{'Origin':'https://example.com','X-SOAR-CSRF':server.csrf_token}]:
                    req=Request(base+'/api/prompts/save',data=encode({'text':INSTRUCTION,'label':'Default'}).encode(),headers={'Content-Type':'application/json',**headers})
                    with self.assertRaises(HTTPError) as caught:urlopen(req)
                    self.assertEqual(caught.exception.code,403)
                headers={'Content-Type':'application/json','Origin':base,'X-SOAR-CSRF':server.csrf_token}
                req=Request(base+'/api/prompts/save',data=encode({'text':INSTRUCTION+'Review timing carefully.','label':'Timing'}).encode(),headers=headers)
                with urlopen(req) as response:self.assertEqual(json.load(response)['status'],'saved')
                with self.assertRaises(HTTPError):urlopen(Request(base+'/api/rules/read',data=b'{}',headers=headers))
            finally:server.shutdown();server.server_close();server.experiments.close();thread.join()


if __name__=='__main__':unittest.main()
