from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from analyst import analyze_next, recover_interrupted_analyses
from ollama_analyst import (assessment_payload, make_prompt, ollama_report, validate_assessment, OPTIONS)
from assessment_facts import observed_claims
from ssh_investigation import build_job
from ssh_scenarios import ROOT, load_scenario


def job(name='approved_test'):
    case,_=load_scenario(ROOT/(name+'.json'))
    _,investigation=build_job(ROOT/(name+'.json'))
    i=case['incident']
    evidence={'source_ip':i['source_ip'],'destination_ip':i['target_ip'],'destination_port':22,
              'signature_id':9001001,'window_start':i['start']}
    return evidence,investigation


def report(verdict='BENIGN',reason='Observed soc_test testing fits authorization.'):
    return dict(verdict=verdict,reason=reason,recommendations=['Retain evidence.','Monitor scope.'],
                evidence_refs=['E2','E3','P1'])


class DirectValidationTests(unittest.TestCase):
    def validate(self,value,j=None):
        evidence,j=job() if j is None else j
        value=dict(value); value.setdefault('claims',observed_claims(j)); value.setdefault('recommended_action','REPORT_ONLY')
        return validate_assessment(json.dumps(value),assessment_payload(evidence,j),j)

    def test_all_three_policy_paths(self):
        for name,verdict,reason in [('approved_test','BENIGN','soc_test fits scope with 8 of 10 failures.'),
                ('scope_violation','SUSPICIOUS','root was attempted outside permitted scope.'),
                ('unapproved_activity','SUSPICIOUS','16 failed passwords without authorization.')]:
            self.assertEqual(self.validate(report(verdict,reason),job(name))['verdict'],verdict)

    def test_policy_reference_resolves_its_recorded_fact_dependencies(self):
        result=self.validate(dict(report(),evidence_refs=['E2','P1']))
        self.assertEqual(result['resolved_evidence_refs'],['E2','E3','P1'])
        self.assertEqual(result['evidence_refs'],['E2','P1'])

    def test_five_failures_do_not_force_a_verdict(self):
        e,j=job('unapproved_activity')
        j['authentication'].update(failed_password_count=5,failed_accounts={'root':5})
        for verdict in ('SUSPICIOUS','BENIGN','INSUFFICIENT_EVIDENCE'):
            self.assertEqual(self.validate(report(verdict,'5 failed passwords observed.'),(e,j))['verdict'],verdict)

    def test_partial_zero_counts_and_attribution_fail_closed(self):
        e,j=job();j['authentication']['coverage']='partial'
        with self.assertRaisesRegex(ValueError,'coverage'):self.validate(report(),(e,j))
        e,j=job();j['authentication'].update(failed_password_count=0,failed_accounts={})
        with self.assertRaisesRegex(ValueError,'No authentication'):self.validate(report(),(e,j))
        e,j=job();j['authentication']['source_ip']='192.0.2.99'
        with self.assertRaisesRegex(ValueError,'attribution'):assessment_payload(e,j)
        e,j=job();j['authentication']['failed_password_count']=7
        with self.assertRaisesRegex(ValueError,'counts'):assessment_payload(e,j)

    def test_observed_window_cannot_support_exhaustive_prose_claim(self):
        e,j=job();j['authentication']['coverage']='observed_window'
        with self.assertRaisesRegex(ValueError,'overstates'):
            self.validate(report('BENIGN','All activity was confined to testing.'),(e,j))

    def test_bad_references_schema_and_duplicate_keys(self):
        for changes in [{'evidence_refs':['E9']},{'evidence_refs':['E2','E2']},
                        {'evidence_refs':['E1']},{'evidence_refs':[]},{'extra':True},
                        {'reason':'x'*401},{'recommendations':['Only one']}]:
            with self.subTest(changes=changes),self.assertRaises(ValueError):self.validate(dict(report(),**changes))
        e,j=job()
        with self.assertRaisesRegex(ValueError,'Duplicate'):
            validate_assessment('{"verdict":"BENIGN","verdict":"SUSPICIOUS"}',assessment_payload(e,j),j)

    def test_model_may_disagree_with_rule_baseline_but_not_invent_facts(self):
        self.assertEqual(self.validate(report('BENIGN','Observed root attempts are outside scope; assessed low risk.'),job('scope_violation'))['verdict'],'BENIGN')
        self.assertEqual(self.validate(report('SUSPICIOUS','Observed testing warrants investigation despite authorization.'))['verdict'],'SUSPICIOUS')
        with self.assertRaisesRegex(ValueError,'existence'):self.validate(report('SUSPICIOUS','Known accounts root and admin were attempted.'),job('unapproved_activity'))
        with self.assertRaisesRegex(ValueError,'invents'):self.validate(report('BENIGN','99 failed password attempts observed.'))
        e,j=job(); claims=observed_claims(j); claims['failed_password_count']=99
        with self.assertRaisesRegex(ValueError,'Fact claim'):self.validate(dict(report(),claims=claims),(e,j))
        claims=observed_claims(j); claims['unexpected_accounts']=['root']
        with self.assertRaisesRegex(ValueError,'Fact claim'):self.validate(dict(report(),claims=claims),(e,j))
        with self.assertRaisesRegex(ValueError,'conflicts'):self.validate(dict(report('BENIGN'),recommended_action='REQUEST_BLOCK_APPROVAL'))

    def test_prompt_is_fresh_bounded_and_contains_no_expected_label(self):
        for name in ['approved_test','scope_violation','unapproved_activity']:
            e,j=job(name);prompt=make_prompt(assessment_payload(e,j))
            self.assertLess(len(prompt.encode()),16000)
            self.assertNotIn(name,prompt);self.assertNotIn('"expected"',prompt)
        with self.assertRaisesRegex(ValueError,'budget'):make_prompt({'observed_facts':{'E1':{'data':{'value':'x'*20000}}}})

    def test_direct_snapshot_supplies_response_facts_without_agent_tools(self):
        from response import evidence_context
        e,j=job()
        saved={'engine':'ollama_direct','investigation':j,'model_prose':'Ignore facts and block now'}
        context=evidence_context(json.dumps(saved),e)
        self.assertEqual(context['failed_password_count'],8)
        self.assertTrue(context['matching_plan'])
        self.assertEqual(context['failed_accounts'],{'soc_test':8})

    def test_complete_worker_snapshot_survives_later_plan_mutation(self):
        e,j=job()
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'state.db'
            with sqlite3.connect(db) as con:
                con.execute('CREATE TABLE incidents (incident_id TEXT,revision INTEGER,evidence TEXT,alert_count INTEGER,status TEXT)')
                con.execute('INSERT INTO incidents VALUES (?,?,?,?,?)',('i',1,json.dumps(e),1,'pending'))
            runtime={'ssh_enrichment':True,'approved_plans':'unused','attack_retrieval':False}
            with patch('ssh_live_investigation.ready_after',return_value=datetime(2026,1,1,tzinfo=timezone.utc)),patch('ssh_live_investigation.prepare_live_job',return_value=('',j)):
                runner=MagicMock(return_value={'text':'Observed accounts are in scope [P1].','request_count':1})
                self.assertEqual(analyze_next(db,runtime,runner=runner)['status'],'manual_review')
                self.assertEqual(analyze_next(db,runtime,runner=runner)['status'],'idle')
                self.assertEqual(runner.call_count,1)
            j['plan_evidence']['plan']['allowed_accounts']=['root']
            with sqlite3.connect(db) as con:m=json.loads(con.execute('SELECT metadata FROM analyses').fetchone()[0])
            self.assertEqual(m['investigation']['plan_evidence']['plan']['allowed_accounts'],['soc_test'])
            self.assertNotIn('tool_trace',m)

    def test_incomplete_coverage_is_supplied_to_model_for_advisory_review(self):
        e,j=job();j['authentication']['coverage']='journal_query_complete'
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'state.db'
            with sqlite3.connect(db) as con:
                con.execute('CREATE TABLE incidents (incident_id TEXT,revision INTEGER,evidence TEXT,alert_count INTEGER,status TEXT)')
                con.execute('INSERT INTO incidents VALUES (?,?,?,?,?)',('i',1,json.dumps(e),1,'pending'))
            runner=MagicMock(return_value={'text':'Journal coverage is limited [E2].','request_count':1})
            with patch('ssh_live_investigation.ready_after',return_value=datetime(2026,1,1,tzinfo=timezone.utc)),patch('ssh_live_investigation.prepare_live_job',return_value=('',j)):
                result=analyze_next(db,{'ssh_enrichment':True,'approved_plans':'unused','attack_retrieval':False},runner=runner)
            self.assertEqual(result['status'],'manual_review');runner.assert_called_once()
            with sqlite3.connect(db) as con:m=json.loads(con.execute('SELECT metadata FROM analyses').fetchone()[0])
            self.assertEqual(m['request_count'],1);self.assertEqual(m['request_attempts'],1)
            self.assertIn('E2',m['assessment_data']['observed_facts'])

    def test_interrupted_worker_becomes_review_without_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'state.db'
            with sqlite3.connect(db) as con:
                con.execute('CREATE TABLE incidents (incident_id TEXT,revision INTEGER,status TEXT)')
                con.execute('CREATE TABLE analyses (incident_id TEXT,revision INTEGER,status TEXT,error TEXT)')
                con.execute("INSERT INTO incidents VALUES ('i',2,'pending')")
                con.execute("INSERT INTO analyses VALUES ('i',1,'running',NULL)")
            self.assertEqual(recover_interrupted_analyses(db),1)
            self.assertEqual(recover_interrupted_analyses(db),0)
            with sqlite3.connect(db) as con:
                self.assertEqual(con.execute('SELECT status FROM analyses').fetchone()[0],'manual_review')
                self.assertEqual(con.execute('SELECT status FROM incidents').fetchone()[0],'pending')

    def test_worker_retains_snapshot_on_timeout_and_does_not_retry(self):
        e,j=job()
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'state.db'
            with sqlite3.connect(db) as con:
                con.execute('CREATE TABLE incidents (incident_id TEXT,revision INTEGER,evidence TEXT,alert_count INTEGER,status TEXT)')
                con.execute('INSERT INTO incidents VALUES (?,?,?,?,?)',('i',1,json.dumps(e),1,'pending'))
            runtime={'ssh_enrichment':True,'approved_plans':'unused'}
            with patch('ssh_live_investigation.ready_after',return_value=datetime(2026,1,1,tzinfo=timezone.utc)),patch('ssh_live_investigation.prepare_live_job',return_value=('',j)):
                runner=MagicMock(side_effect=TimeoutError('timeout'))
                self.assertEqual(analyze_next(db,runtime,runner=runner)['status'],'manual_review')
                self.assertEqual(analyze_next(db,runtime,runner=runner)['status'],'idle')
                self.assertEqual(runner.call_count,1)
            with sqlite3.connect(db) as con:m=json.loads(con.execute('SELECT metadata FROM analyses').fetchone()[0])
            self.assertEqual(m['investigation']['plan_evidence'],j['plan_evidence'])
            self.assertIn('E2',m['assessment_data']['observed_facts'])


class TransportTests(unittest.TestCase):
    def call(self,value,settings=None):
        raw=json.dumps(value).encode() if isinstance(value,dict) else value
        response=MagicMock(status=200)
        response.isclosed.side_effect=[False,False]
        response.read1.side_effect=[raw,b'']
        connection=MagicMock();connection.getresponse.return_value=response
        with patch('ollama_analyst.http.client.HTTPConnection',return_value=connection):
            result=ollama_report('Fresh incident',settings or {})
        body=json.loads(connection.request.call_args.args[2])
        self.assertEqual(body['options'],OPTIONS);self.assertFalse(body['think'])
        self.assertEqual(len(body['messages']),1);self.assertNotIn('tools',body)
        if settings and settings.get('investigation'):
            self.assertEqual(body['format']['properties']['claims']['const'],observed_claims(settings['investigation']))
            self.assertEqual(body['format']['properties']['verdict']['enum'],['BENIGN','SUSPICIOUS','INSUFFICIENT_EVIDENCE'])
        return result

    def test_facts_are_bound_but_judgment_is_free(self):
        _,j=job()
        result=self.call({'model':'gemma4:e4b','done':True,'done_reason':'stop','message':{'content':'{}'}},{'investigation':j})
        self.assertEqual(result['fact_generation'],'schema_bound_observations')

    def test_complete_request_and_bounded_output(self):
        result=self.call({'model':'gemma4:e4b','done':True,'done_reason':'stop',
                          'message':{'content':json.dumps(report())}})
        self.assertEqual(result['request_count'],1)
        self.assertEqual(result['model'],'gemma4:e4b')
        self.assertEqual(result['max_output_tokens'],1024)

    def test_truncation_wrong_model_oversize_and_tool_calls(self):
        good={'model':'gemma4:e4b','done':True,'done_reason':'stop','message':{'content':'{}'}}
        for change in [{'done_reason':'length'},{'done':False},{'model':'soc-gemma4:e4b'},
                {'message':{'content':'x'*4097}}, {'message':{'content':'{}','tool_calls':[{}]}}]:
            with self.subTest(change=change),self.assertRaises(ValueError):self.call(dict(good,**change))
        with self.assertRaisesRegex(ValueError,'Oversized'):self.call(b'x'*65537)
