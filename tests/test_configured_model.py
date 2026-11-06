from copy import deepcopy
import json
import time
from datetime import datetime,timezone
import unittest
from unittest.mock import patch
from ollama_analyst import ollama_report,model_config
from test_direct_gemma import job
from test_windows_profile import windows


class ConfiguredModelTests(unittest.TestCase):
    def settings(self):return {'lab_profile':windows()}

    def good(self):return dict(model='gemma3:1b',done=True,done_reason='stop',message={'content':'{}'},prompt_eval_count=3000,eval_count=100)

    def test_configured_identity_and_no_truncation_flags(self):
        with patch('ollama_analyst.request_json',return_value=self.good()) as api:
            result=ollama_report('Synthetic fixed prompt',self.settings())
        body=api.call_args.args[2]
        self.assertEqual(body['model'],'gemma3:1b');self.assertEqual(body['options']['num_ctx'],8192)
        self.assertEqual(body['options']['num_predict'],1024);self.assertEqual(body['options']['num_thread'],2)
        self.assertIs(body['truncate'],False);self.assertIs(body['shift'],False)
        self.assertTrue(result['context_budget_verified'])

    def test_returned_model_cannot_select_trust_or_override_operator_config(self):
        for name in ['gemma3:latest','gemma4:e4b','soc-gemma3:1b']:
            with patch('ollama_analyst.request_json',return_value=dict(self.good(),model=name)),self.assertRaisesRegex(ValueError,'identity mismatch'):
                ollama_report('Synthetic prompt',self.settings())
        with self.assertRaisesRegex(ValueError,'differ'):
            model_config(dict(self.settings(),ollama={'model':'gemma3:latest'}))

    def test_cpu_threads_are_trusted_bounded_and_keep_two_thread_default(self):
        self.assertEqual(model_config(self.settings())[1]['num_thread'],2)
        settings=self.settings();settings['lab_profile']['ollama']['num_thread']=4
        self.assertEqual(model_config(settings)[1]['num_thread'],4)
        for value in (0,5,True,'4'):
            settings=self.settings();settings['lab_profile']['ollama']['num_thread']=value
            with self.subTest(value=value),self.assertRaises(ValueError):model_config(settings)
        with self.assertRaisesRegex(ValueError,'differ'):
            model_config(dict(self.settings(),ollama={'num_thread':4}))

    def test_missing_and_over_budget_metrics_fail_closed(self):
        for fields in [{'prompt_eval_count':None},{'prompt_eval_count':True},{'prompt_eval_count':8000},
                       {'eval_count':1025},{'done_reason':'length'},{'done':False}]:
            with patch('ollama_analyst.request_json',return_value=dict(self.good(),**fields)),self.assertRaises(ValueError):
                ollama_report('Synthetic prompt',self.settings())

    def test_required_fact_output_must_fit_before_request(self):
        _,investigation=job();investigation=deepcopy(investigation)
        investigation['authentication']['failed_accounts']={('account_'+str(i)+'x'*45):1 for i in range(32)}
        investigation['authentication']['failed_password_count']=32
        from ssh_investigation import compare_scope
        pe=investigation['plan_evidence']
        pe['scope_comparison']=compare_scope(investigation['authentication'],pe['plan'],pe['checks'])
        with patch('ollama_analyst.request_json') as api,self.assertRaisesRegex(ValueError,'Required structured facts'):
            ollama_report('Synthetic prompt',dict(self.settings(),investigation=investigation))
        api.assert_not_called()

    def test_claims_first_preserves_facts_and_free_judgment(self):
        _,investigation=job()
        settings=dict(self.settings(),ollama={'claims_first':True},investigation=investigation)
        with patch('ollama_analyst.request_json',return_value=self.good()) as api:
            ollama_report('Synthetic prompt',settings)
        schema=api.call_args.args[2]['format']
        self.assertEqual(next(iter(schema['properties'])),'claims')
        self.assertEqual(schema['properties']['verdict']['enum'],['BENIGN','SUSPICIOUS','INSUFFICIENT_EVIDENCE'])
        from assessment_facts import observed_claims
        self.assertEqual(schema['properties']['claims'],{'const':observed_claims(investigation)})

    def test_live_evidence_uses_trusted_configured_identity_not_report_text(self):
        from live_response import validate_live_evidence
        from assessment_facts import VERSION,observed_claims
        from lab_config import sources,protected
        lab=windows();now=datetime(2030,1,1,tzinfo=timezone.utc).timestamp()
        evidence=dict(window_start=datetime.fromtimestamp(now-180,timezone.utc).isoformat(),source_ip=lab['attacker']['ip'],destination_ip=lab['victim']['ip'])
        auth=dict(source_ip=lab['attacker']['ip'],target_ip=lab['victim']['ip'],coverage='observed_window',limited=False,
                  failed_password_count=6,failed_accounts={'invalid_fixture':6},successful_login_count=0,
                  coverage_checks={k:True for k in ('query_not_limited','retained_entry_before_start','root_service_records','window_elapsed')})
        investigation=dict(kind='ssh',origin='live_read_only',authentication=auth,plan_evidence={'plan':None,'checks':{},'scope_comparison':{}})
        metadata=dict(engine='ollama_direct',model='gemma3:1b',investigation=investigation,assessment_version=VERSION)
        report=dict(verdict='SUSPICIOUS',coverage='observed_window',recommended_action='REQUEST_BLOCK_APPROVAL',claims=observed_claims(investigation),assessment_version=VERSION)
        policy=dict(lab_profile=lab,live_enabled_after=datetime.fromtimestamp(now-600,timezone.utc).isoformat(),allowed_attacker_ips=sources(lab),protected_ips=protected(lab))
        validate_live_evidence(evidence,report,metadata,policy,now)
        with self.assertRaises(ValueError):validate_live_evidence(evidence,dict(report,model='gemma3:1b'),dict(metadata,model='gemma4:e4b'),policy,now)
