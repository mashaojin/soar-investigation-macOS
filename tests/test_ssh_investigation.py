import json
import unittest
from ssh_scenarios import ROOT
from ssh_investigation import build_job, validate_investigation

class SSHInvestigationTests(unittest.TestCase):
    def test_labels_are_not_sent_to_agent(self):
        for path in ROOT.glob('*.json'):
            prompt, tools = build_job(path)
            wire = prompt + json.dumps(tools)
            self.assertNotIn(path.stem, wire)
            self.assertNotIn('expected', tools)
            self.assertLess(len(wire.encode()), 6000)

    def test_conclusive_report_requires_evidence(self):
        report = {'verdict': 'BENIGN', 'reason': 'Test activity.',
                  'recommendations': ['Record the incident.', 'Review scope.']}
        envelope = {'text': json.dumps(report), 'tools_used': []}
        with self.assertRaises(ValueError):
            validate_investigation(envelope)
        envelope['tools_used'] = ['get_ssh_auth_summary', 'get_approved_test_plan']
        self.assertEqual(validate_investigation(envelope), report)

    def test_agent_can_stop_without_tools_as_inconclusive(self):
        report = {'verdict': 'INSUFFICIENT_EVIDENCE', 'reason': 'Evidence missing.',
                  'recommendations': ['Request review.', 'Collect authentication evidence.']}
        self.assertEqual(validate_investigation({'text': json.dumps(report), 'tools_used': []}), report)

    def test_false_benign_scope_violation_is_rejected(self):
        _, investigation = build_job(ROOT / 'scope_violation.json')
        envelope = {'text': json.dumps({'verdict': 'BENIGN', 'reason': 'Within scope.',
                    'recommendations': ['Record.', 'Monitor.']}),
                    'tools_used': ['get_ssh_auth_summary', 'get_approved_test_plan']}
        with self.assertRaisesRegex(ValueError, 'contradicts approved scope'):
            validate_investigation(envelope, investigation)

    def test_scope_comparison_handles_accounts_and_boundaries(self):
        from ssh_investigation import compare_scope
        auth = {'failed_accounts': {'test': 8, 'backup': 2}, 'failed_password_count': 10,
                'successful_login_count': 0, 'coverage': 'complete_for_fixture'}
        plan = {'allowed_accounts': ['test'], 'maximum_failed_attempts': 10}
        comparison = compare_scope(auth, plan, {'approved': True})
        self.assertEqual(comparison['unexpected_accounts'], ['backup'])
        self.assertFalse(comparison['attempt_limit_exceeded'])
        auth['failed_password_count'] = 11
        self.assertTrue(compare_scope(auth, plan, {})['attempt_limit_exceeded'])
        self.assertFalse(compare_scope(auth, None, {})['plan_available'])

    def test_incomplete_evidence_cannot_support_conclusive_report(self):
        _, investigation = build_job(ROOT / 'approved_test.json')
        investigation['authentication']['coverage'] = 'partial'
        envelope = {'text': json.dumps({'verdict': 'SUSPICIOUS', 'reason': 'Attack.',
                    'recommendations': ['Review.', 'Monitor.']}),
                    'tools_used': ['get_ssh_auth_summary', 'get_approved_test_plan']}
        with self.assertRaisesRegex(ValueError, 'incomplete authentication coverage'):
            validate_investigation(envelope, investigation)

    def test_no_outcomes_cannot_be_declared_benign(self):
        _, investigation = build_job(ROOT/'approved_test.json')
        investigation['authentication'].update(failed_password_count=0,failed_accounts={})
        envelope={'text':json.dumps({'verdict':'BENIGN','reason':'No failures.',
                    'recommendations':['Record.','Monitor.']}),
                  'tools_used':['get_ssh_auth_summary','get_approved_test_plan']}
        with self.assertRaisesRegex(ValueError,'no authentication outcomes'):
            validate_investigation(envelope,investigation)
