from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from advisory_report import validate
from analyst import analyze_next
from attack_knowledge import retrieve
from ollama_analyst import assessment_payload
from ssh_investigation import build_job
from ssh_scenarios import ROOT
from verify_gemma import compare_retrieval


def fixture(path):
    _, job = build_job(path)
    auth = job['authentication']
    evidence = dict(source_ip=auth['source_ip'], destination_ip=auth['target_ip'],
                    destination_port=22, signature_id=9001001, window_start=auth['start'])
    return evidence, job


class AttackKnowledgeTests(unittest.TestCase):
    def test_retrieval_requires_retained_ssh_failures(self):
        evidence, job = fixture(ROOT / 'approved_test.json')
        payload = assessment_payload(evidence, job)
        self.assertEqual(retrieve(payload)['K1']['technique_id'], 'T1110.001')
        self.assertEqual(retrieve(assessment_payload(evidence)), {})
        self.assertEqual(retrieve(assessment_payload(dict(evidence, destination_port=80), job)), {})
        payload['observed_facts']['E2']['data'] = {'failed_password_count': 1}
        self.assertEqual(retrieve(payload), {})

    def test_knowledge_citations_are_separate_and_checked(self):
        evidence, job = fixture(ROOT / 'approved_test.json')
        payload = assessment_payload(evidence, job)
        knowledge = retrieve(payload)
        report = validate('Observed failures [E2]. Password guessing background [K1, T1110.001].',
                          payload, knowledge=knowledge)
        self.assertEqual(report['evidence_refs'], ['E2'])
        self.assertEqual(report['knowledge_refs'][0]['url'], 'https://attack.mitre.org/techniques/T1110/001/')
        self.assertEqual(len(report['knowledge_refs']), 1)
        for unknown in ('K2', 'T1110.003', 'E9', 'P2'):
            with self.assertRaises(ValueError):
                validate(f'Unknown [{unknown}]', payload, knowledge=knowledge)
        with self.assertRaises(ValueError):
            validate('Unknown [T1110.001]', payload)

    def test_comparison_holds_evidence_and_model_settings_fixed(self):
        for path in sorted(ROOT.glob('*.json')):
            with self.subTest(path=path.name):
                evidence, job = fixture(path)
                payload = assessment_payload(evidence, job)
                calls = []

                def runner(prompt, settings):
                    calls.append((prompt, settings))
                    return {'text': 'Assessment: Insufficient evidence\nSee [E2].'
                            + (' See [K1].' if 'ATT&CK background' in prompt else '')}

                result = compare_retrieval(payload, job, runner)
                baseline, candidate = calls
                self.assertEqual(baseline[1], candidate[1])
                self.assertEqual(baseline[0].split('\nEvidence:\n')[1],
                                 candidate[0].split('\nEvidence:\n')[1])
                self.assertNotIn('T1110.001', baseline[0])
                self.assertIn('T1110.001', candidate[0])
                self.assertEqual(result['arms'][1]['report']['knowledge_refs'][0]['ref'], 'K1')

    def test_live_analysis_uses_one_primary_call_with_or_without_retrieval(self):
        for mode in ('enabled', 'disabled', 'no_match', 'unavailable', 'over_budget'):
            with self.subTest(mode=mode), TemporaryDirectory() as directory:
                db_path = Path(directory) / 'ssh-live.sqlite3'
                evidence, job = fixture(ROOT / 'approved_test.json')
                with closing(sqlite3.connect(db_path)) as db, db:
                    db.execute('CREATE TABLE incidents(incident_id TEXT, revision INTEGER, evidence TEXT, alert_count INTEGER, status TEXT)')
                    db.execute("INSERT INTO incidents VALUES('sample',1,?,1,'pending')", (json.dumps(evidence),))
                calls = []

                def runner(prompt, settings):
                    calls.append(prompt)
                    text = 'Assessment: Benign\nFits the approved test [P1].'
                    if mode == 'enabled':
                        text += ' Behavior resembles password guessing [T1110.001].'
                    return {'text': text, 'model': 'gemma4:e4b', 'request_count': 1}

                def lookup(payload):
                    if mode == 'unavailable':
                        raise FileNotFoundError
                    if mode == 'no_match':
                        return {}
                    knowledge = retrieve(payload)
                    if mode == 'over_budget':
                        knowledge['K1']['note'] = 'a' * 16000
                    return knowledge

                with patch('ssh_live_investigation.prepare_live_job', return_value=('', job)), \
                        patch('ssh_live_investigation.ready_after', return_value=datetime(2020, 1, 1, tzinfo=timezone.utc)), \
                        patch('attack_knowledge.retrieve', side_effect=lookup) as retrieval:
                    result = analyze_next(db_path, {'ssh_enrichment': True, 'approved_plans': 'unused',
                                                    'attack_retrieval': mode != 'disabled'}, runner=runner)
                self.assertEqual(result['status'], 'complete')
                self.assertEqual(len(calls), 1)
                self.assertEqual(retrieval.call_count, int(mode != 'disabled'))
                self.assertIn('"observed_facts"', calls[0])
                self.assertIn('"policy_findings"', calls[0])
                self.assertEqual('T1110.001' in calls[0], mode == 'enabled')
                with closing(sqlite3.connect(db_path)) as db:
                    saved, metadata = map(json.loads, db.execute('SELECT report,metadata FROM analyses').fetchone())
                self.assertEqual(saved['evidence_refs'], ['P1'])
                self.assertEqual(saved['reason'].splitlines()[0], 'Assessment: Benign')
                self.assertEqual(metadata['request_count'], 1)
                self.assertEqual(metadata['assessment_data'], assessment_payload(dict(evidence, alert_count=1), job))
                if mode == 'enabled':
                    self.assertEqual(saved['knowledge_refs'][0]['technique_id'], 'T1110.001')
                    self.assertEqual(metadata['attack_retrieval']['status'], 'included')
                    self.assertEqual(metadata['assessment_knowledge']['K1']['technique_id'], 'T1110.001')
                else:
                    self.assertNotIn('knowledge_refs', saved)
                    self.assertNotIn('assessment_knowledge', metadata)
                    if mode != 'disabled':
                        expected = 'no_match' if mode == 'no_match' else 'unavailable'
                        self.assertEqual(metadata['attack_retrieval']['status'], expected)
