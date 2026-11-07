from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from advisory_report import validate
from configure_gemini import prepare
from provider_service import ProviderService


CHOICE = dict(provider='gemini', model='gemini-test', expected_model_version='gemini-test-001')
KEY = 'test-key-placeholder-only'


class AssessmentProviderTests(unittest.TestCase):
    def test_only_length_and_citations_are_checked(self):
        evidence = dict(observed_facts={'E1': {}}, policy_findings={'P1': {}})
        self.assertEqual(validate('An unexpected interpretation [E1, p1].', evidence)['evidence_refs'], ['E1', 'P1'])
        self.assertEqual(validate('Plain prose without a verdict or citations.', evidence)['evidence_refs'], [])
        with self.assertRaisesRegex(ValueError, 'unknown evidence ID E9'):
            validate('See E9.', evidence)
        with self.assertRaisesRegex(ValueError, '4096'):
            validate('é' * 2049, evidence)

    def test_gemini_synthetic_uses_plain_text_and_never_activates(self):
        with TemporaryDirectory() as folder, patch.dict('os.environ', {'GEMINI_API_KEY': KEY}):
            root = Path(folder)
            service = ProviderService(root)
            self.assertEqual(service.state()['provider'], 'ollama')
            name = 'models/' + CHOICE['model']
            responses = [
                dict(name=name, supportedGenerationMethods=['generateContent'],
                     inputTokenLimit=65536, outputTokenLimit=8192),
                dict(totalTokens=200),
                dict(modelVersion=CHOICE['expected_model_version'],
                     candidates=[dict(finishReason='STOP', content=dict(parts=[dict(text='Synthetic advisory [E1].')]))],
                     usageMetadata=dict(promptTokenCount=200, candidatesTokenCount=6)),
            ]
            with patch('gemini_provider.request', side_effect=responses) as request:
                with self.assertRaisesRegex(ValueError, 'quota'):
                    service.check(CHOICE)
                request.assert_not_called()
                prepare(root, CHOICE['model'], CHOICE['expected_model_version'], 'free_tier', 1, 1, True)
                result = service.check(CHOICE)
                self.assertTrue(result['checks_passed'])
                self.assertIsNone(request.call_args_list[0].args[2])
                body = request.call_args.args[2]
                self.assertEqual(set(body), {'contents', 'generationConfig'})
                self.assertEqual(set(body['generationConfig']), {'temperature', 'candidateCount', 'maxOutputTokens'})
                with self.assertRaisesRegex(ValueError, 'budget exhausted'):
                    service.check(CHOICE)
                self.assertEqual(request.call_count, 3)
            self.assertEqual(service.state()['provider'], 'ollama')
            service.activate(dict(CHOICE, expected_selection='default'))
            self.assertEqual(service.state()['provider'], 'gemini')
            self.assertFalse(service.state()['access']['real_evidence_authorized'])
