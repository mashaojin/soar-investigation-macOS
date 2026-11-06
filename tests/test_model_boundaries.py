import unittest
from evaluate_model_boundaries import boundary_cases,local_safety_checks
from assessment_facts import observed_claims
from ollama_analyst import assessment_payload,make_prompt


class BoundaryTests(unittest.TestCase):
    def test_boundary_facts_are_consistent_and_labels_do_not_reach_model(self):
        cases=boundary_cases()
        self.assertEqual(len(cases),3)
        for case in cases:
            prompt=make_prompt(assessment_payload(case['evidence'],case['investigation']))
            self.assertNotIn(case['name'],prompt)
        self.assertFalse(observed_claims(cases[0]['investigation'])['matching_plan'])
        root=observed_claims(cases[1]['investigation'])
        self.assertEqual(root['failed_password_count'],2);self.assertEqual(root['unexpected_accounts'],['root'])
        self.assertEqual(cases[2]['evidence']['alert_count'],4)
        self.assertEqual(observed_claims(cases[2]['investigation'])['failed_password_count'],16)

    def test_missing_evidence_skips_inference_and_malformed_output_is_rejected(self):
        results=local_safety_checks()
        self.assertTrue(all(v['passed'] for v in results.values()))
        self.assertEqual(results['missing_evidence']['model_calls'],0)
