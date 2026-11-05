import json
import tempfile
import unittest
from pathlib import Path
from ssh_scenarios import ROOT, evidence_bundle, load_scenario, plan_checks

class SSHScenarioTests(unittest.TestCase):
    def test_scenarios_and_label_separation(self):
        paths = sorted(ROOT.glob('*.json'))
        self.assertEqual(len(paths), 3)
        for path in paths:
            case, checks = load_scenario(path)
            bundle = evidence_bundle(path)
            self.assertNotIn('expected', bundle)
            self.assertNotIn(case['expected']['required_observation'], json.dumps(bundle))
        case, checks = load_scenario(ROOT / 'scope_violation.json')
        self.assertTrue(all(checks.values()))
        self.assertIn('root', case['authentication']['failed_accounts'])
        self.assertNotIn('root', case['plan']['allowed_accounts'])

    def test_window_and_approval(self):
        case, _ = load_scenario(ROOT / 'approved_test.json')
        incident, plan = case['incident'], case['plan']
        incident['end'] = plan['end']
        self.assertFalse(plan_checks(incident, plan)['within_window'])
        plan['approval_status'] = 'draft'
        self.assertFalse(plan_checks(incident, plan)['approved'])
        incident['start'] = '2026-10-26T18:10:00'
        with self.assertRaises(ValueError):
            plan_checks(incident, plan)

    def test_wrong_source_rejected(self):
        case, _ = load_scenario(ROOT / 'approved_test.json')
        case['authentication']['source_ip'] = '192.0.2.99'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'case.json'
            path.write_text(json.dumps(case))
            with self.assertRaises(ValueError):
                load_scenario(path)
