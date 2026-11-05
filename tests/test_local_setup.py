from contextlib import closing
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from configure_local import configure

class LocalSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        source=Path(__file__).parents[1]
        for directory in ('config','prompts'):shutil.copytree(source/directory,self.root/directory)

    def test_new_checkout_gets_dry_run_empty_plans_and_exported_prompt(self):
        result=configure(self.root)
        policy=json.loads((self.root/'response.local.json').read_text())
        self.assertEqual(policy['mode'],'dry_run');self.assertFalse(policy['exclusive_polling_confirmed'])
        self.assertIsNone(policy['live_enabled_after'])
        self.assertIsNotNone(policy['review_notifications_enabled_after'])
        self.assertEqual(json.loads((self.root/'plans/dashboard-plans.json').read_text()),[])
        with closing(sqlite3.connect(self.root/'lab-experiments.sqlite3')) as db:
            active=db.execute('SELECT text FROM prompts p JOIN prompt_active a ON p.id=a.id').fetchone()[0]
        self.assertEqual(active,(self.root/'prompts/current.txt').read_text())
        self.assertIn('lab-experiments.sqlite3',result['created'])
        self.assertFalse((self.root/'ssh-live.sqlite3').exists())

    def test_existing_config_plans_and_prompt_store_are_not_overwritten(self):
        configure(self.root)
        policy=self.root/'response.local.json';policy.write_text('{"mode":"existing operator choice"}')
        plans=self.root/'plans/dashboard-plans.json';plans.write_text('[{"id":"existing-plan"}]')
        store=(self.root/'lab-experiments.sqlite3').read_bytes()
        self.assertEqual(configure(self.root)['created'],[])
        self.assertEqual(policy.read_text(),'{"mode":"existing operator choice"}')
        self.assertEqual(plans.read_text(),'[{"id":"existing-plan"}]')
        self.assertEqual((self.root/'lab-experiments.sqlite3').read_bytes(),store)
