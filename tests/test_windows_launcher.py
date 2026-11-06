"""Local configuration parsing and installer rendering; never installs anything."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from windows_lab import read_env
from prepare_windows_response import prepare

ROOT=Path(__file__).parents[1]


class WindowsLauncherTests(unittest.TestCase):
    def test_duplicate_monitor_and_telegram_polling_are_refused(self):
        import fcntl
        import monitor
        from telegram_client import bot_lock,TelegramError
        with tempfile.TemporaryDirectory() as folder,patch('monitor.collect_once') as collector:
            db=Path(folder)/'state.sqlite3'
            with open(str(db)+'.monitor.lock','a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaisesRegex(RuntimeError,'monitor already'):
                    monitor.run({},str(db),{},duration=0.1,analysis_enabled=False)
            collector.assert_not_called()
        with bot_lock('b'*64):
            with self.assertRaises(TelegramError):
                with bot_lock('b'*64):self.fail('Second polling lock was acquired')

    def test_collection_only_never_calls_model_or_starts_live_worker(self):
        import monitor
        from contextlib import closing
        import sqlite3
        with tempfile.TemporaryDirectory() as folder,patch('monitor.collect_once',return_value={'has_more':False}),patch('monitor.analyze_next',side_effect=AssertionError('Model must remain deferred')) as analyst:
            db=Path(folder)/'state.sqlite3'
            self.assertEqual(monitor.run({'poll_seconds':1},str(db),{},duration=0.1,analysis_enabled=False),0)
            analyst.assert_not_called()
            with sqlite3.connect(db) as connection:
                row=connection.execute("SELECT status FROM service_state WHERE component='analyst'").fetchone()
                self.assertEqual(row[0],'deferred')
            with self.assertRaises(ValueError):monitor.run({},str(db),{},response_policy={'mode':'live'},analysis_enabled=False)

    def test_post_install_verification_never_dispatches_or_enables_live(self):
        from verify_windows_helpers import verify
        from windows_response import expected_receipt
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);lab=json.loads((ROOT/'config/lab.windows-hyperv.example.json').read_text())
            (root/'lab.local.json').write_text(json.dumps(lab));(root/'response.local.json').write_text(json.dumps({'mode':'dry_run'}))
            with patch('verify_windows_helpers.remote',return_value=expected_receipt(lab)) as remote:
                result=verify(root)
                self.assertEqual(remote.call_args.args[1][-1],'inspect')
                self.assertEqual(result['firewall_actions'],0)
            policy=json.loads((root/'response.local.json').read_text())
            self.assertEqual(policy['mode'],'dry_run');self.assertNotIn('live_rehearsal_authorized_at',policy)
            self.assertNotIn('model_evaluation_passed',policy)
    def test_credentials_are_literal_data_never_shell_code(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'.env'
            path.write_text("SOC_TELEGRAM_BOT_TOKEN='synthetic:$(touch /tmp/should-not-execute)'\nSOC_TELEGRAM_CHAT_ID='123'\n")
            values=read_env(path)
            self.assertIn('$(touch',values['SOC_TELEGRAM_BOT_TOKEN'])
            path.write_text("SOC_TELEGRAM_BOT_TOKEN=__import__('os').system('id')\nSOC_TELEGRAM_CHAT_ID='123'\n")
            with self.assertRaises(ValueError):read_env(path)
            for text in ["EXTRA='x'", "SOC_TELEGRAM_BOT_TOKEN='replace-with-your-bot-token'", "SOC_TELEGRAM_CHAT_ID='1'\nSOC_TELEGRAM_CHAT_ID='2'"]:
                path.write_text(text)
                with self.assertRaises(ValueError):read_env(path)

    def test_prepared_installer_is_inspect_only_without_apply_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);lab=json.loads((ROOT/'config/lab.windows-hyperv.example.json').read_text())
            (root/'lab.local.json').write_text(json.dumps(lab));output=root/'package'
            receipt=prepare(root,output,with_rule_editor=True)
            compile((output/'install.py').read_text(),'install.py','exec')
            result=subprocess.run([sys.executable,str(output/'install.py')],capture_output=True,text=True,check=True)
            self.assertEqual(json.loads(result.stdout)['status'],'prepared')
            self.assertFalse(receipt['provisioned'])
            self.assertIn('/usr/bin/python3 -I /usr/local/libexec/soc-rule-editor.py',(output/'rule-sudoers').read_text())
            (output/'windows_response_helper.py').write_text('tampered')
            result=subprocess.run([sys.executable,str(output/'install.py')],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            with self.assertRaises(ValueError):prepare(root,output)


if __name__=='__main__':unittest.main()
