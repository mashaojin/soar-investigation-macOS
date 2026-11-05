from contextlib import redirect_stdout
import io
import json
import subprocess
import unittest
from unittest.mock import patch
import ssh_demo_client


class DemoPacingTests(unittest.TestCase):
    def run_mock(self,mode,source):
        output=io.StringIO()
        route=json.dumps([{'prefsrc':source}])
        failed=subprocess.CompletedProcess([],255,stderr='Permission denied')
        with patch.object(ssh_demo_client.subprocess,'check_output',return_value=route), \
             patch.object(ssh_demo_client.subprocess,'run',return_value=failed) as invoke, \
             patch.object(ssh_demo_client.time,'sleep') as sleep,redirect_stdout(output):
            ssh_demo_client.run(mode)
        return invoke,sleep,output.getvalue()

    def test_unapproved_is_exactly_six_attempts_with_one_cooldown(self):
        invoke,sleep,output=self.run_mock('unapproved','192.168.64.4')
        self.assertEqual(invoke.call_count,6)
        self.assertEqual([call.args[0] for call in sleep.call_args_list],[.2,.2,.2,12,.2,.2,.2])
        self.assertIn('12 seconds',output)
        self.assertTrue(all('soc_rehearsal_invalid@192.168.64.6' in c.args[0] for c in invoke.call_args_list))

    def test_scope_violation_keeps_one_root_and_five_soc_test(self):
        invoke,_,_=self.run_mock('scope-violation','192.168.64.8')
        accounts=[c.args[0][-2] for c in invoke.call_args_list]
        self.assertEqual(accounts,['root@192.168.64.6']+['soc_test@192.168.64.6']*5)

    def test_wrong_source_fails_before_login(self):
        with patch.object(ssh_demo_client.subprocess,'check_output',return_value='[{"prefsrc":"192.168.64.8"}]'),patch.object(ssh_demo_client.subprocess,'run') as invoke:
            with self.assertRaises(ValueError): ssh_demo_client.run('unapproved')
            invoke.assert_not_called()
