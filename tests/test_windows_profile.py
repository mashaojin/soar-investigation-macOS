"""Deterministic Windows profile tests: no live keys, guests, model or Telegram."""
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime,timezone
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from configure_local import configure
from lab_config import MAC,load_profile,validate_profile,sources,protected
from ssh_transport import command
from response import plan_for

ROOT=Path(__file__).parents[1]


def windows():return json.loads((ROOT/'config/lab.windows-hyperv.example.json').read_text())


class ProfileTests(unittest.TestCase):
    def test_relative_dashboard_root_resolves_profile_once(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            path=Path(folder);(path/'lab.local.json').write_text(json.dumps(windows()))
            relative=path.relative_to(Path.cwd())
            loaded=load_profile(root=relative)
            self.assertEqual(loaded['platform'],'windows-hyperv')
            self.assertEqual(loaded['_path'],str((path/'lab.local.json').resolve()))

    def test_legacy_defaults_are_unchanged_and_not_mutated_by_windows(self):
        before=load_profile();other=windows();other['victim']['ip']='172.18.241.70'
        validate_profile(other)
        self.assertEqual(load_profile(),before)
        self.assertEqual(before['victim']['ip'],'192.168.64.6')
        self.assertEqual(before['ollama']['model'],'gemma4:e4b')

    def test_windows_explicit_model_budget_and_protection(self):
        lab=validate_profile(windows())
        self.assertEqual(lab['ollama']['model'],'gemma3:1b')
        self.assertEqual((lab['ollama']['num_ctx'],lab['ollama']['num_predict']),(8192,1024))
        self.assertEqual(protected(lab),['172.18.240.1','172.18.250.163'])
        self.assertNotIn('192.168.64.1',protected(lab))

    def test_ambiguous_or_unsafe_profiles_fail_closed(self):
        changes=[lambda v:v['victim'].update(user='victim; command'),
                 lambda v:v['attacker'].update(ip=v['victim']['ip']),
                 lambda v:v.update(management_ips=[]),lambda v:v.update(ssh_port=2222),
                 lambda v:v.update(block_duration_seconds=600),
                 lambda v:v['ssh'].update(transport='native'),
                 lambda v:v['ollama'].update(endpoint='http://user:secret@localhost:11434'),
                 lambda v:v['ollama'].update(num_predict=2048)]
        for change in changes:
            value=windows();change(value)
            with self.subTest(value=value),self.assertRaises((ValueError,KeyError)):validate_profile(value)

    def test_ssh_is_strict_and_scoped_to_explicit_role(self):
        lab=windows();lab['_path']='/mnt/c/offline lab/lab.local.json'
        with patch('ssh_transport.windows_path',side_effect=lambda p:'C:\\offline lab\\'+Path(p).name):
            argv=command(lab,'victim','python3 -')
        self.assertIn('StrictHostKeyChecking=yes',argv);self.assertIn('BatchMode=yes',argv)
        self.assertIn('IdentitiesOnly=yes',argv);self.assertEqual(argv[-2:],["victim@172.18.250.163",'python3 -'])
        self.assertTrue(any('ProxyCommand=' in item and '-ProfilePath' in item for item in argv))
        self.assertFalse(any('/Applications/' in item for item in argv))
        with self.assertRaises(ValueError):command(lab,'management','true')

    def test_native_mac_transport_remains_available(self):
        argv=command(MAC,'victim','true')
        self.assertEqual(argv[-2:],["victim@192.168.64.6",'true'])
        self.assertFalse(any('ProxyCommand=' in item for item in argv))


class InitializationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for folder in ('config','prompts'):shutil.copytree(ROOT/folder,self.root/folder)

    def test_fresh_windows_state_is_dry_run_and_empty(self):
        configure(self.root,profile='windows-hyperv',lab=windows())
        response=json.loads((self.root/'response.local.json').read_text())
        runtime=json.loads((self.root/'runtime.ssh.live.local.json').read_text())
        live=json.loads((self.root/'live.ssh.local.json').read_text())
        self.assertEqual(response['mode'],'dry_run');self.assertIsNone(response['live_enabled_after'])
        self.assertFalse(response['exclusive_polling_confirmed']);self.assertIsNone(response['credentials_source'])
        self.assertEqual(runtime['ollama']['model'],'gemma3:1b')
        self.assertEqual(live['ssh_target'],'victim@172.18.250.163')
        self.assertEqual(json.loads((self.root/'plans/dashboard-plans.json').read_text()),[])
        self.assertFalse((self.root/'ssh-live.sqlite3').exists())
        self.assertEqual(configure(self.root)['created'],[])

    def test_mac_operational_state_cannot_be_adopted_as_windows(self):
        (self.root/'ssh-live.sqlite3').write_bytes(b'preserved local state')
        with self.assertRaisesRegex(ValueError,'Fresh Windows state'):configure(self.root,profile='windows-hyperv',lab=windows())
        self.assertEqual((self.root/'ssh-live.sqlite3').read_bytes(),b'preserved local state')
        self.assertFalse((self.root/'lab.local.json').exists())

    def test_existing_operator_profile_is_never_overwritten(self):
        configure(self.root,profile='windows-hyperv',lab=windows())
        old=(self.root/'lab.local.json').read_bytes();changed=windows();changed['victim']['ip']='172.18.241.70'
        with self.assertRaisesRegex(ValueError,'differs'):configure(self.root,lab=changed)
        self.assertEqual((self.root/'lab.local.json').read_bytes(),old)


class WindowsBoundaries(unittest.TestCase):
    def test_monitor_refuses_profile_collection_mismatch_before_starting(self):
        from monitor import run
        with tempfile.TemporaryDirectory() as folder:
            db=Path(folder)/'never-created.sqlite3'
            with self.assertRaisesRegex(ValueError,'Collection scope'):
                run({'destination_ip':'192.168.64.6','source_ips':[]},db,{'lab_profile':windows()})
            self.assertFalse(db.exists())

    def test_protected_addresses_and_unprovisioned_live_response_rejected(self):
        lab=windows()
        policy=dict(mode='dry_run',lab_profile=lab,victim_ip=lab['victim']['ip'],allowed_attacker_ips=sources(lab),
                    protected_ips=protected(lab),destination_port=22,duration_seconds=60)
        evidence=dict(source_ip=lab['attacker']['ip'],destination_ip=lab['victim']['ip'],destination_port=22,signature_id=9001001)
        self.assertEqual(plan_for(evidence,policy)['mode'],'dry_run')
        for address in protected(lab):
            with self.assertRaises(ValueError):plan_for(dict(evidence,source_ip=address),policy)
        with self.assertRaisesRegex(ValueError,'not provisioned'):plan_for(evidence,dict(policy,mode='live'))

    def test_plan_hints_follow_profile(self):
        from dashboard_view import plan_view
        lab=windows();plan=dict(approval_status='approved',source_ips=[lab['trust_client']['ip']],target_ip=lab['victim']['ip'],
            target_port=22,allowed_accounts=['soc_test'],maximum_failed_attempts=10,start='2030-01-01T00:00:00Z',end='2030-01-01T00:03:00Z')
        view=plan_view(plan,datetime(2029,1,1,tzinfo=timezone.utc),lab)
        self.assertIn('--lab-config',view['run_instructions']['command'])
        self.assertEqual(view['run_instructions']['vm'],'Trust-Client')

    def test_configurable_timezone_has_vancouver_default(self):
        import incident_labels
        self.addCleanup(incident_labels.configure_timezone)
        incident_labels.configure_timezone('UTC')
        value={'incident_occurred_at':'2026-11-05T02:00:00Z'}
        self.assertIn('02:00:00 UTC',incident_labels.time_display(value))
        incident_labels.configure_timezone()
        self.assertIn('America/Vancouver',incident_labels.time_display(value))

    def test_windows_demo_is_bounded_and_keeps_strict_host_checking(self):
        import ssh_demo_client as demo
        lab=windows()
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'known_hosts').write_text('synthetic mocked host key')
            with patch.object(demo,'__file__',str(Path(folder)/'ssh_demo_client.py')),\
                 patch.object(demo.subprocess,'check_output',return_value=json.dumps([{'prefsrc':lab['trust_client']['ip']}])) ,\
                 patch.object(demo.subprocess,'run') as run,patch.object(demo.time,'sleep'),redirect_stdout(io.StringIO()):
                run.return_value.returncode=255;run.return_value.stderr='synthetic failure'
                demo.run('scope-violation',lab=lab)
                self.assertEqual(run.call_count,6)
                calls=[call.args[0] for call in run.call_args_list]
                self.assertTrue(all('StrictHostKeyChecking=yes' in call for call in calls))
                self.assertIn('root@'+lab['victim']['ip'],calls[0])
                self.assertTrue(all('soc_test@'+lab['victim']['ip'] in call for call in calls[1:]))


if __name__=='__main__':unittest.main()
