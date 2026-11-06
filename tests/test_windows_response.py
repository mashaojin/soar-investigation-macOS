"""Offline failure-injection tests; no sockets, root commands or live firewall."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import windows_response_helper as guard
from windows_response import helper_config, expected_receipt, check_policy, WindowsExecutor
from response import plan_for
from live_response import verify_receipt, executor_for


def lab():
    value=json.loads((Path(__file__).parents[1]/'config/lab.windows-hyperv.example.json').read_text())
    value['_path']='/mnt/c/lab/lab.local.json'
    return value


class WindowsResponseTests(unittest.TestCase):
    def setUp(self):
        self.lab=lab();self.config=helper_config(self.lab);self.id='a'*24
        self.source=self.lab['attacker']['ip']

    def test_protected_scope_and_input_rejection(self):
        for source in [self.config['victim_ip'],*self.config['management_ips'],'8.8.8.8','172.18.1.2; id']:
            with self.subTest(source=source),self.assertRaises(ValueError):guard.rules(self.config,self.id,source)
        for name in ['../x','a'*25,None,'a;id']:
            with self.subTest(name=name),self.assertRaises(ValueError):guard.run_name(name)
        for change in [dict(port=80),dict(duration_seconds=600),dict(allowed_sources=[self.config['victim_ip'],self.source])]:
            with self.assertRaises(ValueError):guard.validate_config(dict(self.config,**change))

    def snapshot(self):
        return {'nftables':[{'metainfo':{}}]+[{k:dict(v,handle=7)} for item in guard.rules(self.config,self.id,self.source)['nftables'] for k,v in item['add'].items()]}

    def test_kernel_scope_verification_rejects_extra_or_changed_rules(self):
        snapshot=self.snapshot();guard.verify_table(snapshot,self.config,self.id,self.source)
        changed=deepcopy(snapshot);changed['nftables'][-1]['rule']['expr'][-1]={'accept':None}
        with self.assertRaises(ValueError):guard.verify_table(changed,self.config,self.id,self.source)
        changed=deepcopy(snapshot);changed['nftables'].append(changed['nftables'][-1])
        with self.assertRaises(ValueError):guard.verify_table(changed,self.config,self.id,self.source)

    def test_apply_arms_timer_before_deny_and_never_redispatches(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(guard,'STATE',Path(folder)),patch.object(guard,'table_snapshot',side_effect=[None,self.snapshot()]),patch.object(guard,'run') as run:
            def execute(argv,text=None):
                if argv[:3]==['/usr/sbin/ip','-j','address']:return json.dumps([{'addr_info':[{'local':self.config['victim_ip']}]}])
                if 'is-active' in argv:return 'active\n'
                return ''
            run.side_effect=execute
            state=guard.apply(self.config,self.id,self.source)
            self.assertEqual(state['stage'],'applied')
            commands=[call.args[0] for call in run.call_args_list]
            arm=next(i for i,c in enumerate(commands) if c[0]=='/usr/bin/systemd-run')
            deny=next(i for i,c in enumerate(commands) if c==[guard.NFT,'-j','-f','-'])
            self.assertLess(arm,deny)
            self.assertIn(guard.HELPER,commands[arm])
            with self.assertRaises(ValueError):guard.apply(self.config,self.id,self.source)

    def test_timer_failure_prevents_apply_and_attempts_cleanup(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(guard,'STATE',Path(folder)),patch.object(guard,'table_snapshot',return_value=None),patch.object(guard,'rollback') as rollback,patch.object(guard,'run') as run:
            def execute(argv,text=None):
                if argv[0]=='/usr/sbin/ip':return json.dumps([{'addr_info':[{'local':self.config['victim_ip']}]}])
                if 'is-active' in argv:return 'inactive\n'
                return ''
            run.side_effect=execute
            with self.assertRaises(RuntimeError):guard.apply(self.config,self.id,self.source)
            self.assertFalse(any(c.args[0]==[guard.NFT,'-j','-f','-'] for c in run.call_args_list))
            rollback.assert_called_once_with(self.id)

    def test_rollback_uses_saved_config_and_removes_only_owned_table(self):
        state=dict(run_id=self.id,config=self.config,source=self.source)
        with tempfile.TemporaryDirectory() as folder,patch.object(guard,'read_state',return_value=(Path(folder),state)),patch.object(guard,'table_snapshot',side_effect=[self.snapshot(),None]),patch.object(guard,'run') as run:
            result=guard.rollback(self.id)
            payload=json.loads(run.call_args.args[1])
            self.assertEqual(payload,{'nftables':[{'delete':{'table':{'family':'inet','name':'socw_'+self.id}}}]})
            self.assertEqual(result['stage'],'rolled_back')

    def policy(self):
        return dict(mode='live',lab_profile=self.lab,victim_ip=self.config['victim_ip'],protected_ips=self.config['management_ips']+[self.config['victim_ip']],allowed_attacker_ips=self.config['allowed_sources'],duration_seconds=60,destination_port=22,live_enabled_after='2026-11-05T00:00:00Z',live_rehearsal_authorized_at='2026-11-05T00:00:00Z',model_evaluation_passed=True,windows_response=dict(provisioned=True,**expected_receipt(self.lab)))

    def test_policy_keeps_provisioning_model_and_fresh_authorization_gates(self):
        policy=self.policy();check_policy(policy)
        evidence=dict(source_ip=self.source,destination_ip=self.config['victim_ip'],destination_port=22,signature_id=9001001)
        self.assertEqual(plan_for(evidence,policy)['source_ip'],self.source)
        for change in [dict(windows_response={}),dict(model_evaluation_passed=False),dict(live_rehearsal_authorized_at='old')]:
            with self.subTest(change=change),self.assertRaises(ValueError):plan_for(evidence,dict(policy,**change))

    def test_windows_dispatch_is_fixed_ssh_helper_and_checks_identity(self):
        executor=executor_for(self.source,self.policy())
        self.assertIsInstance(executor,WindowsExecutor)
        with patch.object(executor,'remote',side_effect=[dict(expected_receipt(self.lab)),{'stage':'applied'}]) as remote:
            executor.dispatch(self.id)
            self.assertEqual(remote.call_args.args,('victim',['sudo','-n',guard.HELPER,'apply',self.id,self.source]))
        with patch.object(executor,'remote',return_value={} ) as remote:
            with self.assertRaises(ValueError):executor.dispatch(self.id)
            self.assertEqual(remote.call_count,1)

    def test_receipts_and_management_are_bound_to_actual_lab(self):
        state=dict(run_id=self.id,source=self.source,destination=self.config['victim_ip'],port=22,duration_seconds=60,stage='rolled_back',firewall_after='Owned table absent')
        verify_receipt(state,self.id,self.source,self.config['victim_ip'])
        with self.assertRaises(ValueError):verify_receipt(state,self.id,self.source)
        executor=WindowsExecutor(self.source,self.policy())
        with patch.object(executor,'remote',return_value={'connection':'192.168.64.1 123 172.18.250.163 22'}):
            with self.assertRaises(ValueError):executor.management()

    def test_windows_worker_completes_and_reconciles_uncertain_dispatch_without_resend(self):
        import test_continuous_response as legacy
        from assessment_facts import observed_claims
        from live_response import run_one,reconcile
        for uncertain in (False,True):
            with self.subTest(uncertain=uncertain):
                fixture=legacy.ContinuousResponseTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
                fixture.policy.update(self.policy())
                # Keep freshly computed fixture activation/window timestamps.
                fixture.policy['live_enabled_after']=fixture.evidence['window_start']
                fixture.policy['live_rehearsal_authorized_at']=fixture.policy['live_enabled_after']
                fixture.evidence.update(source_ip=self.source,destination_ip=self.config['victim_ip'])
                fixture.metadata['model']=self.lab['ollama']['model']
                fixture.metadata['investigation']['authentication'].update(source_ip=self.source,target_ip=self.config['victim_ip'])
                fixture.report['claims']=observed_claims(fixture.metadata['investigation'])
                with sqlite3.connect(fixture.db) as db:
                    db.execute('UPDATE incidents SET evidence=?',(json.dumps(fixture.evidence),))
                    db.execute('UPDATE analyses SET report=?,metadata=?',(json.dumps(fixture.report),json.dumps(fixture.metadata)))
                fixture.approve()
                source=self.source;destination=self.config['victim_ip']
                class Executor(legacy.Executor):
                    def probe(self):return dict(super().probe(),actual_source=source)
                    def read(self,run_id):return dict(super().read(run_id),source=source,destination=destination)
                    def dispatch(self,run_id):
                        super().dispatch(run_id)
                        if uncertain:raise TimeoutError('Synthetic interrupted transport')
                executor=Executor();self.assertTrue(run_one(fixture.db,fixture.policy,legacy.IDENTITY,executor,wait=lambda _:None))
                if uncertain:
                    self.assertEqual(fixture.status(),'live_recovery_required')
                    self.assertFalse(run_one(fixture.db,fixture.policy,legacy.IDENTITY,executor))
                    executor.reads=1;reconcile(fixture.db,executor,policy=fixture.policy)
                    self.assertEqual(fixture.status(),'live_failed')
                else:self.assertEqual(fixture.status(),'live_complete')
                self.assertEqual(executor.dispatches,1)

    def test_recovery_reads_remain_available_after_live_authorization_is_removed(self):
        policy=self.policy();policy['model_evaluation_passed']=False
        with self.assertRaises(ValueError):executor_for(self.source,policy)
        self.assertIsInstance(executor_for(self.source,policy,recovery=True),WindowsExecutor)


if __name__=='__main__':unittest.main()
