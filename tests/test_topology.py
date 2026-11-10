import json
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from dashboard import snapshot
from live import collect_once
from live_lab_guard import ROLLBACK
from remote_reader import read_batch
from live_response import LabExecutor
from response import plan_for
from ssh_demo_client import run
from stage_demo_clients import stage
from topology import DEFAULT, FILENAME, collector_config, load, response_config, verify_management


ALTERNATE = {
    'victim': {'name': 'SOC Sensor', 'user': 'sensor', 'ip': '10.77.20.30'},
    'kali': {'name': 'SOC Kali', 'user': 'operator', 'ip': '10.77.20.31'},
    'trusted': {'name': 'SOC Approved', 'user': 'analyst', 'ip': '10.77.20.32'},
    'management_ip': '10.77.20.1',
}
ROOT = Path(__file__).resolve().parents[1]


class TopologyTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def use_alternate(self):
        (self.root / FILENAME).write_text(json.dumps(ALTERNATE))

    def test_defaults_match_existing_examples(self):
        self.assertEqual(load(self.root), DEFAULT)
        live = json.loads((ROOT / 'config/live.ssh.example.json').read_text())
        policy = json.loads((ROOT / 'config/response.example.json').read_text())
        self.assertEqual(collector_config(live, self.root), live)
        self.assertEqual(response_config(policy, self.root), policy)

    def test_alternate_collector_and_plan_editor_scope(self):
        self.use_alternate()
        live = json.loads((ROOT / 'config/live.ssh.example.json').read_text())
        (self.root / 'live.ssh.local.json').write_text(json.dumps(live))
        effective = collector_config(live, self.root)
        self.assertEqual(effective['ssh_target'], 'sensor@10.77.20.30')
        self.assertEqual(effective['source_ips'], ['10.77.20.31', '10.77.20.32'])
        self.assertEqual(effective['signature_ids'], live['signature_ids'])
        self.assertEqual(snapshot(self.root)['editor_options'], {
            'source_ips': effective['source_ips'], 'target_ip': '10.77.20.30',
            'preferred_source_ip': '10.77.20.32', 'maximum_window_minutes': 10,
        })

    def test_alternate_eve_filter_and_cursor(self):
        self.use_alternate()
        log = self.root / 'eve.json'
        event = dict(event_type='alert', timestamp='2026-11-09T00:00:00Z',
                     src_ip='10.77.20.31', dest_ip='10.77.20.30', dest_port=22,
                     alert=dict(signature_id=9001001))
        events = [event, dict(event, src_ip='192.168.64.4'), dict(event, dest_ip='192.168.64.6')]
        log.write_text(''.join(json.dumps(entry) + '\n' for entry in events))
        config = collector_config(dict(log_path=str(log), start_at='beginning'), self.root)
        db = self.root / 'alternate.sqlite3'

        def reader(config, cursor):
            return read_batch(dict(path=config['log_path'], cursor=cursor, start_at=config['start_at']))

        batch = collect_once(config, db, reader=reader)
        self.assertEqual((batch['inserted'], batch['filtered']), (1, 2))
        self.assertEqual(collect_once(config, db, reader=reader)['inserted'], 0)

    def test_staged_files_and_demo_route(self):
        self.use_alternate()
        for name in ('topology.py', 'ssh_demo_client.py'):
            (self.root / name).write_bytes((ROOT / name).read_bytes())
        remote = {}

        def transfer(command, **kwargs):
            operation, machine, path = command[2:]
            if operation == 'push':
                remote[machine, path] = kwargs['input']
            return CompletedProcess(command, 0, stdout=remote[machine, path])

        with patch('stage_demo_clients.subprocess.run', side_effect=transfer):
            self.assertEqual(len(stage(self.root)), 6)
        self.assertEqual(json.loads(remote['SOC Kali', '/home/operator/soc-demo/' + FILENAME]), ALTERNATE)
        route = '[{"prefsrc":"10.77.20.31"}]'
        with patch('ssh_demo_client.load', return_value=ALTERNATE), \
                patch('ssh_demo_client.subprocess.check_output', return_value=route) as ip, \
                patch('ssh_demo_client.Path.write_text') as receipt, patch('builtins.print'):
            run('unapproved', preflight=True)
            self.assertFalse(json.loads(receipt.call_args.args[0])['attack_executed'])
            self.assertEqual(ip.call_args.args[0], ['ip', '-j', 'route', 'get', '10.77.20.30'])
            with self.assertRaisesRegex(ValueError, 'requires source'):
                run('approved', preflight=True)

    def test_alternate_live_scope_and_management_proof(self):
        self.use_alternate()
        policy = json.loads((ROOT / 'config/response.example.json').read_text())
        policy = response_config(dict(policy, mode='live'), self.root)
        evidence = dict(source_ip='10.77.20.31', destination_ip='10.77.20.30',
                        destination_port=22, signature_id=9001001)
        plan = plan_for(evidence, policy)
        self.assertEqual(plan['topology'], ALTERNATE)
        self.assertEqual(plan['apply_argv'][-9:], [
            'deny', 'from', '10.77.20.31', 'to', '10.77.20.30', 'port', '22', 'proto', 'tcp',
        ])
        for address in ('10.77.20.1', '10.77.20.30', '192.168.64.4'):
            with self.assertRaises(ValueError):
                plan_for(dict(evidence, source_ip=address), policy)
        executor = LabExecutor(evidence['source_ip'], ALTERNATE)
        with patch('live_response.subprocess.run') as dispatch:
            executor.dispatch('a' * 24)
        command = dispatch.call_args.args[0]
        self.assertEqual(command[1:3], ['exec', 'SOC Sensor'])
        self.assertEqual(json.loads(command[-1]), ALTERNATE)
        verify_management('10.77.20.1 12345 10.77.20.30 22', ALTERNATE)
        with patch.object(executor, 'remote', return_value={
                'reachable': True, 'connection': '10.77.20.31 12345 10.77.20.30 22'}):
            with self.assertRaisesRegex(ValueError, 'management source'):
                executor.management()

    def test_rollback_removes_only_the_tagged_alternate_rule(self):
        folder = self.root / ('a' * 24)
        folder.mkdir()
        state = folder / 'state.json'
        state.write_text(json.dumps(dict(source='10.77.20.31', destination='10.77.20.30')))
        tag = 'soc-lab-' + folder.name
        status = '[ 1] 10.77.20.30 22/tcp        DENY IN     10.77.20.31               # ' + tag
        with patch('subprocess.run', side_effect=[
                CompletedProcess([], 0, stdout=status), CompletedProcess([], 0, stdout=''),
                CompletedProcess([], 0, stdout='Status: active')]) as ufw:
            with self.assertRaises(SystemExit) as exit_status:
                exec(ROLLBACK, {'__file__': str(folder / 'rollback.py')})
        self.assertEqual(exit_status.exception.code, 0)
        self.assertEqual(ufw.call_args_list[1].args[0], ['/usr/sbin/ufw', '--force', 'delete', '1'])
        self.assertEqual(json.loads(state.read_text())['stage'], 'rolled_back')

    def test_overlapping_management_address_is_invalid(self):
        (self.root / FILENAME).write_text(json.dumps(dict(ALTERNATE, management_ip='10.77.20.31')))
        with self.assertRaisesRegex(ValueError, 'distinct IPv4'):
            load(self.root)
