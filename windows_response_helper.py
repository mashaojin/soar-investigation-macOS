#!/usr/bin/python3 -I
"""Root-owned Linux helper. Fixed JSON operations only; no model commands.

Prepared locally; installation and any live use require separate operator action.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

CONFIG = Path('/etc/soc-pipeline/windows-response.json')
STATE = Path('/var/lib/soc-pipeline/windows-response')
HELPER = '/usr/local/libexec/soc-windows-response.py'
NFT = '/usr/sbin/nft'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_config(config):
    if set(config) != {'version', 'victim_ip', 'allowed_sources', 'management_ips', 'port', 'duration_seconds'}:
        raise ValueError('Unexpected helper configuration')
    if config['version'] != 1 or config['port'] != 22 or config['duration_seconds'] != 60:
        raise ValueError('Only TCP/22 and 60 seconds supported')
    groups = [config['allowed_sources'], config['management_ips']]
    if any(not isinstance(g, list) or not g for g in groups) or len(config['allowed_sources']) != 2:
        raise ValueError('Two clients and protected management addresses required')
    addresses = [config['victim_ip'], *config['allowed_sources'], *config['management_ips']]
    for value in addresses:
        ip = ipaddress.IPv4Address(value)
        if not ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            raise ValueError('Private unicast lab addresses required')
    if len(addresses) != len(set(addresses)):
        raise ValueError('Protected and source addresses must be distinct')
    return config


def trusted(path, directory=False):
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError('Unsafe root-owned path: ' + str(path))
    return path


def config_load():
    trusted(CONFIG.parent, True)
    return validate_config(json.loads(trusted(CONFIG).read_text()))


def run(argv, text=None):
    result = subprocess.run(argv, input=text, capture_output=True, text=True, timeout=12, check=True)
    if len(result.stdout) > 131072:
        raise ValueError('Oversized system receipt')
    return result.stdout


def run_name(run_id):
    if not isinstance(run_id, str) or not re.fullmatch('[0-9a-f]{24}', run_id):
        raise ValueError('Invalid run ID')
    return 'socw_' + run_id


def save(folder, state):
    temp = folder / 'state.tmp'
    with temp.open('w') as file:
        json.dump(state, file)
        file.flush()
        os.fsync(file.fileno())
    temp.chmod(0o600)
    temp.replace(folder / 'state.json')


def rules(config, run_id, source):
    name = run_name(run_id)
    if source not in config['allowed_sources'] or source in config['management_ips'] or source == config['victim_ip']:
        raise ValueError('Protected or unsupported source')
    return {'nftables': [
        {'add': {'table': {'family': 'inet', 'name': name, 'comment': 'soc-lab-' + run_id}}},
        {'add': {'chain': {'family': 'inet', 'table': name, 'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': -10, 'policy': 'accept'}}},
        {'add': {'rule': {'family': 'inet', 'table': name, 'chain': 'input', 'comment': 'soc-lab-' + run_id,
            'expr': [
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': source}},
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}}, 'right': config['victim_ip']}},
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': 22}},
                {'drop': None}]}}}]}


def table_snapshot(run_id):
    name = run_name(run_id)
    tables = json.loads(run([NFT, '-j', 'list', 'tables']))
    if not any(item.get('table', {}).get('family') == 'inet' and item['table'].get('name') == name for item in tables['nftables']):
        return None
    return json.loads(run([NFT, '-j', 'list', 'table', 'inet', name]))


def verify_table(snapshot, config, run_id, source):
    expected = [next(iter(item['add'].items())) for item in rules(config, run_id, source)['nftables']]
    actual = [next(iter(item.items())) for item in snapshot['nftables'] if 'metainfo' not in item]
    if len(actual) != len(expected):
        raise ValueError('Unexpected objects in owned table')
    # nft supplies handles and chain use counts; scope and expressions must match.
    for kind, wanted in expected:
        matches = [v for k, v in actual if k == kind]
        if len(matches) != 1 or any(matches[0].get(k) != v for k, v in wanted.items()):
            raise ValueError('Owned table scope or tag changed')


@contextmanager
def locked():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    trusted(STATE.parent, True)
    trusted(STATE, True)
    lock_path = STATE / 'guard.lock'
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as file:
        trusted(lock_path)
        fcntl.flock(file, fcntl.LOCK_EX)
        yield


def read_state(run_id):
    run_name(run_id)
    folder = trusted(STATE / run_id, True)
    state = json.loads(trusted(folder / 'state.json').read_text())
    if state['run_id'] != run_id:
        raise ValueError('Receipt ID mismatch')
    return folder, state


def rollback(run_id):
    folder, state = read_state(run_id)
    # Use root-owned saved scope so a later config edit cannot prevent rollback.
    config = validate_config(state['config'])
    snapshot = table_snapshot(run_id)
    if snapshot is not None:
        verify_table(snapshot, config, run_id, state['source'])
        run([NFT, '-j', '-f', '-'], json.dumps({'nftables': [{'delete': {'table': {'family': 'inet', 'name': run_name(run_id)}}}]}))
    if table_snapshot(run_id) is not None:
        raise RuntimeError('Owned table removal not verified')
    state.update(stage='rolled_back', rolled_back_at=time.time(), firewall_after='Owned temporary table absent; other tables preserved')
    save(folder, state)
    return state


def apply(config, run_id, source):
    transaction = rules(config, run_id, source)
    interfaces = json.loads(run(['/usr/sbin/ip', '-j', 'address', 'show']))
    if not any(a.get('local') == config['victim_ip'] for i in interfaces for a in i.get('addr_info', [])):
        raise ValueError('Configured Victim address is not local')
    for path in STATE.glob('*/state.json'):
        old = json.loads(trusted(path).read_text())
        if old['stage'] not in ('rolled_back', 'preflight_failed'):
            raise ValueError('Earlier operation requires reconciliation')
    if table_snapshot(run_id) is not None:
        raise ValueError('Table already exists; no redispatch')
    folder = STATE / run_id
    folder.mkdir(mode=0o700)  # Exclusive operation ID, including failed attempts.
    state = dict(run_id=run_id, source=source, destination=config['victim_ip'], port=22, duration_seconds=60,
                 config=config, config_hash=digest(config), stage='preflight')
    save(folder, state)
    armed = False
    try:
        run([NFT, '-c', '-j', '-f', '-'], json.dumps(transaction))
        unit = 'socw-' + run_id + '-rollback'
        started = time.monotonic()
        epoch = time.time()
        run(['/usr/bin/systemd-run', '--quiet', '--unit=' + unit, '--on-active=60s', '--timer-property=AccuracySec=1s',
             '--property=Restart=on-failure', '--property=RestartSec=2s', '--property=StartLimitIntervalSec=0', HELPER, 'rollback', run_id])
        armed = True
        if run(['/usr/bin/systemctl', 'is-active', unit + '.timer']).strip() != 'active' or time.monotonic() - started >= 10:
            raise RuntimeError('Rollback timer not verified promptly; no deny')
        state.update(stage='armed', rollback_due_at=epoch + 60, timer_unit=unit + '.timer')
        save(folder, state)
        run([NFT, '-j', '-f', '-'], json.dumps(transaction))
        snapshot = table_snapshot(run_id)
        if snapshot is None:
            raise RuntimeError('Temporary deny absent after apply')
        verify_table(snapshot, config, run_id, source)
        state.update(stage='applied', applied_at=time.time(), firewall_applied=json.dumps(snapshot))
        save(folder, state)
        return state
    except Exception as error:
        state.update(stage='apply_failed' if armed else 'preflight_failed', error=str(error)[:1000])
        save(folder, state)
        if armed:
            try:
                rollback(run_id)
            except Exception as recovery:
                state.update(stage='rollback_failed', recovery_error=str(recovery)[:1000])
                save(folder, state)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['inspect', 'apply', 'read', 'rollback'])
    parser.add_argument('run_id', nargs='?')
    parser.add_argument('source', nargs='?')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Root required via reviewed fixed-helper sudoers entry')
    if (args.operation == 'inspect' and (args.run_id or args.source)) or (args.operation != 'apply' and args.source):
        raise ValueError('Unexpected arguments')
    with locked():
        if args.operation == 'inspect':
            config = config_load()
            result = dict(config=config, config_hash=digest(config), helper_hash=hashlib.sha256(trusted(Path(HELPER)).read_bytes()).hexdigest(),
                          nft_tables=json.loads(run([NFT, '-j', 'list', 'tables'])), operations=['inspect', 'apply', 'read', 'rollback'])
        elif args.operation == 'apply':
            result = apply(config_load(), args.run_id, args.source)
        elif args.operation == 'rollback':
            result = rollback(args.run_id)
        else:
            _, result = read_state(args.run_id)
            # Recheck actual kernel state; never trust a saved applied receipt alone.
            snapshot = table_snapshot(args.run_id)
            if result['stage'] == 'applied':
                if snapshot is None:
                    raise ValueError('Recorded deny is no longer present')
                verify_table(snapshot, result['config'], args.run_id, result['source'])
            elif result['stage'] == 'rolled_back' and snapshot is not None:
                raise ValueError('Recorded rollback disagrees with kernel state')
        print(json.dumps(result))


if __name__ == '__main__':
    main()
