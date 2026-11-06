"""WSL SSH response adapter. Provisioning and live authorization fail closed."""
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

from lab_config import load_profile, sources, protected
from ssh_transport import command
from windows_response_helper import digest, validate_config, HELPER


def helper_config(lab):
    return validate_config(dict(version=1, victim_ip=lab['victim']['ip'], allowed_sources=sources(lab),
                                management_ips=lab['management_ips'], port=22, duration_seconds=60))


def expected_receipt(lab):
    return dict(config_hash=digest(helper_config(lab)),
                helper_hash=hashlib.sha256(Path(__file__).with_name('windows_response_helper.py').read_bytes()).hexdigest())


def check_policy(policy, lab=None):
    if policy.get('experimental_assessment'):raise ValueError('Experimental assessment disables all live responses')
    lab = lab or load_profile(policy)
    receipt = policy.get('windows_response', {})
    if lab['platform'] != 'windows-hyperv' or receipt.get('provisioned') is not True or any(receipt.get(k) != v for k,v in expected_receipt(lab).items()):
        raise ValueError('Windows live transport is not provisioned; keep responses in dry_run')
    from human_approved_live import authorization
    accepted=authorization(policy,policy) if policy.get('human_approved_live') else {}
    if ((policy.get('model_evaluation_passed') is not True and not accepted) or not policy.get('live_enabled_after')
            or policy.get('live_rehearsal_authorized_at') != policy['live_enabled_after']):
        raise ValueError('Windows live response requires model readiness and separate fresh live-rehearsal authorization')
    if (set(policy['protected_ips']) != set(protected(lab)) or policy['victim_ip'] != lab['victim']['ip']
            or not set(policy['allowed_attacker_ips']) <= set(sources(lab))):
        raise ValueError('Windows policy does not match provisioned helper scope')


class WindowsExecutor:
    def __init__(self, source, policy, recovery=False):
        self.lab = load_profile(policy)
        if not recovery:
            check_policy(policy, self.lab)
        if source not in sources(self.lab) or source in protected(self.lab):
            raise ValueError('Unsupported or protected source')
        self.source = source
        self.role = next(role for role in ('attacker','trust_client') if self.lab[role]['ip'] == source)

    def remote(self, role, argv):
        result = subprocess.run(command(self.lab, role, shlex.join(argv)), capture_output=True, text=True, timeout=55, check=True)
        if len(result.stdout) > 65536:
            raise ValueError('Oversized SSH helper receipt')
        return json.loads(result.stdout)

    def helper(self, operation, run_id=None):
        if operation not in ('inspect','read','apply'):
            raise ValueError('Unsupported worker operation')
        argv = ['sudo','-n',HELPER,operation]
        if operation != 'inspect':
            if not re.fullmatch('[0-9a-f]{24}',run_id or ''):
                raise ValueError('Invalid guard ID')
            argv.append(run_id)
        if operation == 'apply':
            argv.append(self.source)
        return self.remote('victim',argv)

    def dispatch(self, run_id):
        receipt = self.helper('inspect')
        if any(receipt.get(k) != v for k,v in expected_receipt(self.lab).items()):
            raise ValueError('Installed helper/config identity changed; no dispatch')
        return self.helper('apply',run_id)

    def read(self, run_id):
        state = self.helper('read',run_id)
        if state.get('config_hash') != expected_receipt(self.lab)['config_hash']:
            raise ValueError('Guard configuration binding changed')
        return state

    def management(self):
        result = self.remote('victim',['python3','-c',"import json,os; print(json.dumps({'connection':os.environ.get('SSH_CONNECTION','')}))"])
        connection = result.get('connection','').split()
        if len(connection) != 4 or connection[0] not in self.lab['management_ips'] or connection[2] != self.lab['victim']['ip']:
            raise ValueError('Victim-observed management address changed')
        return dict(result,reachable=True)

    def probe(self):
        # One TCP connection from the actual client, with no SSH authentication.
        code = '''import json,socket
s=socket.socket();s.settimeout(3)
s.bind((SOURCE,0))
actual=s.getsockname()[0]
try:
 s.connect((TARGET,22)); reachable=True
except OSError:
 reachable=False
finally:
 s.close()
print(json.dumps(dict(reachable=reachable,actual_source=actual)))
'''.replace('SOURCE',repr(self.source)).replace('TARGET',repr(self.lab['victim']['ip']))
        return self.remote(self.role,['python3','-c',code])
