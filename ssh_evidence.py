"""Host-side, read-only SSH evidence collector; no model or response actions."""
import argparse
import base64
import json
from pathlib import Path
import shlex
import subprocess
from topology import load, ssh_target
from ssh_auth_reader import validate_request


def collect_auth(request):
    validate_request(request)
    topology = load()
    if request['target_ip'] != topology['victim']['ip']:
        raise ValueError('Only the configured Ubuntu lab victim is supported')
    payload = base64.b64encode(json.dumps(request).encode()).decode()
    command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
               '-o', 'StrictHostKeyChecking=yes', ssh_target(topology), 'python3 - ' + shlex.quote(payload)]
    script = Path(__file__).with_name('ssh_auth_reader.py').read_text()
    result = subprocess.run(command, input=script, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Read-only SSH journal collection failed: '+result.stderr[:500])
    if len(result.stdout.encode()) > 16000:
        raise ValueError('Oversized authentication summary')
    return json.loads(result.stdout)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--start', required=True)
    parser.add_argument('--end', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    summary = collect_auth({'source_ip':args.source, 'target_ip':load()['victim']['ip'],
                            'start':args.start, 'end':args.end})
    args.output.write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2))
