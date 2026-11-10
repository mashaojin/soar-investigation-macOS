"""Copy and verify demo files in precreated guest folders without running them."""
from pathlib import Path
import hashlib
import json
import subprocess

from topology import FILENAME, ROOT, UTM, clients, load


def stage(root=ROOT):
    topology = load(root)
    files = {
        'ssh_demo_client.py': (root / 'ssh_demo_client.py').read_bytes(),
        'topology.py': (root / 'topology.py').read_bytes(),
        FILENAME: json.dumps(topology).encode(),
    }
    results = []
    for guest in clients(topology).values():
        machine = guest['name']
        for name, data in files.items():
            destination = f"/home/{guest['user']}/soc-demo/{name}"
            subprocess.run([UTM, 'file', 'push', machine, destination], input=data,
                           capture_output=True, timeout=20, check=True)
            pull = subprocess.run([UTM, 'file', 'pull', machine, destination],
                                  capture_output=True, timeout=20, check=True)
            if pull.stdout != data:
                raise RuntimeError('Copy verification failed for ' + machine + ': ' + name)
            results.append(dict(machine=machine, path=destination,
                                sha256=hashlib.sha256(data).hexdigest(), verified=True, executed=False))
    return results


if __name__ == '__main__':
    results = stage()
    receipt = json.dumps(results, indent=2) + '\n'
    (Path(__file__).with_name('verification-client-staging.json')).write_text(receipt)
    print(receipt, end='')
