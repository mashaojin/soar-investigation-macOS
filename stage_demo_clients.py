"""Copy demo client to precreated ~/soc-demo folders; never generates traffic."""
from pathlib import Path
import hashlib
import json
import subprocess
from lab_config import load_profile


def stage(lab=None):
    lab=lab or load_profile(root=Path(__file__).parent)
    if lab['platform']=='windows-hyperv':
        from stage_windows_clients import stage as windows_stage
        results=windows_stage(lab)
    else:
        script=Path(__file__).with_name('ssh_demo_client.py').read_bytes();results=[]
        for role in ('attacker','trust_client'):
            host=lab[role];destination=f"/home/{host['user']}/soc-demo/ssh_demo_client.py"
            push=subprocess.run([lab['utmctl'],'file','push',host['vm'],destination],input=script,capture_output=True,timeout=20)
            if push.returncode:raise RuntimeError('Push failed for '+host['vm'])
            pull=subprocess.run([lab['utmctl'],'file','pull',host['vm'],destination],capture_output=True,timeout=20)
            if pull.returncode or pull.stdout!=script:raise RuntimeError('Copy verification failed for '+host['vm'])
            results.append(dict(machine=host['vm'],path=destination,sha256=hashlib.sha256(script).hexdigest(),verified=True,executed=False))
    Path(__file__).with_name('verification-client-staging.json').write_text(json.dumps(results,indent=2)+'\n')
    return results


if __name__=='__main__':print(json.dumps(stage(),indent=2))
