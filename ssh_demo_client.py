"""Six bounded lab SSH attempts. Run manually on Kali or Trust-Client."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from topology import load

def run(mode, preflight=False):
    topology = load()
    target = topology['victim']['ip']
    expected = topology['kali' if mode=='unapproved' else 'trusted']['ip']
    route=json.loads(subprocess.check_output(['ip','-j','route','get',target],text=True,timeout=5))[0]
    if route.get('prefsrc') != expected:
        raise ValueError(f'This mode requires source {expected}; route reports {route.get("prefsrc")}')
    if preflight:
        result={'source_ip':expected,'target_ip':target,'route':route,'attack_executed':False}
        Path('/tmp/soar-client-preflight.json').write_text(json.dumps(result))
        print(json.dumps(result));return
    accounts=['soc_test']*6 if mode=='approved' else ['soc_rehearsal_invalid']*6
    if mode=='scope-violation': accounts=['root']+['soc_test']*5
    results=[]
    with tempfile.TemporaryDirectory(prefix='soc-demo-') as directory:
        askpass=Path(directory)/'askpass'
        askpass.write_text('#!/bin/sh\nprintf "%s\\n" "SOC_Invalid_Demo_Only_2026"\n');askpass.chmod(0o700)
        env=dict(os.environ,SSH_ASKPASS=str(askpass),SSH_ASKPASS_REQUIRE='force',DISPLAY='soc-demo:0')
        for index,account in enumerate(accounts):
            if index==3:
                # Two bursts of three let OpenSSH's per-source failure penalty
                # decay without disabling it. This is pacing, not extra attempts.
                print('Pausing 12 seconds between the two three-attempt bursts.',flush=True)
                time.sleep(12)
            command=['ssh','-o','ConnectTimeout=3','-o','ConnectionAttempts=1',
                     '-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',
                     '-o','NumberOfPasswordPrompts=1','-o','StrictHostKeyChecking=yes',
                     '-o','ControlMaster=no','-o','ControlPath=none',account+'@'+target,'true']
            try:
                result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE,env=env,start_new_session=True,text=True,timeout=4)
                results.append({'account':account,'returncode':result.returncode,
                                'diagnostic':result.stderr[-300:]})
                if result.returncode==0: raise RuntimeError('Unexpected successful authentication; test stopped')
            except subprocess.TimeoutExpired:
                results.append({'account':account,'timeout':True})
            time.sleep(.2)
    print(json.dumps({'mode':mode,'source_ip':expected,'target_ip':target,'attempts':results,
                      'note':'Failed-password counts must be verified from victim logs; SSH protections may reject connections early.'},indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=['approved','unapproved','scope-violation'],required=True)
    parser.add_argument('--preflight',action='store_true')
    parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    if not args.execute and not args.preflight: parser.error('Explicit --execute required; approved mode also needs an active approved plan')
    run(args.mode,args.preflight)
