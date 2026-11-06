"""Read-only post-install verification. Never dispatches a block or edits a rule."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

from lab_config import load_profile
from ssh_transport import command
from windows_response import expected_receipt
from windows_response_helper import HELPER


def remote(lab,argv,request=None):
    result=subprocess.run(command(lab,'victim',shlex.join(argv)),input=json.dumps(request) if request is not None else None,
                          capture_output=True,text=True,timeout=65,check=True)
    if len(result.stdout)>65536:raise ValueError('Oversized verification response')
    return json.loads(result.stdout)


def verify(root,rule_editor=False):
    root=Path(root);lab=load_profile(root=root)
    if lab['platform']!='windows-hyperv':raise ValueError('Explicit Windows profile required')
    expected=expected_receipt(lab)
    receipt=remote(lab,['sudo','-n',HELPER,'inspect'])
    if any(receipt.get(k)!=v for k,v in expected.items()):raise ValueError('Installed helper/config identity mismatch')
    policy_path=root/'response.local.json';policy=json.loads(policy_path.read_text())
    if policy['mode']!='dry_run':raise ValueError('Post-install verification requires dry_run mode')
    if rule_editor:
        # Code identity and root ownership are independently checked over ordinary SSH.
        code="import hashlib,json,os,stat; p='/usr/local/libexec/soc-rule-editor.py'; s=os.lstat(p); print(json.dumps(dict(sha=hashlib.sha256(open(p,'rb').read()).hexdigest(),safe=stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022)))"
        identity=remote(lab,['python3','-I','-c',code])
        sha=hashlib.sha256(Path(__file__).with_name('soc_rule_helper.py').read_bytes()).hexdigest()
        if identity.get('safe') is not True or identity.get('sha')!=sha:raise ValueError('Rule helper identity/ownership mismatch')
        status=remote(lab,['sudo','-n','/usr/bin/python3','-I','/usr/local/libexec/soc-rule-editor.py'],{'action':'read'})
        if status.get('ok') is not True or status['result'].get('service_running') is not True:raise ValueError('Rule editor/service read not verified')
        (root/'rule-editor-enabled.json').write_text(json.dumps(dict(platform='windows-hyperv',victim_ip=lab['victim']['ip'],helper_sha256=sha,installed=True),indent=2)+'\n')
    policy['windows_response']=dict(expected,provisioned=True)
    # Does not set model readiness, live activation or live authorization.
    policy_path.write_text(json.dumps(policy,indent=2)+'\n')
    return dict(provisioned=True,mode=policy['mode'],rule_editor_verified=rule_editor,firewall_actions=0,**expected)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).parent)
    parser.add_argument('--rule-editor',action='store_true')
    args=parser.parse_args();print(json.dumps(verify(args.root,args.rule_editor),indent=2))
